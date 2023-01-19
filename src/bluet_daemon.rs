use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::time::Instant;
use futures::pin_mut;
use futures::StreamExt;  // Enable use of .next() on streams
use log::{debug, error, info, LevelFilter, trace};
use tokio::sync::{mpsc};
use tokio::{task, time};
use tokio::time::{Duration};
use tokio_stream::wrappers::ReceiverStream;
use crate::parser::load_all_rules;
use crate::common::{AddressBT, DeviceBT, DeviceProps, Filter, Rule};
use crate::bt_triggerer::{ScanDeviceEvent, scanning_loop};
use crate::consts::{BLUET_CONFIG_DIR};
use crate::global_config::CONFIG;

#[macro_use]
extern crate lazy_static;

mod common;
mod parser;
mod consts;
mod bt_triggerer;
mod global_config;


const DEFAULT_GLOBAL_BLUET_FILE: &str = "\
# /etc/bluet/.bluet: system-wide bluet rules file.
# Unlike other .bluet files, this one has a username field,
# so dont forget to include the username as which to run the command.

# Example of rules definition:
# .----------------------- rule (ANY; PAIRED; NOT_PAIRED)
# |   .------------------- address (*; aa:bb:cc:dd:ee:ff)
# |   | .----------------- event (CONNECT; DISCONNECT; FOUND; LOST)
# |   | |     .----------- username to run the command as
# |   | |     |        .-- command to be executed
# |   | |     |        |
# ANY * FOUND username ./command.sh

";


pub struct EventMatcher {
    rules: Vec<Rc<Rule>>,
    devices: HashMap<AddressBT, DeviceBT>,
}

impl EventMatcher {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules: rules.into_iter().map(Rc::new).collect(),
            devices: HashMap::new(),
        }
    }

    //region Externally callable functions
    pub fn on_device_add_or_change(&mut self, address: AddressBT, new_props: DeviceProps) {
        trace!("EventMatcher :: Device added/changed event: {}, new props: {:?}", address, new_props);

        if self.devices.contains_key(&address) {
            // Properties changes
            match self.devices.get_mut(&address) {
                None => {}
                Some(mut device) => {
                    for rule in &device.matched_rules {
                        rule.check_and_run(&device, &device.properties, &new_props);
                    }
                    if new_props.rssi.is_some() {
                        device.last_seen = Instant::now();
                        device.properties = new_props;
                    } else {
                        self.devices.remove(&address);
                        // Remove the device when it goes out.
                        debug!("EventMatcher :: Device {} removed by change event.", address);
                    }
                }
            }
        } else {
            if new_props.rssi.is_none() { return; }

            // New device
            let matching_rules = self.get_matching_rules(&address, &new_props);

            if matching_rules.len() > 0 {
                debug!("EventMatcher :: New device {} matched for {} rules. Its props: {:?}", address, matching_rules.len(), new_props);

                let device = DeviceBT {
                    address,
                    properties: new_props,
                    last_seen: Instant::now(),
                    matched_rules: matching_rules,
                };

                for rule in &device.matched_rules {
                    rule.check_and_run(&device, &DeviceProps::default(), &device.properties);
                }

                self.devices.insert(address, device);
            }
        }
    }

    pub fn on_device_remove(&mut self, address: AddressBT) {
        trace!("EventMatcher :: Device removed event: {}", address);

        if self.devices.contains_key(&address) {
            // Properties changes
            match self.devices.get_mut(&address) {
                None => {}
                Some(device) => {
                    for rule in &device.matched_rules {
                        rule.check_and_run(&device, &device.properties, &DeviceProps::default());
                    }
                    debug!("EventMatcher :: Device {} removed by remove event.", address);
                    self.devices.remove(&address);
                }
            }
        }
    }

    pub fn check_expired_devices(&mut self) {
        trace!("EventMatcher :: Checking expired devices");

        let mut to_remove = Vec::new();

        for (address, device) in &self.devices {
            if device.last_seen.elapsed().as_secs() > CONFIG.timeout_for_disconnect {
                to_remove.push(address.clone());
                for rule in &device.matched_rules {
                    rule.check_and_run(&device, &device.properties, &DeviceProps::default());
                }
            }
        }

        for address in to_remove {
            self.devices.remove(&address);
            debug!("EventMatcher :: Device {} removed in expiry check.", address);
        }
    }
    //endregion

    fn get_matching_rules(&self, address: &AddressBT, props: &DeviceProps) -> Vec<Rc<Rule>> {
        let mut matched_rules = Vec::new();
        for rule in &self.rules {
            if rule.address_matcher.is_match(address) {
                if match rule.filter {
                    Filter::Any => true,
                    Filter::Paired => props.paired,
                    Filter::NotPaired => !props.paired,
                } {
                    matched_rules.push(Rc::clone(rule));
                }
            }
        }
        return matched_rules;
    }
}


// Check for expired devices every X seconds
// main() returns Result, so we can use await? without expect().
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    // Setup Logging
    if cfg!(debug_assertions) {
        println!("Running debug build of BlueT!");
        ::std::env::set_var("RUST_LOG", "debug");
        env_logger::init();
        log::warn!("Running debug build of BlueT!");
    } else {
        systemd_journal_logger::init().unwrap();
        log::set_max_level(LevelFilter::Info);
    }

    info!("Starting BlueT daemon...");

    // Check if root
    if !cfg!(debug_assertions) {
        let uid = users::get_current_uid();
        if uid != 0 {
            error!("BlueT must be run under ROOT user, but is run under user with id: {}", uid);
            panic!("BlueT must be run under ROOT user, but is run under user with id: {}", uid);
        }
    }

    // Check lazily loaded CONFIG
    debug!("Loaded config: {:?}", *CONFIG);

    // Make sure `/etc/bluet` folder exists
    if !Path::new(BLUET_CONFIG_DIR).exists() {
        // No Config folder found -> create it:
        // .expect(&format!("Can't create config directory '{BLUET_CONFIG_DIR}'!").as_str());
        match fs::create_dir_all(BLUET_CONFIG_DIR) {
            Ok(_) => info!("Created new configuration directory for BlueT ('{BLUET_CONFIG_DIR}')."),
            Err(err) => panic!("Can't create config directory '{BLUET_CONFIG_DIR}'! Error: {err:?}"),
        }
    }

    // Load rules from files
    info!("Loading .bluet rules files...");
    let rules = load_all_rules().expect("Failed loading rules!");
    info!("Loaded total of {} rules.", rules.len());

    // Start the daemon
    info!("Setting up event matcher...");
    let mut event_matcher = EventMatcher::new(rules);
    let scan_events = scanning_loop().await?;
    pin_mut!(scan_events);

    // Start Expired devices checking
    let (tx_check_expired, rx_check_expired) = mpsc::channel(1);

    task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(CONFIG.expired_check));

        loop {
            interval.tick().await;
            if tx_check_expired.send(()).await.is_err() {
                break;
            };
        }
    });

    // Loop forever
    let mut rx_check_expired_stream = ReceiverStream::new(rx_check_expired);
    info!("BlueT daemon running.");
    loop {
        tokio::select! {
            Some(scan_event) = scan_events.next() => {
                match scan_event {
                    ScanDeviceEvent::AddOrChangeDevice(address, props) => {
                        event_matcher.on_device_add_or_change(address, props);
                    },
                    ScanDeviceEvent::RemoveDevice(address) => {
                        event_matcher.on_device_remove(address)
                    },
                }
            },
            _ = rx_check_expired_stream.next() => {
                event_matcher.check_expired_devices();
            },
            else => break,
        }
    }


    info!("BlueT daemon stopped.");
    Ok(())
}
