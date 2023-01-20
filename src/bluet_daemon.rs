use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::time::Instant;
use futures::pin_mut;
// futures:StreamExt -> Enable use of .next() on streams
use futures::StreamExt;
use log::{debug, error, info, trace};
use tokio::sync::{mpsc};
use tokio::{task, time};
use tokio::time::{Duration};
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::ReceiverStream;
use crate::parser::load_all_rules;
use crate::common::{AddressBT, DeviceBT, DeviceProps, Filter, Rule};
use crate::bt_triggerer::{ScanDeviceEvent, scanning_loop};
use crate::consts::{BLUET_CONFIG_DIR};
use crate::global_config::CONFIG;

#[cfg(not(all(feature = "debug", debug_assertions)))]
use log::LevelFilter;

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
                    for rule in device.matched_rules.iter().collect::<Vec<&Rc<Rule>>>() {
                        rule.check_and_run(device, &device.properties, &new_props);
                    }
                    if new_props.rssi.is_some() {
                        if new_props.rssi.unwrap() > CONFIG.rssi_threshold { device.is_found = true; }
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
                    is_found: false,
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

        for (address, mut device) in &self.devices {
            if device.last_seen.elapsed().as_secs() > CONFIG.timeout_for_disconnect {
                to_remove.push(address.clone());
                for rule in &device.matched_rules {
                    rule.check_and_run(&mut device, &device.properties, &DeviceProps::default());
                }
            }
        }

        for address in to_remove {
            self.devices.remove(&address);
            debug!("EventMatcher :: Device {} removed in expiry check.", address);
        }
    }

    /// Reload Event matcher with new rules.
    /// Does matching and for newly added / changed rules it triggers command immediately.
    /// Returns count of rules (not_changed, deleted, added)
    pub fn reload_rules(&mut self, new_rules: Vec<Rule>) -> (usize, usize, usize) {
        let mut new_rules_vec: Vec<Rc<Rule>> = Vec::new();

        // Delete matched rules from devices
        let old_rules_count = self.rules.len();
        for device in self.devices.values_mut() {
            device.matched_rules.clear();
        }

        // Create checker structure for rule existence
        let mut rules_counts: HashMap<&Rule, u32> = HashMap::new();
        for rule in &self.rules {
            rules_counts.entry(&*rule).and_modify(|counter| *counter += 1).or_insert(1);
        }

        // Iterate rules for changes
        let mut added_rules_count: usize = 0;
        for rule in &new_rules.into_iter().map(Rc::new).collect::<Vec<Rc<Rule>>>() {
            new_rules_vec.push(Rc::clone(rule));

            // Check if this rule already existed
            if rules_counts.get(&**rule).unwrap_or(&0) > &0 {
                // Rule existed
                rules_counts.entry(&**rule).and_modify(|counter| *counter -= 1);
                for (addr, device) in &mut self.devices {
                    if rule.address_matcher.is_match(addr) {
                        device.matched_rules.push(Rc::clone(rule));
                    }
                }

            } else {
                // New rule
                debug!("New rule found: {:?}", rule);
                added_rules_count += 1;
                for (addr, device) in &mut self.devices {
                    if rule.address_matcher.is_match(addr) {
                        device.matched_rules.push(Rc::clone(rule));
                        rule.check_and_run(&device, &DeviceProps::default(), &device.properties);
                    }
                }
            }
        }

        self.rules = new_rules_vec;

        let rules_not_changed = self.rules.len() - added_rules_count;
        let rules_deleted = old_rules_count - rules_not_changed;
        let rules_added = added_rules_count;
        info!("Reloaded rules. {} rules unchanged, {} rules deleted, {} rules added.",
            rules_not_changed, rules_deleted, rules_added
        );
        return (rules_not_changed, rules_deleted, rules_added);
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
    #[cfg(all(feature = "debug", debug_assertions))]
    {
        println!("Running debug build of BlueT!");
        ::std::env::set_var("RUST_LOG", "debug");
        env_logger::init();
        log::warn!("Running debug build of BlueT!");
    }
    #[cfg(not(all(feature = "debug", debug_assertions)))]
    {
        systemd_journal_logger::init().unwrap();
        log::set_max_level(LevelFilter::Info);
    }

    info!("Starting BlueT daemon...");

    // Check if root if not debug build
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

    // Listen for reload (SIGHUP signal)
    let mut sighup_signal = signal(SignalKind::hangup())?;
    info!("Attached SIGHUP signal listener for rules 'reload'.");

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
            _ = sighup_signal.recv() => {
                info!("SIGHUP received, reloading all .bluet rule files");
                let new_rules = load_all_rules().expect("Failed reloading rules!");
                event_matcher.reload_rules(new_rules);
            }
            else => break,
        }
    }


    info!("BlueT daemon stopped.");
    Ok(())
}



#[cfg(test)]
mod bluet_daemon_tests {
    use super::*;
    // Makes available User.home_dir():
    use users::os::unix::UserExt;
    use crate::common::{Command, Event, UserToRun};
    use crate::parser::{AddressMatcher, MatchingType};

    fn get_testing_rule(command: &str) -> Rule {
        let user = users::get_user_by_uid(users::get_current_uid()).unwrap();

        let rule = Rule {
            filter: Filter::Any,
            address_matcher: Box::new(AddressMatcher::new(MatchingType::All)),
            event: Event::Connect,
            user_to_run: UserToRun {
                username: Box::from(user.name()),
                uid: user.uid(),
                gid: user.primary_group_id(),
                home_dir: user.home_dir().to_path_buf(),
                shell_path: user.shell().to_path_buf(),
            },
            source_file: None,
            command: Command::System(command.to_string()),
        };

        return rule;
    }

    #[test]
    fn test_reload_rules_counts() {
        let rules = vec![
            get_testing_rule("1"),
            get_testing_rule("2"),
            get_testing_rule("3"),
        ];
        let new_rules = vec![
            // get_testing_rule("1"), // delete
            // get_testing_rule("2"), // delete
            get_testing_rule("3"),  // no change
            get_testing_rule("4"),  // add
            get_testing_rule("5"),  // add
            get_testing_rule("6"),  // add
        ];

        let mut event_matcher = EventMatcher::new(rules);

        let (not_changed, deleted, added) = event_matcher.reload_rules(new_rules);

        assert_eq!((not_changed, deleted, added), (1, 2, 3))
    }
}
