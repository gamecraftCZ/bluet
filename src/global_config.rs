//! Module to load CONFIG from file and make it globally available.
use std::fmt::{Debug};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;  // Enable use of writeln!() to file.
use std::path::Path;
use log::{error, info};
use serde::{Deserialize, Serialize};
use crate::consts::{CONFIG_FILEPATH};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    // Minimal rssi value to consider the device to be in proximity
    pub rssi_threshold: i16,

    // No pings from device for X seconds -> probably is not in proximity anymore -> trigger LOST event
    pub timeout_for_disconnect: u64,

    // Check if some device didn't ping existence each X seconds
    pub expired_check: u64,

    // BT device to use for scanning; None means default BT device
    pub bluetooth_device: Option<String>,
}

impl Config {
    pub const fn default() -> Self {
        Self {
            rssi_threshold: -70,
            timeout_for_disconnect: 30,
            expired_check: 5,
            bluetooth_device: None,
        }
    }
}

fn config_from_file() -> Result<Config, Box<dyn Error>> {
    if Path::new(&*CONFIG_FILEPATH).exists() {
        // Load config
        let config_str = fs::read_to_string(&*CONFIG_FILEPATH)?;
        return Ok(toml::from_str(config_str.as_str())?);
    } else {
        // Create new config file
        let cfg = Config::default();
        let config_str = toml::to_string(&cfg)?;
        match File::create(&*CONFIG_FILEPATH) {
            Ok(mut file) => {
                write!(&mut file, "{}", config_str)?;
                if cfg.bluetooth_device.is_none() {
                    #[warn(unused_must_use)]
                    write!(&mut file, "# bluetooth_device = \"bt_device_to_use\"")?;
                }
                info!("Created new configuration directory for BlueT ('{}').", *CONFIG_FILEPATH);
            }
            Err(err) => {
                error!("Can't create config file '{}'! Error: {err:?}", *CONFIG_FILEPATH);
                panic!("Can't create config file '{}'! Error: {err:?}", *CONFIG_FILEPATH);
            },
        }
        return Ok(cfg);
    }
}

lazy_static!{
    pub static ref CONFIG: Config = config_from_file().unwrap();
}
