use std::ffi::{CString, OsStr};
use std::fmt::{Debug, Display, Formatter};
use std::path::{PathBuf};
use std::rc::Rc;
use std::str::FromStr;
use std::time::Instant;
use crate::parser::{AddressMatcher};
use libc;
use libc::{uid_t, gid_t, pid_t, _exit};
use std::process;
use log::{debug, error, info};
use crate::global_config::CONFIG;

/// Bluetooth address
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AddressBT(pub [u8; 6]);

impl AddressBT {
    pub const fn new(addr: [u8; 6]) -> Self {
        Self(addr)
    }
}

impl Display for AddressBT {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Debug for AddressBT {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_string().as_str())
    }
}

#[derive(Debug)]
pub struct InvalidAddress(pub String);

impl std::error::Error for InvalidAddress {}

impl Display for InvalidAddress {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Invalid Bluetooth ADDRESS: {}", &self.0)
    }
}

impl FromStr for AddressBT {
    type Err = InvalidAddress;
    fn from_str(s: &str) -> Result<Self, InvalidAddress> {
        let mut addr: [u8; 6] = [0; 6];

        let splt: Vec<&str> = s.split(":").collect();
        if splt.len() != 6 {
            return Err(InvalidAddress(s.to_string()));
        }
        for i in 0..6 {
            let byte = match u8::from_str_radix(splt[i], 16) {
                Ok(number) => number,
                Err(_) => return Err(InvalidAddress(s.to_string())),
            };
            addr[i] = byte;
        }

        Ok(Self::new(addr))
    }
}


#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DeviceProps {
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub paired: bool,
    pub connected: bool,
}

impl DeviceProps {
    pub fn default() -> Self {
        Self {
            name: None,
            rssi: None,
            paired: false,
            connected: false,
        }
    }
}

#[derive(Debug)]
pub struct DeviceBT {
    pub address: AddressBT,
    pub properties: DeviceProps,
    pub last_seen: Instant,
    pub matched_rules: Vec<Rc<Rule>>,
    pub is_found: bool,  // Were the FOUND rules triggered
    pub is_connected: bool,  // Were the CONNECT rules triggered
    pub last_connect: Option<Instant>,
}


#[derive(Debug, Hash, Eq, PartialEq)]
pub enum Filter { Any, Paired, NotPaired }

// ,Connected
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum Event { Connect, Disconnect, Found, Lost }

// , Paired, Forget
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum Command { System(String) }

impl Command {
    fn run(&self, rule: &Rule) {
        match self {
            Command::System(command) => {
                process::Command::new(rule.user_to_run.shell_path.as_os_str())
                    .current_dir(&rule.user_to_run.home_dir)
                    .arg("-c")
                    .arg(command)
                    .status()
                    .expect("Failed to execute process");
                debug!("Command {:?} execution finished", command);
            }
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct UserToRun {
    pub username: Box<OsStr>,
    pub uid: uid_t,
    pub gid: gid_t,
    pub home_dir: PathBuf,
    pub shell_path: PathBuf,
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Rule {
    pub filter: Filter,
    pub address_matcher: Box<AddressMatcher>,
    pub event: Event,
    pub user_to_run: UserToRun,
    pub source_file: Option<PathBuf>,
    pub command: Command,
}

impl Rule {
    /// Check if rule is matched and run if yes. Returns true if run, otherwise false.
    pub fn check_and_run(&self, device: &DeviceBT, _old_props: &DeviceProps, new_props: &DeviceProps) -> bool {
        // Check BT Address: Just in case, but it is checked elsewhere.
        if !self.address_matcher.is_match(&device.address) { return false; }

        // Check Filter
        if !match self.filter {
            Filter::Any => true,
            Filter::Paired => device.properties.paired,
            Filter::NotPaired => !device.properties.paired,
        } { return false; }

        // Check Event type:
        if !match self.event {
            Event::Connect => !device.is_connected && new_props.connected,
            Event::Disconnect => device.is_connected && !new_props.connected,
            Event::Found => !device.is_found
                && new_props.rssi.is_some()
                && new_props.rssi.unwrap() > CONFIG.rssi_threshold,
            Event::Lost => device.is_found && new_props.rssi.is_none(),
        } { return true; }

        info!("Triggered rule '{:?}' by device '{:?}', new_props: '{:?}'.", self, device, new_props);
        unsafe { self.run_command_as_user_in_new_process(); }
        return true;
    }

    pub unsafe fn run_command_as_user_in_new_process(&self) -> pid_t {
        match { libc::fork() } {
            -1 => {
                error!("Failed to fork the process to execute command!");
                return -1;
            }
            0 => {
                // Child code
                // Prepare running environment
                libc::setsid();  // For to its own process group.

                libc::setgid(self.user_to_run.gid);
                let username_cstr = CString::new(self.user_to_run.username.to_str().unwrap()).unwrap();
                libc::initgroups(username_cstr.as_ptr(), self.user_to_run.gid);
                // libc::setlogin(&self.user_to_run.username);  // setlogin not in rust libc

                if libc::setuid(self.user_to_run.uid) != 0 {
                    // Failed to set uid -> EXIT, so we dont run the command as ROOT unintentionally
                    _exit(1);
                }

                // From now on, we are not ROOT, but the user defined in Rule.user_to_run //

                // Run the command
                self.command.run(self);

                // Exit
                _exit(0);
            }
            pid => {
                // Parent
                debug!("Process forked with id: {}", pid);
                return pid;
            }
        }
    }
}


#[cfg(test)]
mod common_tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use users::os::unix::UserExt;
    // Makes available User.home_dir().
    use libc::c_int;
    use crate::parser::MatchingType;

    fn get_default_testing_user_rule() -> Rule {
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
            command: Command::System(String::from("")),
        };

        return rule;
    }

    // Makes available User.home_dir().
    #[test]
    fn test_command_run() {
        // Prepare
        let mut rule = get_default_testing_user_rule();
        let filename = ".temp_rust_test_command_run";
        rule.command = Command::System(String::from(format!("echo abc > {filename}")));
        println!("Testing rule: {:?}", rule);

        // Run
        rule.command.run(&rule);

        let filepath = rule.user_to_run.home_dir.join(&filename);
        println!("Filepath: {:?}", &filepath.as_os_str());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), "abc\n");

        // Clean up
        fs::remove_file(&filepath).unwrap();
        assert!(!filepath.try_exists().unwrap(), "File cleanup failed!");
    }

    #[test]
    fn test_rule_process_form_run() {
        // Prepare
        let mut rule = get_default_testing_user_rule();
        let filename = ".temp_rust_test_rule_run_process";
        rule.command = Command::System(String::from(format!("echo abcd_kocka_prede > {filename}")));
        println!("Testing rule: {:?}", rule);

        // Run
        let pid = unsafe { rule.run_command_as_user_in_new_process() };

        // Wait for command to finish running
        let mut status: i32 = 0;
        let ret = unsafe {
            libc::waitpid(
                pid,
                &mut status as *mut c_int,
                0 as c_int,
            )
        };
        // Wait successful if ret == pid (should be always true, or process exited before wait.)
        println!("waitpid for {:?}, ret: {:?}, status: {:?}", pid, ret, status);


        let filepath = rule.user_to_run.home_dir.join(&filename);
        let filepath = filepath.as_path();
        println!("Filepath: {:?}", &filepath.as_os_str());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), "abcd_kocka_prede\n");

        // Clean up
        println!("before: {}", filepath.try_exists().unwrap());
        fs::remove_file(&filepath).unwrap();
        println!("after: {}", filepath.try_exists().unwrap());
        assert!(!filepath.try_exists().unwrap(), "File cleanup failed!");
    }

    #[test]
    fn ztemp() {
        let out = process::Command::new("/bin/bash")
            .current_dir(Path::new("/home/patrik"))
            .arg("-c")
            .arg("./save_device.sh")
            // .arg("pwd")
            .output()
            .expect("Failed to execute process");

        println!("{:?}", out);

        assert!(false);
    }
}
