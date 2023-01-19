use std::{error, fs};
use std::fs::File;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use users::{get_user_by_name};
use users::os::unix::UserExt;
// Makes available User.home_dir().
use log::{error, warn, info, debug, trace};
use crate::common::{AddressBT, Command, Event, Filter, Rule, UserToRun};
use crate::consts::{GLOBAL_BLUET_RULES_FILE_PATH, LOGIN_DEFS, RULES_FILENAME};
use crate::DEFAULT_GLOBAL_BLUET_FILE;

//region Errors
#[derive(Debug)]
pub struct InvalidFilter(pub String);

impl error::Error for InvalidFilter {}

impl Display for InvalidFilter {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Invalid devices FILTER specified: {}", &self.0)
    }
}

#[derive(Debug)]
pub struct InvalidEvent(pub String);

impl error::Error for InvalidEvent {}

impl Display for InvalidEvent {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Invalid trigger EVENT specified: {}", &self.0)
    }
}

#[derive(Debug)]
pub struct RuleTooShort(pub String);

impl error::Error for RuleTooShort {}

impl Display for RuleTooShort {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Rule line is too short after split by spaces: {}", &self.0)
    }
}
//endregion

//region Address matchers
pub trait AddressMatcher: Debug {
    fn is_match(&self, address: &AddressBT) -> bool;
}

/// Matches single address defined in address_to_match attribute
#[derive(Debug)]
pub struct SingleAddressMatcher {
    pub(crate) address_to_match: AddressBT,
}

impl AddressMatcher for SingleAddressMatcher {
    fn is_match(&self, address: &AddressBT) -> bool {
        &self.address_to_match == address
    }
}

/// Matches all addresses
#[derive(Debug)]
pub struct AllAddressMatcher {}

impl AddressMatcher for AllAddressMatcher {
    fn is_match(&self, _address: &AddressBT) -> bool {
        true
    }
}
//endregion

//region Rule parsing
/// Parse line that's in format:
/// `<filter> <address> <event> <OPTIONAL if usernames_included: username> <command>`
/// Warning! Be aware of MULTIPLE SPACES in the Rule declaration!
/// Filters: "ANY", "PAIRED", "NOT_PAIRED"
/// Address: "*" for any, "xx:xx:xx:xx:xx:xx" for single address match
/// Event: "CONNECT", "DISCONNECT", "FOUND, "LOST"
/// OPTIONAL: User: <username> of the user to run the command as. (Only if is_root = true)
/// Command: Any string to be run in console
pub fn parse_rule_line(line: &str, usernames_included: bool, username_to_run: &OsStr) -> Result<Option<Rule>, Box<dyn error::Error>> {
    let line = line.trim();

    // This line is empty or a comment line
    if line.len() == 0 || line.starts_with("#") {
        return Ok(None);
    }

    let expected_len = if usernames_included { 5 } else { 4 };
    let parts: Vec<&str> = line.splitn(expected_len, " ").collect();  // Split to 4 parts by space.

    if parts.len() < expected_len {
        return Err(Box::new(RuleTooShort(String::from(
            format!("length is {}, but should be {}. Line: '{}'", parts.len(), expected_len, line)
        ))));
    }

    // Parse Filter
    let filter: Filter = match parts[0].to_uppercase().as_str() {
        "ANY" => Filter::Any,
        "PAIRED" => Filter::Paired,
        "NOT_PAIRED" => Filter::NotPaired,
        other => return Err(Box::new(InvalidFilter(other.to_string()))),
    };

    // Parse Address
    // Only "*" and full address or all supported
    let address_matcher: Box<dyn AddressMatcher>;
    if parts[1] == "*" {
        // Matches anything
        address_matcher = Box::new(AllAddressMatcher {});
    } else {
        // Matches single address
        let address = AddressBT::from_str(parts[1])?;  // May return parsing error.
        address_matcher = Box::new(SingleAddressMatcher { address_to_match: address })
    }


    // Parse Event
    let event: Event = match parts[2].to_uppercase().as_str() {
        "CONNECT" => Event::Connect,
        "DISCONNECT" => Event::Disconnect,
        "FOUND" => Event::Found,
        "LOST" => Event::Lost,
        other => return Err(Box::new(InvalidEvent(other.to_string()))),
    };

    let username_to_run = if usernames_included {
        OsStr::new(&parts[3])
    } else {
        username_to_run
    };
    let user_to_run = get_user_by_name(username_to_run);
    if user_to_run.is_none() {
        return Err(Box::try_from(format!("User {username_to_run:?} not found!")).unwrap());
    }
    let user_to_run = user_to_run.unwrap();

    // Parse Command
    let mut command_index = 3;
    if usernames_included { command_index += 1; }
    let command = Command::System(parts[command_index].to_string());

    Ok(Some(
        Rule {
            filter,
            address_matcher,
            event,
            user_to_run: UserToRun {
                username: Box::from(user_to_run.name()),
                uid: user_to_run.uid(),
                gid: user_to_run.primary_group_id(),
                shell_path: user_to_run.shell().to_path_buf(),
                home_dir: user_to_run.home_dir().to_path_buf(),
            },
            source_file: None,
            command,
        }
    ))
}

/// Parse BlueT rules string to Vec of Rule objects.
/// Returns Vec of Rule objects and Vector of Errors including error line numbers.
pub fn parse_rules(rules_text: &String, usernames_included: bool, user_to_run: &OsStr) -> (Vec<Rule>, Vec<(u32, Box<dyn error::Error>)>) {
    let mut rules: Vec<Rule> = Vec::new();
    let mut errors: Vec<(u32, Box<dyn error::Error>)> = Vec::new();

    for (i, line) in rules_text.lines().into_iter().enumerate() {
        match parse_rule_line(line, usernames_included, user_to_run) {
            Ok(result) => match result {
                None => {}
                Some(rule) => rules.push(rule),
            }
            Err(err) => errors.push((i as u32, err)),
        }
    }

    return (rules, errors);
}
//endregion

//region Load rules functions
/// Load minimum normal user id (UID_MIN) from `/etc/login.defs`.
/// If UID_MIN not set in the file, return default linux value, which is 1000.
fn get_min_uid_for_normal_users() -> Result<u32, Box<dyn Error>> {
    let data = fs::read_to_string(LOGIN_DEFS)?;
    for line in data.lines() {
        if line.starts_with("UID_MIN") {
            return Ok(line.split_whitespace().rev().next().unwrap().parse()?);
        }
    }

    warn!("No UID_MIN found in {LOGIN_DEFS}! Using default value of 1000.");
    return Ok(1000);  // If nothing found, return default UID_MIN in linux, which is 1000
}

/// Parse rules from <filepath> file and set their 'user_to_run' attribude to <username> user.
/// If <is_root> is true, load 'username' from config file.
/// Prints all errors to log, does not propagate them.
pub fn load_rules_file(filepath: &Path, is_root: bool, username: &OsStr) -> Vec<Rule> {
    match fs::read_to_string(filepath) {
        Ok(data) => {
            let (mut rules, errors) = parse_rules(&data, is_root, username);
            for error in errors {
                warn!("Error loading rule from line no {} in file {:?}, error: {}", error.0, filepath, error.1);
            };
            for mut rule in &mut rules {
                rule.source_file = Some(filepath.to_path_buf());
            }
            return rules;
        }
        Err(err) => error!("Error loading global {GLOBAL_BLUET_RULES_FILE_PATH} rules file! Error: {err}"),
    }

    return Vec::new();
}

/// Parse all rules from Global rules file (`/etc/bluet/.bluet`)
///  and from all `.bluet` rule files in normal users home directories.
pub fn load_all_rules() -> Result<Vec<Rule>, Box<dyn Error>> {
    let mut all_rules = Vec::new();

    // Load global `/etc/bluet/.bluet` rules.
    debug!("Loading global '{GLOBAL_BLUET_RULES_FILE_PATH}' rules file...");
    if Path::new(GLOBAL_BLUET_RULES_FILE_PATH).exists() {
        // Load existing file
        let mut rules = load_rules_file(GLOBAL_BLUET_RULES_FILE_PATH.as_ref(), true, &OsStr::new("root"));
        info!("Loaded {} global rules", rules.len());
        all_rules.append(&mut rules);
    } else {
        info!("Global {GLOBAL_BLUET_RULES_FILE_PATH} rules file not found, creating new...");
        // Create new Global rules file as it doesn't exist
        match File::create(GLOBAL_BLUET_RULES_FILE_PATH) {
            Ok(mut file) => match file.write_all(DEFAULT_GLOBAL_BLUET_FILE.as_ref()) {
                Ok(_) => info!("New {GLOBAL_BLUET_RULES_FILE_PATH} created successfully"),
                Err(_) => error!("Error writing global {GLOBAL_BLUET_RULES_FILE_PATH} rules file!"),
            }
            Err(_) => error!("Error creating global {GLOBAL_BLUET_RULES_FILE_PATH} rules file!"),
        }
    }

    // Load rules for each user:
    debug!("Loading local '~/.bluet` files for each user...");
    let min_uid = get_min_uid_for_normal_users()?;
    let iter = unsafe { users::all_users() };
    for user in iter {
        let uid = user.uid();
        // If normal user
        if uid >= min_uid {
            let username_str = user.name();
            let home_dir: &Path = user.home_dir();
            let filepath = home_dir.join(RULES_FILENAME);
            if filepath.exists() {
                trace!("Loading '{:?}' for user with uid {}", &filepath, uid);
                info!("Loading rules file '{:?}' for user {:?}", filepath, username_str);
                let mut rules = load_rules_file(filepath.as_path(), false, user.name());
                info!("Loaded {} rules for user {:?}", rules.len(), username_str);
                all_rules.append(&mut rules);
            } else {
                trace!("'{:?}' does not exist for user with uid {}", &filepath, uid);
            }
        } else {
            trace!("Not loading user with uid {}, not a normal user.", uid);
        }
    }

    return Ok(all_rules);
}
//endregion

#[cfg(test)]
mod parser_tests {
    use crate::parser::get_min_uid_for_normal_users;

    #[test]
    fn test_get_min_uid_for_normal_users() {
        assert!(get_min_uid_for_normal_users().is_ok())
    }
}
