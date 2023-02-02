//! Module for loading and parsing BlueT rules files.

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
use log::{error, warn, info, debug};
use crate::common::{AddressBT, Command, Event, Filter, Rule, UserToRun};
use crate::consts::{RULES_FILE_TEMPLATE, RULES_FILEPATH};

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
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub enum MatchingType {
    All,
    Single(AddressBT),
    // ByteRange(AddressBT, AddressBT),    // Start and End addresses, range checked on each byte separately
    // AddressRange(AddressBT, AddressBT), // Start and End addresses, range checked on full address
}

#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct AddressMatcher {
    matching_type: MatchingType
}
impl AddressMatcher {
    pub fn new(matching_type: MatchingType) -> Self {
        return Self { matching_type };
    }
    pub fn is_match(&self, address: &AddressBT) -> bool {
        match self.matching_type {
            MatchingType::All => true,
            MatchingType::Single(addr) => &addr == address,
            // MatchingType::ByteRange(start, end) => {
            //     for i in 0..6 {
            //         if (start[i] <= address[i]) && (address[i] <= end[i]) {
            //             return false;
            //         }
            //     }
            //     return true;
            // }
            // MatchingType::AddressRange(start, end) => {
            //     for i in 0..6 {
            //         if (start[i] < address[i]) && (address[i] > end[i]) { return true; }
            //         if (start[i] == address[i]) || (start[i] == address[i]) { continue; }
            //         return false;
            //     }
            //     return true;
            // }
        }
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
/// OPTIONAL: User: \<username\> of the user to run the command as. (Only if is_root = true)
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
    let address_matcher: Box<AddressMatcher>;
    if parts[1] == "*" {
        // Matches anything
        address_matcher = Box::new(AddressMatcher::new(MatchingType::All));
    } else {
        // Matches single address
        let address = AddressBT::from_str(parts[1])?;  // May return parsing error.
        address_matcher = Box::new(AddressMatcher::new(MatchingType::Single(address)));
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

/// Parse rules from \<filepath\> file and set their 'user_to_run' attribute to \<username\> user.
/// If \<is_root\> is true, load 'username' from config file.
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
        Err(err) => error!("Error loading {filepath:?} rules file! Error: {err}"),
    }

    return Vec::new();
}

/// Parse all rules from RULES_FILEPATH. If the rules file does not exist, create ir.
pub fn load_all_rules() -> Result<Vec<Rule>, Box<dyn Error>> {
    debug!("Loading '{}' rules file...", *RULES_FILEPATH);
    if Path::new(&*RULES_FILEPATH).exists() {
        // Load existing rules file
        let rules = load_rules_file(RULES_FILEPATH.as_ref(), true, &OsStr::new("root"));
        info!("Loaded {} rules", rules.len());
        return Ok(rules);
    } else {
        info!("'{}' rules file not found, creating new.", *RULES_FILEPATH);
        // Create new rules file as it doesn't exist
        match File::create(&*RULES_FILEPATH) {
            Ok(mut file) => match file.write_all(RULES_FILE_TEMPLATE.as_ref()) {
                Ok(_) => debug!("New {} created successfully", *RULES_FILEPATH),
                Err(_) => error!("Error writing {} rules file!", *RULES_FILEPATH),
            }
            Err(_) => error!("Error creating {} rules file!", *RULES_FILEPATH),
        }
        return Ok(Vec::new());
    }
}
//endregion
