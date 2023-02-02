//! Loading runtime constants and making them globally available.
use users::{get_user_by_uid, get_current_uid};
use users::os::unix::UserExt;


const RULES_FILENAME: &str = "rules";
const CONFIG_FILENAME: &str = "conf.toml";
const GLOBAL_CONFIG_DIR: &str = "/etc/bluet";
const LOCAL_CONFIG_PATH: &str = ".config/bluet";

lazy_static! {
    pub static ref BLUET_DIR: String = {
        let user = get_user_by_uid(get_current_uid()).unwrap();
        if user.uid() == 0 {
            // If root user, global folder is used
            GLOBAL_CONFIG_DIR.to_string()
        } else {
            // For other users, use folder in their home dir
            format!("{}/{}", user.home_dir().to_str().unwrap(), LOCAL_CONFIG_PATH)
        }
    };
    pub static ref CONFIG_FILEPATH: String = {
        format!("{}/{}", *BLUET_DIR, CONFIG_FILENAME)
    };
    pub static ref RULES_FILEPATH: String = {
        format!("{}/{}", *BLUET_DIR, RULES_FILENAME)
    };

    pub static ref RULES_FILE_TEMPLATE: String = {
        let user = get_user_by_uid(get_current_uid()).unwrap();
        if user.uid() == 0 {
            // if root user, use template with username definitions
            format!("
# version=0.1
# {}: system-wide bluet rules file.
# Unlike other rules files, this one has an additional username field,
# so don't forget to include the username as whom to run the command.

# Example of rule definition:
# .----------------------- rule (ANY; PAIRED; NOT_PAIRED)
# |   .------------------- address (*; aa:bb:cc:dd:ee:ff)
# |   | .----------------- event (CONNECT; DISCONNECT; FOUND; LOST)
# |   | |     .----------- username to run the command as
# |   | |     |        .-- command to be executed
# |   | |     |        |
# ANY * FOUND username ./command.sh

", RULES_FILENAME)

        } else {
            // if not root, use template without username definitions
            format!("
# version=0.1
# {}: users bluet rules file.
# Rules file for a single user.

# Example of rule definition:
# .----------------------- rule (ANY; PAIRED; NOT_PAIRED)
# |   .------------------- address (*; aa:bb:cc:dd:ee:ff)
# |   | .----------------- event (CONNECT; DISCONNECT; FOUND; LOST)
# |   | |     .----------- command to be executed
# |   | |     |
# |   | |     |
# ANY * FOUND ./command.sh

", RULES_FILENAME)
        }
    };
}
