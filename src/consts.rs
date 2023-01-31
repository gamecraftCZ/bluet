//! Loading runtime constants and making them globaly available.

const RULES_FILENAME: &str = "rules";
const CONFIG_FILENAME: &str = "conf.toml";
const GLOBAL_CONFIG_DIR: &str = "/etc/bluet";
const LOCAL_CONFIG_PATH: &str = ".config/bluet"

lazy_static! {
    pub const static ref BLUET_DIR = {
        let user = get_user_by_uid(get_current_uid()).unwrap();
        if user.uid() == 0 {
            // If root user, global folder is used
            GLOBAL_CONFIG_DIR
        } else {
            // For othet users, use folder in their home dir
            format!("{}/{}", user.home_dir(), LOCAL_CONFIG_PATH)
        }
    }
    pub const static ref CONFIG_FILEPATH: &str = {
    .   format!("{BLUET_DIR}/{CONFIG_FILENAME}")
    }
    pub const static ref RULES_FILEPATH: &str = {
        format!("{BLUET_DIR}/{RULES_FILENAME}")
    }
}
