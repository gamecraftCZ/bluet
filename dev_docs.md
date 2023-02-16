# BlueT development documentation

## Overall functioning

BlueT is scanning for bluetooth devices using BlueZ over system D-Bus. It keeps track of the devices found and checks for rule triggers on incoming events. On top of event checks, there is also timeout check every `CONFIG.expired_check` seconds to check for devices which went out of range without event being triggered. On `systemctl reload` (SIGHUP signal) load new rules, delete old ones and check for triggers on changed/new rules.

### How is rule command run

When the rule is triggered, BlueT creates a process fork, sets gid and uid, and runs the command in user home folder with user's default terminal as defined in `/etc/passwd`.

### Rule triggers

- CONNECT: triggers when device `connected` property is set to true and does not change till a second check in 2 seconds. This is due to when connection fails, `connected` is set to true and back to false.
- DISCONNECT: triggers when `connected` is set to false and previously CONNECT event conditions were fulfilled.
- FOUND: triggers when `rssi` property (signal strength) goes above `CONFIG.rssi_threshold`
- LOST: trigger if a) device `rssi` property is set to None by an event or b) BlueZ did not send any event about the device in the last `CONFIG.timeout_for_disconnect` seconds.

### Main() function in main.rs

Handles initialization, then waits for events. All events are handled in parallel by EventManager. Events are: 1) bluetooth events (device props changed, new device, device removed), 2) SIHGUP signal (`systemctl reload`), 3) device timeout check, 4) recheck if device connect was valid. Each of these event types has it's own pipe.

## Modules

### bt_triggerer.rs

Uses BlueZ to scan for Bluetooth device events. Parses these events and sends them to Bluetooth events pipe.

### common.rs

Contains datatypes used through the code. It also contains Rule trigger code.

### consts.rs

Constants. Some of them are lazily created so they can be different in each run of the program. (eg. rules file path)

### global_config.rs

Global `CONFIG` as constant. Config is lazily loaded from a config file.

### parser.rs

Handles rules file loading and parsing.
