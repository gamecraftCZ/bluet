# BlueT (Bluetooth triggers made easy)

---

Linux daemon for specifying bluetooth triggers at the ease of crontab.

## Trigger rules file

- Global one in `/etc/bluet/.bluet`
- Local `.bluet` for each user stored in their home directory.
- Scripts are run in users home folder
- To reload the `.bluet` trigger rules, use `systemctl bluet reload`

### Trigger rules file structure

- One trigger rule per line
- Lines starting with `#` are ignored

- Rule structure: `<filter> <address> <event> <!username> <command>`

- **filter**:
    - `ANY` = Match any device
    - `PAIRED` = Match only paired devices
    - `NOT_PAIRED` = Match only devices that are not paired
- **address** (Bluetooth address matching):
    - `*` = Match devices regardless their BT address
    - `aa:bb:cc:dd:ee:ff` = Match only device with this BT address
- **event** (Event to listen for):
    - `CONNECT` = Trigger command when device connects
    - `DISCONNECT` = Trigger command when device disconnects
    - `FOUND` = Trigger command when device comes to proximity of your PC
    - `LOST` = Trigger command when device leaves from proximity of your PC
- **! username**
    - ONLY valid in global `/etc/bluet/.bluet` triggers file.
    - Specifies under which user to run the
- **command**
    - Command to be run in default user terminal
    - Working directory is set to users home folder

## Configuration file

- Stored in `/etc/bluet/bluet_conf.toml`
- To load new config file, use `systemctl bluet restart` (reload is not enough, mut be restart)
- Writen in TOML

### Configuration file structure

- `rssi_threshold = int` (default -70)
    - Minimum signal strength to consider device to be in proximity and trigger FOUND rule.

- `timeout_for_disconnect = int` (default 30)
    - If not pings from device for <timeout_for_disconnect> seconds, trigger LOST event.

- `expired_check = int` (default 5)
    - Check if some device is LOST each <expired_check> seconds.

- `bluetooth_device = OPTIONAl(String)` (default None)
    - Bluetooth device to use for scanning, if not present, default device is used

## Troubleshooting

- If you get `your_script.sh: command not found` for script you have in your home directory,
  change its path to `./your_script.sh`

## Requirements for running:

- Running `BlueZ` daemon

## Requirements for compilation

- Installed `libbus-1-dev`