# BlueT (Bluetooth triggers made easy)

---

Linux daemon for specifying bluetooth triggers at the ease of crontab.

Read BlueT as  "Blue Tea"

## Trigger rules file

- Global one in `/etc/bluet/rules`
- User local in `~/.config/bluet/rules`
- Scripts are run in users home folder
- To reload the rules, use `systemctl reload bluet` or for user daemon `systemctl --user reload bluet`

### Trigger rules file structure

- One trigger rule per line
- Lines starting with `#` are ignored

- Rule structure: `<filter> <address> <event> <!username> <command>`
- Example: `ANY 11:22:33:44:55:66 FOUND ./headphones_found.sh`

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
    - Don't forget to add `./` prefix if running script from your home directory

## Configuration file

- Global in `/etc/bluet/conf.toml`
- Local user daemon config in `~/.config/bluet/conf.toml`
- To load new config file, use `systemctl bluet restart` or `systemctl --user bluet restary` (reload is not enough, must be restarted)
- Written in TOML

### Configuration file structure

- `rssi_threshold = int` (default -70)
    - Minimum signal strength to consider device to be in proximity and trigger FOUND rule.

- `timeout_for_disconnect = int` (default 30)
    - If not pings from device for <timeout_for_disconnect> seconds, trigger LOST event.

- `expired_check = int` (default 5)
    - Check if some device is LOST each <expired_check> seconds.

- `bluetooth_device = OPTIONAL(String)` (default None)
    - Bluetooth device to use for scanning, if not present, default device is used

## Installation as system global daemon
1. Build the project: `cargo build --package bluet --bin bluet_daemon --release --features="daemon"`
2. Copy binary to bin: `sudo cp target/release/bluet_daemon /usr/bin`
3. Copy service definition file: `sudo cp bluet.service /etc/systemd/system`
4. Reload services files: `sudo systemctl daemon-reload`
5. Enable bluet service: `sudo systemctl enable bluet`

## Installation as local user daemon
1. Build the project: `cargo build --package bluet --bin bluet_daemon --release --features="daemon"`
2. Change service definition file to point to bluet_daemon binary file. Must be absolute path!
3. Copy service definition file: `sudo cp bluet.service ~/.config/systemd/user`
4. Reload services files: `sudo systemctl --user daemon-reload`
5. Enable bluet service: `sudo systemctl --user enable bluet`

## Requirements for running:

- Running `BlueZ` daemon

## Requirements for compilation

- Installed `libbus-1-dev`

## Troubleshooting

- If you get `your_script.sh: command not found` for script you have in your home directory,
  change its path to `./your_script.sh`
- Rule is not working: Maybe the rule is defined incorrectly. Check `systemctl status bluet` / `systemctl --user status bluet` for logs. 
  If there was error parsing the rule, you will se it here.

## Development documentation

- Generate development documentation using `cargo doc --no-deps --document-private-items --bin bluet_daemon --workspace --all-features`
- It will be saved in `./target/doc/bluet_daemon`
