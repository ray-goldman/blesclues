# Raspberry Pi OS installation

## Requirements

- Raspberry Pi 3 Model B or newer, Raspberry Pi OS Lite Bookworm or later, a Bluetooth adapter, and Ethernet for initial setup.
- NetworkManager, BlueZ, Python 3.11+, and systemd. The installer adds the required application packages and services.

## Install

Set the regulatory country before the installer makes any system changes. Example for the United States:

```sh
AP_COUNTRY=US sudo -E bash scripts/install.sh
```

The installer creates separate `bt-detector` and `bt-web` service accounts, persistent configuration and state directories, and scanner and web services. It replaces the old `BLE-Detector` profile with a hidden `Detector-Admin` hotspot that is off by default. The dashboard requires the UI password over both Ethernet and hotspot. The hotspot does not forward internet traffic and starts with the Wi-Fi password `easypassword`. Example files are copied only when a destination file is missing.

Connect the Pi to Ethernet, find its address in your router or with `hostname -I`, and open `http://<Pi Ethernet IP>:8080`. Save the randomly generated UI password printed by the installer, sign in, then change it in **Settings**. To enable hotspot access, turn on **Hidden Wi-Fi admin access** in Settings. Add `Detector-Admin` manually on your phone or computer, connect with the configured Wi-Fi password, and open `http://192.168.4.1:8080`.

In **Settings**, set the HTTPS release manifest URL to enable release checks when Ethernet has internet access. The signed local bundle upload works on Ethernet or the optional hotspot without an uplink.

Settings lists 13 bundled BLE and Wi-Fi indicators derived from the supplied signatures, SSID patterns, BLE names, and OUI data. An indicator must score 40 points to qualify. A BLE and Wi-Fi match within 60 seconds gives the later match a 20-point bonus. OUI checks skip locally administered addresses; name and SSID checks still run. Treat matches as leads for review, not proof of identity, ownership, or activity.

Wi-Fi discovery is off by default. When enabled, the Pi uses `iw` to scan every 15 seconds without joining or authenticating to networks. The Wi-Fi radio can scan or host the hidden hotspot, but cannot do both at once. Switching modes stops the current service before starting the other; the dashboard stays available over Ethernet. SSID and BSSID results stay in bounded memory under `/run`; only qualifying detections enter event history. Scan results are not written to the SD card.

The authenticated **Devices page** starts a temporary broad BLE scan using active scan requests. It never connects to or pairs with devices. The live list is grouped by exact observed BLE address, bounded in memory, and expires after the configured absence interval; no device history is saved. **Pause** stops broad scanning and holds the current list on screen. **Resume scan** starts a fresh scan window. **Stop and restore filters** returns to the saved Bluetooth mode and clears the displayed list. A scanner restart during browsing keeps the temporary mode; browser mode ends on reboot and returns to the saved mode. The temporary mode does not change `/etc/bt-signature-detector/detector.yaml`.

The live BLE/Wi-Fi scan buffers are held in `/run`; routine observations and per-scan results are not logged to disk. Qualifying detections are stored in bounded SQLite history. Service messages go to journald with per-service rate limits to keep fault loops from flooding the SD card.

## Live Feed and Watch Lists

After signing in, the navigation includes **Monitor**, **Live Feed**, **Devices**, **Watch Lists**, **Settings**, and **Updates**. Live Feed shows a bounded window of BLE advertisements with addresses redacted, plus nearby SSIDs and BSSIDs when Wi-Fi scanning is enabled. The observations are held in `/run`, not saved as a device inventory, and clear when the scan service stops or the Pi reboots.

In **Devices**, start a temporary broad scan and select **Watch this** on a row to build a named rule. Criteria can use the exact observed address or its first one to three MAC octets; an exact, contained, or regular-expression name; a SIG company ID with an optional payload prefix; or a service UUID or service-data prefix. Address prefixes can match several devices, and a device address may rotate. New rules require at least three matching observations and have notifications disabled.

Watch rules are stored in the signature file and evaluated by the scanner. They can match only advertisements received in the active scan mode. Coverage is:

- **Full:** an enabled rule has a compatible passive acquisition filter. For an `all` rule, one compatible criterion is enough.
- **Partial:** an `any` rule mixes criteria that can and cannot produce a passive filter.
- **Browser scan only:** no passive filter can be derived.
- **Disabled:** the rule is paused.

Derived filters are combined with the manually configured BlueZ filters when the scanner starts; they do not replace them. BlueZ filters are advanced patterns over raw advertisement bytes, not MAC addresses. An incorrect pattern can hide observations. The Device Browser ignores these filters while its temporary broad scan is running. **Stop and restore filters** returns to the saved scan mode without changing its configuration.

Creating, editing, enabling, disabling, or deleting a watch rule writes the signature file atomically and restarts the scanner. If the restart fails, BLE's Clues restores the previous file and reports the error. Operator changes are the only writes to watch-rule configuration. Qualifying matches use the existing bounded SQLite history; raw advertisements and the device list remain under `/run` and clear on reboot.

Manufacturer-data company IDs show an assigned company name when the ID appears in the bundled Bluetooth SIG Assigned Numbers snapshot. Lookup is local and needs no network access during scanning. An assigned-number label does not establish who made, owns, or operates an observed device. Company IDs are separate from BLE address OUIs.

## Configure passive scanning

Edit `/etc/bt-signature-detector/detector.yaml` and select the adapter and BlueZ `or_patterns` for the advertisements you intend to recognize. Passive BlueZ scanning requires at least one OR pattern. A pattern uses an advertisement data start position, AD data type, and hexadecimal bytes. The included `010203` pattern is synthetic. If the controller does not support passive monitoring, inspect the logs; normal filtered mode retries without changing to active scanning. Broad active scanning is only enabled explicitly from the Devices page.

Add validated, documented signatures in `/etc/bt-signature-detector/signatures.yaml`. Use manufacturer data masks, service UUID/data, names, or exact observed identifiers only when lawful and appropriate. A detection requires at least three matching observations by default; the default alert cooldown is 300 seconds. RSSI is approximate and does not establish distance.

```sh
sudo systemctl restart bt-signature-detector.service
sudo journalctl -u bt-signature-detector.service -n 100 --no-pager
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector validate-config --config /etc/bt-signature-detector/detector.yaml
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector list-signatures --config /etc/bt-signature-detector/detector.yaml
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector recent --config /etc/bt-signature-detector/detector.yaml
```

## Notifications and secrets

Audio uses the configured player, normally `aplay`, and a local sound file. ntfy is opt-in and uses an HTTPS server/topic; authentication values are read from environment variable names in the config. Twilio SMS is optional (`pip install '.[sms]'` during a manual install), disabled by default, and reads its account SID, auth token, and sender number from the service environment file. Keep `/etc/bt-signature-detector/environment` root-owned and mode `0600`. Carrier registration, A2P 10DLC or equivalent local rules, sender approval, and recipient consent may be required. Do not assume ntfy notifications appear in CarPlay.

## Data and removal

Detection history is `/var/lib/bt-signature-detector/events.sqlite3`; retention defaults to 30 days and 10,000 events. Back up that file and configuration if needed. Ordinary live scans are held in `/run/bt-signature-detector` and disappear on reboot.

Run `sudo bash scripts/uninstall.sh` to remove services and the application while preserving configuration and SQLite history. Use `sudo bash scripts/uninstall.sh --purge` only when you intend to remove configuration and history too.
