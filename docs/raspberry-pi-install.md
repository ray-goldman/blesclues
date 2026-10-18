# Raspberry Pi OS installation

## Requirements

- Raspberry Pi 3 Model B or newer, Raspberry Pi OS Lite Bookworm or later, Bluetooth adapter, and Wi-Fi interface capable of access point mode.
- Ethernet is optional for internet connectivity and release checks. The detector, dashboard, and access point work without internet.
- NetworkManager, BlueZ, Python 3.11+, and systemd are installed by the installer.

## Install

Set the regulatory country before the installer makes any system changes. Example for the United States:

```sh
AP_COUNTRY=US sudo -E bash scripts/install.sh
```

The installer creates the `bt-detector` and `bt-web` service accounts, a dedicated NetworkManager profile, local DHCP service, persistent configuration/state directories, and separate scanner/web systemd services. It copies example files only when the destination files are absent. It does not depend on `network-online.target`.

Join `BLE-Detector` with the default Wi-Fi password `easypassword` and browse to `http://192.168.4.1:8080`. The installer prints a randomly generated, separate UI password once; save it and change it in **Settings** after signing in. The UI listens on the AP address and the UI password is never the Wi-Fi password.

In **Settings**, set the HTTPS release manifest URL to enable Ethernet release checks. The signed local bundle upload works without an uplink.

## Configure passive scanning

Edit `/etc/bt-signature-detector/detector.yaml` and select the adapter and BlueZ `or_patterns` for the advertisements you intend to recognize. Passive BlueZ scanning requires at least one OR pattern. A pattern uses an advertisement data start position, AD data type, and hexadecimal bytes. The included `010203` pattern is synthetic. If the controller does not support passive monitoring, inspect the logs; the detector retries without changing to active scanning.

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

Run `sudo bash scripts/uninstall.sh` to remove services and the application while preserving configuration, SQLite history, and the NetworkManager AP profile. Use `sudo bash scripts/uninstall.sh --purge` only when you intend to remove configuration and history too.
