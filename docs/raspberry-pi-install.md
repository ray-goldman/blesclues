# Raspberry Pi OS installation

## Requirements

- Raspberry Pi 3 Model B or newer, Raspberry Pi OS Lite Bookworm or later, Bluetooth adapter, and wired Ethernet connection for initial admin setup.
- Ethernet provides dashboard access and internet connectivity for release checks. BLE scanning itself does not require internet. An optional hidden local Wi-Fi network can also provide dashboard access when enabled in Settings.
- NetworkManager, BlueZ, Python 3.11+, and systemd are installed by the installer.

## Install

Set the regulatory country before the installer makes any system changes. Example for the United States:

```sh
AP_COUNTRY=US sudo -E bash scripts/install.sh
```

The installer creates the `bt-detector` and `bt-web` service accounts, persistent configuration/state directories, and separate scanner/web systemd services. It replaces the legacy `BLE-Detector` hotspot with a hidden `Detector-Admin` profile that is disabled by default. The web service listens on Ethernet and the local AP address; it requires the separate UI password on both. The AP has no internet forwarding and its default Wi-Fi password is `easypassword`. It copies example files only when the destination files are absent.

Connect the Pi to the trusted network with Ethernet, find its assigned IP in your router or with `hostname -I`, and browse to `http://<Pi Ethernet IP>:8080`. The installer prints a randomly generated UI password once; save it and change it in **Settings**. To enable hotspot access, sign in over Ethernet, open **Settings**, and enable **Hidden Wi-Fi admin access**. Add the hidden network `Detector-Admin` manually on the client and connect using the configured Wi-Fi password; browse to `http://192.168.4.1:8080`.

In **Settings**, set the HTTPS release manifest URL to enable release checks when Ethernet has internet access. The signed local bundle upload works on Ethernet or the optional hotspot without an uplink.

The Settings page shows 13 bundled BLE/Wi-Fi rules derived from the supplied signature, SSID, BLE-name, and OUI data. The default alert threshold is 40 points. When BLE and Wi-Fi matches are observed within 60 seconds, the later hit receives a 20-point bonus. OUI checks ignore locally administered addresses; names and SSIDs are still checked. These patterns can produce false positives and do not establish identity, ownership, or activity.

Wi-Fi discovery is optional and off by default. When enabled, the Pi requests a nearby-network scan every 15 seconds using `iw`; it does not associate with or authenticate to networks. The same WLAN radio serves the hidden hotspot, so enabling scanning stops the hotspot, and enabling the hotspot stops scanning. The dashboard remains available on wired Ethernet in either mode. Live SSID/BSSID results are bounded and stored only in `/run`; only qualifying detections enter event history. Per-scan results are not written to the SD card.

The authenticated **Devices page** starts a temporary broad BLE scan using active scan requests. It never connects to or pairs with devices. The live list is grouped by exact observed BLE address, bounded in memory, and expires after the configured absence interval; no device history is saved. **Pause** stops broad scanning and holds the current list on screen. **Resume scan** starts a fresh scan window. **Stop and restore filters** returns to the saved Bluetooth mode and clears the displayed list. A scanner restart during browsing keeps the temporary mode; browser mode ends on reboot and returns to the saved mode. The temporary mode does not change `/etc/bt-signature-detector/detector.yaml`.

The live BLE/Wi-Fi scan buffers are held in `/run`; routine observations and per-scan results are not logged to disk. Qualifying detections are stored in bounded SQLite history. Service messages go to journald with per-service rate limits to keep fault loops from flooding the SD card.

## Live Feed and Watch Lists

The authenticated navigation includes **Monitor**, **Live Feed**, **Devices**, **Watch Lists**, **Settings**, and **Updates**. Live Feed shows the bounded `/run` BLE advertisement window with addresses redacted, plus SSID/BSSID scan results when Wi-Fi scanning is active. Raw results are volatile and are not a saved device inventory; stopping a scan service or rebooting clears them.

In **Devices**, start a temporary broad scan, select **Watch this** on an observed row, then choose the characteristics that should identify future advertisements and save the rule under a named list. Available criteria include the exact observed address or first one to three MAC octets, exact/contained/regular-expression advertised name, SIG manufacturer company ID with an optional payload prefix, and advertised service UUID or service-data prefix. Address prefixes can match multiple devices, and an address may rotate. Watch rules begin with at least three required observations and notifications disabled.

Watch rules are stored in the existing signature file and are checked by the existing software matcher. They match only advertisements delivered by the active scan mode. Coverage is **Full** when an enabled rule has a compatible derived passive acquisition filter (one compatible criterion is enough for an `all` rule), **Partial** when an `any` rule has both filterable and unfilterable criteria, **Browser scan only** when no compatible filter can be derived, and **Disabled** when the rule is paused. Derived filters are combined at scanner startup with manually configured BlueZ filters and never replace them. In Settings, BlueZ filters are advanced raw advertisement-byte patterns applied before watch rules; they do not match MAC addresses, and a wrong pattern can hide observations. Device Browser ignores them. The temporary Device Browser uses its separate unfiltered active scan and **Stop and restore filters** returns the scanner to configured passive behavior without changing the saved scan mode.

Saving, renaming, enabling, disabling, or deleting a watch rule or list writes the signature file atomically and restarts the scanner so it reloads the rules. If restart fails, BLE's Clues restores the prior file and reports the error. Only operator changes write watch-rule configuration; qualifying matches use existing bounded SQLite retention. Raw advertisements and the device list stay under `/run`, do not enter SQLite, and clear on reboot.

Manufacturer-data company IDs show an assigned company name when found in the bundled Bluetooth SIG Assigned Numbers YAML registry snapshot. Lookup is local and needs no network access during scanning. The assigned-number label does not prove that company made, owns, or operates an observed device, and company IDs are not BLE-address OUIs.

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
