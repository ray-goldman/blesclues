# BLE's Clues

BLE's Clues is a Raspberry Pi tool for observing Bluetooth Low Energy (BLE) advertisements and matching them against operator-configured rules. It can also scan nearby Wi-Fi networks when that feature is enabled.

## Quick start

Use a Raspberry Pi 3 Model B or newer with Raspberry Pi OS Lite Bookworm or later. Set the two-letter country code for the place where the Pi will operate, then run the installer:

```sh
AP_COUNTRY=US sudo -E bash scripts/install.sh
```

Replace `US` with the appropriate country code. Connect the Pi to Ethernet and open `https://<Pi Ethernet IP>:8080`. The dashboard uses a locally generated self-signed TLS certificate; the browser will show a certificate warning until you trust that certificate on your device. The installer prints a one-time dashboard password. Save it, sign in, and change it in **Settings**.

The hidden `Detector-Admin` Wi-Fi network is optional and disabled by default. Enable it in **Settings** when needed. Its factory password is `easypassword`, and the dashboard is available at `https://192.168.4.1:8080`. The hotspot provides local access and does not forward internet traffic. Keep the dashboard password separate from the Wi-Fi password.

The example passive Bluetooth filter uses synthetic bytes. Configure `bluetooth.or_patterns` in `/etc/bt-signature-detector/detector.yaml` for the adapter and advertisements you intend to observe before expecting passive results. See [Raspberry Pi installation](docs/raspberry-pi-install.md).

## Scanning and matching

- **Passive BLE monitoring** applies configured BlueZ advertisement filters, then checks matching advertisements against enabled signatures and watch rules. The synthetic example filter is not a ready-made detector profile.
- **Wi-Fi discovery** is optional and off by default. When enabled, the Pi scans for network names and BSSIDs every 15 seconds; it does not join networks. The single Wi-Fi radio can scan or host the hidden admin network, one mode at a time.
- **Devices** shows advertisers received by the continuously running scanner with its configured passive BlueZ filters. **Pause updates** freezes only the page display; the scanner and optional Wi-Fi scan keep running. Resume updates the displayed BLE and Wi-Fi results. The device list stays in memory and is not saved as history.
- **Watch Lists** lets an operator save named rules based on an observed address or address prefix, advertised name, manufacturer data, or service UUID/data. Exact addresses can rotate. The page shows whether each enabled rule has a compatible passive acquisition filter.
- **Live Feed** shows a bounded window of recent BLE observations and, when Wi-Fi discovery is enabled, nearby SSIDs and BSSIDs. The feed is volatile; qualifying matches are stored separately in bounded SQLite event history.

Settings includes a bundled catalog of BLE and Wi-Fi indicators. A built-in indicator must score at least 40 to qualify; a BLE and Wi-Fi match within 60 seconds adds 20 points to the later observation. Vendor, OUI, advertised-name, and SSID patterns are leads for review. They do not confirm a device's identity, owner, or activity.

## Useful commands

```sh
sudo systemctl status bt-signature-detector.service
sudo journalctl -u bt-signature-detector.service -f
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector status --config /etc/bt-signature-detector/detector.yaml
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector recent --config /etc/bt-signature-detector/detector.yaml
```

To run the project test suite, install the development dependencies and run `python -m unittest discover -s tests -v`.

## Data and privacy

- Ordinary BLE and Wi-Fi observations are kept in bounded memory under `/run`. They are cleared when scanning stops or the Pi reboots; they are not stored as a device inventory.
- The Live Feed redacts BLE addresses. Only qualifying detections enter SQLite event history, which has retention and row-count limits.
- Routine observations are not written to logs. System services use journal rate limits to reduce SD-card writes during repeated faults.
- BLE's Clues does not connect to, pair with, authenticate to, or control observed devices. The temporary Devices scan may send BLE scan requests.
- Rotating Bluetooth addresses remain separate observations. Company labels identify the company assigned a Bluetooth SIG number; they do not establish who made or operates an observed device.
- Remote ntfy and SMS messages omit observed identifiers. SMS is disabled by default, and a test send requires `--confirm-sms`.

## Documentation

- [Raspberry Pi installation](docs/raspberry-pi-install.md)
- [Software updates](docs/software-updates.md)
- [Troubleshooting](docs/troubleshooting.md)
- [CarPlay and Siri testing](docs/carplay-testing.md)
