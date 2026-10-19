# BLE's Clues

BLE's Clues is a Bluetooth Low Energy (BLE) signature detector for Raspberry Pi OS. It normally observes advertisements using configured filters, compares them with signature rules, and stores only detections that pass the signal and repeated-observation filters.

## Quick start

Use Raspberry Pi 3 Model B or newer with Raspberry Pi OS Lite Bookworm or later. Before installing, set your local two-letter regulatory country code:

```sh
AP_COUNTRY=US sudo -E bash scripts/install.sh
```

Replace `US` with the country where the Pi will operate. Connect the Pi to your trusted network by Ethernet and open `http://<Pi Ethernet IP>:8080`. The installer prints a separate one-time UI password; sign in with it and change it in Settings. The optional hidden `Detector-Admin` Wi-Fi network is disabled by default. Enable it in Settings when needed; it uses `easypassword` initially and provides local dashboard access at `http://192.168.4.1:8080` without forwarding internet traffic.

The example passive scan filter contains synthetic bytes and is not a detector profile. Edit `/etc/bt-signature-detector/detector.yaml` and configure the adapter-specific `bluetooth.or_patterns` before expecting observations. See [Raspberry Pi installation](docs/raspberry-pi-install.md).

The authenticated **Devices page** can temporarily scan broadly with active scan requests and show nearby advertisers that do not match those filters. It does not connect to or pair with devices. Choose **Stop and restore filters** to return to the saved mode; browser mode ends on reboot. The live device list is bounded, volatile, and not saved as history.

**Settings** lists the bundled BLE and Wi-Fi indicators, including their source notes. A qualifying built-in alert needs a score of 40. If BLE and Wi-Fi indicators occur within 60 seconds, the second observation receives a 20-point bonus. These vendor, OUI, name, and SSID patterns are leads for review; they do not confirm a device, owner, or activity. The Wi-Fi scan is optional, defaults off, requests nearby-network scans every 15 seconds, and never joins a network. The WLAN radio can scan or host the hidden admin network, one mode at a time; enabling one turns the other off.

The **Live Feed** shows the current BLE observation window and, when enabled, nearby SSIDs/BSSIDs. Raw observations live only under `/run` and clear when the service stops or the Pi reboots. Only threshold-qualified matches enter the bounded SQLite event history.

Use **Live Feed** to review the bounded, address-redacted BLE advertisement window and optional Wi-Fi sightings. It shows only data received by the current scan modes and is not a saved device inventory. From **Devices**, select **Watch this** on an observation to choose its address, advertised name, manufacturer-data prefix, or service UUID, then save the rule under a named list. Exact addresses can rotate, so address rules match only that observed identifier.

The **Watch Lists** page shows passive coverage for each saved rule. **Full** means a compatible BlueZ filter can acquire its match path, **Partial** means an `any` rule mixes filterable and unfilterable criteria, and **Browser scan only** means none of the criteria can derive a passive filter. Rules match only advertisements received by the current mode. Derived filters are combined at scanner startup with the manually configured BlueZ filters; they do not overwrite the configured list or enable active scanning. Saving, editing, or removing a watch rule restarts the scanner, and failed restarts restore the previous signature file. Rules persist in the existing signature file; matches use the bounded SQLite history.

Manufacturer-data company IDs may display a Bluetooth SIG Assigned Numbers company label from a bundled offline snapshot. This label identifies the company assigned that number; it does not prove the observed device's manufacturer, owner, or operator, and it is not derived from the BLE address.

## Useful commands

```sh
sudo systemctl status bt-signature-detector.service
sudo journalctl -u bt-signature-detector.service -f
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector status --config /etc/bt-signature-detector/detector.yaml
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector recent --config /etc/bt-signature-detector/detector.yaml
```

For the project test suite, install the development dependencies and run `python -m unittest discover -s tests -v`.

## Safety and privacy

- BLE's Clues never connects, pairs, authenticates, or controls observed devices. The explicit Devices mode may send BLE scan requests to advertisers.
- Use only synthetic examples until you have lawfully documented, validated signatures. Generic BLE identifiers do not identify equipment.
- Rotating Bluetooth addresses remain separate observations; the detector does not infer a device identity.
- Ordinary advertisements and the Devices list appear only in a bounded `/run` cache, which is volatile; the Live Feed redacts addresses. They are not saved as a device inventory. SQLite retains qualifying match events under its existing retention and row-count limits.
- Remote ntfy and SMS messages omit observed identifiers. SMS is disabled by default; a test send requires `--confirm-sms`.
- Routine advertisements stay in the bounded volatile cache and are not written to durable history. Watch-list rules are written to the signature file only when an operator changes them; qualifying watch matches are stored as bounded events. Scanner, web, and updater journal output has per-service rate limits to reduce SD-card writes during faults.
- The optional hidden Wi-Fi network is off by default and does not forward traffic. Keep the separate UI password private; use wired Ethernet for normal administration and enable the hotspot only when needed.

## Documentation

- [Raspberry Pi installation](docs/raspberry-pi-install.md)
- [Troubleshooting](docs/troubleshooting.md)
- [CarPlay and Siri validation](docs/carplay-testing.md)
- [Software updates](docs/software-updates.md)
