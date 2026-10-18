# Raspberry Pi Bluetooth Signature Detector

An advertisement-only Bluetooth Low Energy (BLE) detector for Raspberry Pi OS. It passively observes BLE advertisements, compares configured patterns, and stores only detections that pass the signature, signal, and repeated-observation filters.

## Quick start

Use Raspberry Pi 3 Model B or newer with Raspberry Pi OS Lite Bookworm or later. Before installing, set your local two-letter regulatory country code:

```sh
AP_COUNTRY=US sudo -E bash scripts/install.sh
```

Replace `US` with the country where the Pi will operate. Join the `BLE-Detector` Wi-Fi network with the default passphrase `easypassword`, then open `http://192.168.4.1:8080`. The installer prints a separate one-time UI password; sign in with it and change it in Settings. The AP is local-only and provides no internet forwarding.

The example passive scan filter contains synthetic bytes and is not a detector profile. Edit `/etc/bt-signature-detector/detector.yaml` and configure the adapter-specific `bluetooth.or_patterns` before expecting observations. See [Raspberry Pi installation](docs/raspberry-pi-install.md).

## Useful commands

```sh
sudo systemctl status bt-signature-detector.service
sudo journalctl -u bt-signature-detector.service -f
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector status --config /etc/bt-signature-detector/detector.yaml
sudo -u bt-detector /opt/bt-signature-detector/active/bin/detector recent --config /etc/bt-signature-detector/detector.yaml
```

For the project test suite, install the development dependencies and run `python -m unittest discover -s tests -v`.

## Safety and privacy

- The scanner never connects, pairs, authenticates, or transmits to observed devices.
- Use only synthetic examples until you have lawfully documented, validated signatures. Generic BLE identifiers do not identify equipment.
- Rotating Bluetooth addresses remain separate observations; the detector does not infer a device identity.
- Ordinary advertisements appear only in a bounded `/run` cache, which is volatile. SQLite retains filtered detections only.
- Remote ntfy and SMS messages omit observed identifiers. SMS is disabled by default; a test send requires `--confirm-sms`.
- Wi-Fi and UI credentials are separate. Change the default AP password after initial setup and keep the UI password private.

## Documentation

- [Raspberry Pi installation](docs/raspberry-pi-install.md)
- [Troubleshooting](docs/troubleshooting.md)
- [CarPlay and Siri validation](docs/carplay-testing.md)
- [Software updates](docs/software-updates.md)
