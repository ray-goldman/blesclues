# Troubleshooting

## Admin dashboard is unreachable

The admin dashboard is served through Ethernet and the optional AP address. For Ethernet, check `ip -4 addr show dev eth0`; for hotspot access, check `systemctl status bt-signature-detector-ap.service` and `nmcli connection show --active`. The hidden AP is called `Detector-Admin`, uses `192.168.4.1`, and must be enabled in Settings. Check `systemctl status bt-signature-detector-web.service` and `journalctl -u bt-signature-detector-web.service -n 100 --no-pager` for service errors.

## Web login and password

If the UI password is forgotten, stop the web service and remove only the configured `web.password_hash_file`; restart the service and create a new UI password. Do not delete the session key or detector database to reset login.

## No BLE observations

Check `systemctl status bluetooth.service bt-signature-detector.service` and `journalctl -u bt-signature-detector.service -f`. Validate the configuration and adapter name. Passive mode requires BlueZ `or_patterns`; a generic or synthetic pattern is unlikely to match nearby devices. Controller/firmware limitations may prevent passive scanning. The service retries with a capped delay and never falls back to active scanning.

For an explicitly started Devices scan, check the BLE scanner state and error shown on the Devices page. The `scanner-status.json` snapshot in `/run/bt-signature-detector` distinguishes an active systemd process from a scanner that is retrying after an adapter error. Use **Stop and restore filters** even when the adapter is unavailable; reboot also clears temporary browser mode.

If **Start device scan** reports an exit status, the dismissible error panel keeps the helper's sanitized stderr through normal status polling. Check `sudo -n /usr/local/sbin/bt-detector-device-browser start` and `sudo -n /usr/local/sbin/bt-detector-device-browser stop` as the `bt-web` account, then inspect `journalctl -u bt-signature-detector.service -n 100 --no-pager`. The sudo rule intentionally grants only these fixed start/stop helper actions.

## Wi-Fi scan is unavailable

Wi-Fi scanning is off by default. Enable it from **Settings** while the hidden admin hotspot is off. The single WLAN radio cannot scan and host the hotspot at the same time; mode changes stop one service before starting the other. Check `systemctl status bt-signature-detector-wifi.service bt-signature-detector-wifi-mode.service` and `journalctl -u bt-signature-detector-wifi.service -n 50 --no-pager`. The scan uses `iw` and `CAP_NET_ADMIN`; it does not join detected networks. Raw scan results stay in `/run` and are not written to SQLite or the SD card.

## No detection or alert

Check the signature file, RSSI threshold, and three-observation minimum. A stronger RSSI number is closer to zero. Custom signature notifications require `confidence: confirmed` and notifications enabled. Bundled BLE/Wi-Fi indicators use the separate score threshold of 40; an opposite-protocol match within 60 seconds adds 20 points to the later hit. These indicator matches may dispatch through configured notification backends, but are not confirmation of equipment identity, ownership, or activity. `detector test-alert` tests enabled backends. Add `--confirm-sms` before sending a live SMS test.

For a saved watch rule, check its passive coverage on **Watch Lists**. **Browser scan only** rules cannot contribute an acquisition filter and will not match in filtered passive mode unless an advertisement also passes a manually configured BlueZ filter. **Partial** coverage applies to `any` rules with a mix of filterable and unfilterable criteria. A watch-rule change restarts the scanner; if that restart fails, the prior signature file is restored. The Live Feed shows only the packets the current scan mode receives and clears on reboot.

Manufacturer-data company labels come from the bundled Bluetooth SIG Assigned Numbers registry. An unknown company ID remains visible numerically. The assigned company label is not proof of the observed device's manufacturer or owner.

## Network and updates

Release checks need internet access through Ethernet. A signed bundle can also be uploaded from a client on Ethernet or the optional hidden hotspot. The AP has no internet forwarding. See [software updates](software-updates.md).
