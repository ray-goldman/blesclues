# Troubleshooting

## The AP does not appear

Check `systemctl status NetworkManager bt-signature-detector-dhcp.service` and `nmcli connection show --active`. Confirm the country code in `/etc/bt-signature-detector/detector.yaml` matches the Pi's operating location and that the selected Wi-Fi interface supports AP mode. Check kernel logs with `journalctl -u NetworkManager -b`. The detector AP uses `wlan0`, channel 6, and `192.168.4.1/24` by default.

Clients receive an address in `192.168.4.20` through `192.168.4.200`. DHCP is local to the AP; internet routing is not enabled. Open `http://192.168.4.1:8080` after connecting.

## Web login and password

The Wi-Fi password and UI password are separate. If the UI password is forgotten, stop the web service and remove only the configured `web.password_hash_file`; restart the service and create a new UI password. Do not delete the session key or detector database to reset login.

## No BLE observations

Check `systemctl status bluetooth.service bt-signature-detector.service` and `journalctl -u bt-signature-detector.service -f`. Validate the configuration and adapter name. Passive mode requires BlueZ `or_patterns`; a generic or synthetic pattern is unlikely to match nearby devices. Controller/firmware limitations may prevent passive scanning. The service retries with a capped delay and never falls back to active scanning.

## No detection or alert

Check the signature file, RSSI threshold, and three-observation minimum. A stronger RSSI number is closer to zero. Confirm that alert notifications are enabled on a signature with `confidence: confirmed`; lower-confidence matches are logged/stored but do not dispatch notifications. `detector test-alert` tests enabled backends. Add `--confirm-sms` before sending a live SMS test.

## Ethernet and updates

The dashboard remains available without Ethernet. Release checks need Ethernet or another uplink; local signed bundle upload can be used offline after the updater is configured. See [software updates](software-updates.md).
