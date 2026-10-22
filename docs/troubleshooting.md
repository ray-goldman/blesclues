# Troubleshooting

## Admin dashboard is unreachable

The dashboard is available over Ethernet and, when enabled, the local hotspot. For Ethernet, check `ip -4 addr show dev eth0`. For hotspot access, check `systemctl status bt-signature-detector-ap.service` and `nmcli connection show --active`. The hidden `Detector-Admin` network uses `192.168.4.1` and must be enabled in **Settings**. Check the web service and its recent logs for errors:

```sh
sudo systemctl status bt-signature-detector-web.service
sudo journalctl -u bt-signature-detector-web.service -n 100 --no-pager
```

## Web login and password

If you forget the dashboard password, stop the web service and remove only the file configured by `web.password_hash_file`. Restart the service and create a new password at login. Do not remove the session key or detector database.

## No BLE observations

Check the Bluetooth and scanner services, then validate the adapter and configuration:

```sh
sudo systemctl status bluetooth.service bt-signature-detector.service
sudo journalctl -u bt-signature-detector.service -f
```

Passive mode requires BlueZ `or_patterns`. A generic or synthetic pattern may not match nearby devices, and some controllers cannot monitor passively. The scanner retries with a capped delay; it does not switch to active scanning on its own.

The **Devices** page reads the same configured BLE scan as the detector. **Pause updates** only stops this page from refreshing; the radio and Live Feed continue. If the displayed rows stop changing, use **Resume updates** and check whether advertisements pass the configured BlueZ filters. The `scanner-status.json` snapshot in `/run/bt-signature-detector` shows whether the scanner is active or retrying after an adapter error.

```sh
sudo journalctl -u bt-signature-detector.service -n 100 --no-pager
```

## Wi-Fi scan is unavailable

Wi-Fi scanning is off by default. Enable it in **Settings** when the hidden hotspot is off. The single radio cannot scan and host the hotspot together; switching modes stops one service before starting the other. Check the Wi-Fi services and recent scan log:

```sh
sudo systemctl status bt-signature-detector-wifi.service bt-signature-detector-wifi-mode.service
sudo journalctl -u bt-signature-detector-wifi.service -n 50 --no-pager
```

The scanner uses `iw` and `CAP_NET_ADMIN`; it does not join networks. Raw results stay in `/run` and are not written to SQLite or the SD card.

## No detection or alert

Check the signature file, RSSI threshold, and three-observation minimum. RSSI values closer to zero indicate a stronger signal. Custom signature alerts require `confidence: confirmed` and notifications enabled. Bundled BLE and Wi-Fi indicators use a separate threshold of 40; a match from the other protocol within 60 seconds adds 20 points to the later hit. These are indicators for review, not confirmation of identity, ownership, or activity. Use `detector test-alert` to test enabled backends. Add `--confirm-sms` to send an actual SMS test.

For a saved watch rule, check its passive coverage on **Watch Lists**. **No derived filter** rules cannot contribute an acquisition filter and will match only if an advertisement also passes another configured BlueZ filter. **Partial** coverage applies to `any` rules with a mix of filterable and unfilterable criteria. A watch-rule change restarts the scanner; if that restart fails, the prior signature file is restored. The Live Feed shows only the packets the configured scan mode receives and clears on reboot.

Manufacturer-data company labels come from the bundled Bluetooth SIG Assigned Numbers registry. An unknown company ID remains visible numerically. The assigned company label is not proof of the observed device's manufacturer or owner.

## Network and updates

Release checks need internet access through Ethernet. A signed bundle can also be uploaded from a client on Ethernet or the optional hidden hotspot. The AP has no internet forwarding. See [software updates](software-updates.md).
