#!/usr/bin/env bash
set -euo pipefail
PREFIX="/opt/bt-signature-detector"
CONFIG_DIR="/etc/bt-signature-detector"
STATE_DIR="/var/lib/bt-signature-detector"
PURGE=0
if [[ "${1:-}" == "--purge" ]]; then PURGE=1; elif [[ "$#" -gt 0 ]]; then echo "Usage: sudo $0 [--purge]" >&2; exit 2; fi
if [[ "${EUID}" -ne 0 ]]; then echo "Run this uninstaller with sudo." >&2; exit 1; fi
systemctl disable --now bt-signature-detector.service 2>/dev/null || true
systemctl disable --now bt-signature-detector-wifi.service 2>/dev/null || true
systemctl disable --now bt-signature-detector-wifi-mode.service 2>/dev/null || true
systemctl disable --now bt-signature-detector-bluetooth.service 2>/dev/null || true
systemctl disable --now bt-signature-detector-web.service bt-signature-detector-dhcp.service bt-signature-detector-ap.service 2>/dev/null || true
if command -v nmcli >/dev/null 2>&1; then nmcli connection delete BLE-Detector 2>/dev/null || true; nmcli connection delete Detector-Admin 2>/dev/null || true; fi
rm -f /etc/systemd/system/bt-signature-detector.service /etc/systemd/system/bt-signature-detector-bluetooth.service /etc/systemd/system/bt-signature-detector-web.service /etc/systemd/system/bt-signature-detector-dhcp.service /etc/systemd/system/bt-signature-detector-ap.service /etc/systemd/system/bt-signature-detector-wifi.service /etc/systemd/system/bt-signature-detector-wifi-mode.service /etc/systemd/system/bt-signature-detector-updater@.service /etc/systemd/system/bluetooth.service.d/10-bt-signature-detector.conf /etc/sudoers.d/bt-signature-detector-ap /etc/sudoers.d/bt-signature-detector-device-browser /etc/sudoers.d/bt-signature-detector-wifi-mode /usr/local/sbin/bt-detector-apply-update /usr/local/sbin/bt-detector-restart-scanner /usr/local/sbin/bt-detector-device-browser /usr/local/sbin/bt-detector-wifi-mode /usr/local/sbin/bt-detector-ap-helper "$CONFIG_DIR/dnsmasq-ap.conf"
systemctl daemon-reload
systemctl restart bluetooth.service
rm -rf -- "$PREFIX"
if [[ "$PURGE" -eq 1 ]]; then
  rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
  echo "Application, configuration, and state removed."
else
  echo "Application removed. Configuration and detection history were preserved at $CONFIG_DIR and $STATE_DIR."
fi
