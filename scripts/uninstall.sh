#!/usr/bin/env bash
set -euo pipefail
PREFIX="/opt/bt-signature-detector"
CONFIG_DIR="/etc/bt-signature-detector"
STATE_DIR="/var/lib/bt-signature-detector"
PURGE=0
if [[ "${1:-}" == "--purge" ]]; then PURGE=1; elif [[ "$#" -gt 0 ]]; then echo "Usage: sudo $0 [--purge]" >&2; exit 2; fi
if [[ "${EUID}" -ne 0 ]]; then echo "Run this uninstaller with sudo." >&2; exit 1; fi
systemctl disable --now bt-signature-detector.service 2>/dev/null || true
systemctl disable --now bt-signature-detector-web.service bt-signature-detector-dhcp.service bt-signature-detector-ap.service 2>/dev/null || true
rm -f /etc/systemd/system/bt-signature-detector.service /etc/systemd/system/bt-signature-detector-web.service /etc/systemd/system/bt-signature-detector-dhcp.service /etc/systemd/system/bt-signature-detector-ap.service /etc/systemd/system/bt-signature-detector-updater@.service /etc/sudoers.d/bt-signature-detector-ap /usr/local/sbin/bt-detector-apply-update /usr/local/sbin/bt-detector-restart-scanner
systemctl daemon-reload
rm -rf -- "$PREFIX"
if [[ "$PURGE" -eq 1 ]]; then
  if command -v nmcli >/dev/null 2>&1; then nmcli connection delete BLE-Detector 2>/dev/null || true; fi
  rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
  echo "Application, configuration, state, and detector AP profile removed."
else
  echo "Application removed. Configuration and detection history were preserved at $CONFIG_DIR and $STATE_DIR."
fi
