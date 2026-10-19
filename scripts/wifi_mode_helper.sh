#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This helper must run as root." >&2
  exit 1
fi

case "${1:-}" in
  scan-start)
    systemctl stop bt-signature-detector-ap.service
    systemctl start bt-signature-detector-wifi.service
    ;;
  scan-stop)
    systemctl stop bt-signature-detector-wifi.service
    ;;
  ap-start)
    systemctl stop bt-signature-detector-wifi.service
    systemctl start bt-signature-detector-ap.service
    ;;
  ap-stop)
    systemctl stop bt-signature-detector-ap.service
    systemctl stop bt-signature-detector-dhcp.service
    ;;
  *)
    echo "Expected scan-start, scan-stop, ap-start, or ap-stop." >&2
    exit 2
    ;;
esac
