#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-/opt/bt-signature-detector}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bt-signature-detector}"
STATE_DIR="${STATE_DIR:-/var/lib/bt-signature-detector}"
SERVICE_USER="bt-detector"
AP_COUNTRY="${AP_COUNTRY:-}"

if [[ "${EUID}" -ne 0 ]]; then echo "Run this installer with sudo." >&2; exit 1; fi
if [[ ! -r /etc/os-release ]]; then echo "Cannot identify operating system." >&2; exit 1; fi
. /etc/os-release
if [[ "${ID:-}" != "debian" || "${VERSION_CODENAME:-}" != "bookworm" && "${VERSION_CODENAME:-}" != "trixie" ]]; then
  echo "Supported target: Raspberry Pi OS Bookworm or later Debian-based release." >&2; exit 1
fi
for tool in apt-get systemctl nmcli python3; do
  command -v "$tool" >/dev/null || { echo "Required command missing: $tool" >&2; exit 1; }
done
if [[ ! "$AP_COUNTRY" =~ ^[A-Za-z]{2}$ ]]; then
  echo "Set your regulatory country before installation, for example: AP_COUNTRY=US sudo -E bash scripts/install.sh" >&2
  exit 1
fi

apt-get update
apt-get install -y python3-venv python3-dev libbluetooth-dev network-manager bluez dnsmasq-base sudo iw rfkill
getent group bluetooth >/dev/null || groupadd --system bluetooth
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin --groups bluetooth "$SERVICE_USER"
usermod -a -G bluetooth "$SERVICE_USER"
id -u bt-web >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR/web" --no-create-home --shell /usr/sbin/nologin --groups bt-detector bt-web
usermod -a -G bt-detector bt-web
install -d -o root -g "$SERVICE_USER" -m 0750 "$PREFIX"
install -d -o root -g "$SERVICE_USER" -m 0770 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR"
install -d -o bt-web -g bt-detector -m 0750 "$STATE_DIR/web"
if [[ ! -e "$CONFIG_DIR/environment" ]]; then install -m 0600 /dev/null "$CONFIG_DIR/environment"; fi
iw reg set "$AP_COUNTRY"

if [[ ! -e "$CONFIG_DIR/detector.yaml" ]]; then
  install -m 0640 -o root -g "$SERVICE_USER" "$ROOT_DIR/config/detector.example.yaml" "$CONFIG_DIR/detector.yaml"
  sed -i "s#signatures.example.yaml#signatures.yaml#; s#country: \"\"#country: $AP_COUNTRY#" "$CONFIG_DIR/detector.yaml"
fi
if [[ ! -e "$CONFIG_DIR/signatures.yaml" ]]; then
  install -m 0640 -o root -g "$SERVICE_USER" "$ROOT_DIR/config/signatures.example.yaml" "$CONFIG_DIR/signatures.yaml"
fi
if grep -q '^  country: ""$' "$CONFIG_DIR/detector.yaml"; then
  sed -i "s#^  country: \"\"$#  country: $AP_COUNTRY#" "$CONFIG_DIR/detector.yaml"
fi
chown root:"$SERVICE_USER" "$CONFIG_DIR/detector.yaml" "$CONFIG_DIR/signatures.yaml"
chmod 0660 "$CONFIG_DIR/detector.yaml"

python3 -m venv "$PREFIX/venv.new"
"$PREFIX/venv.new/bin/pip" install --upgrade pip
"$PREFIX/venv.new/bin/pip" install "$ROOT_DIR"
ln -sfn venv.new "$PREFIX/active.new"
mv -Tf "$PREFIX/active.new" "$PREFIX/active"
if [[ ! -e "$STATE_DIR/web/ui-password.hash" ]]; then
  "$PREFIX/active/bin/python" "$ROOT_DIR/scripts/initialize_ui_password.py" "$STATE_DIR/web/ui-password.hash"
  chown bt-web:bt-detector "$STATE_DIR/web/ui-password.hash"
fi
install -m 0644 "$ROOT_DIR/systemd/bt-signature-detector.service" /etc/systemd/system/bt-signature-detector.service
install -m 0644 "$ROOT_DIR/systemd/bt-signature-detector-bluetooth.service" /etc/systemd/system/bt-signature-detector-bluetooth.service
install -m 0644 "$ROOT_DIR/systemd/bt-signature-detector-dhcp.service" /etc/systemd/system/bt-signature-detector-dhcp.service
install -m 0644 "$ROOT_DIR/systemd/bt-signature-detector-ap.service" /etc/systemd/system/bt-signature-detector-ap.service
install -m 0644 "$ROOT_DIR/systemd/bt-signature-detector-updater@.service" /etc/systemd/system/bt-signature-detector-updater@.service
install -m 0755 "$ROOT_DIR/scripts/apply_update_helper.sh" /usr/local/sbin/bt-detector-apply-update
install -m 0755 "$ROOT_DIR/scripts/restart_detector_helper.sh" /usr/local/sbin/bt-detector-restart-scanner
install -m 0440 "$ROOT_DIR/systemd/bt-signature-detector-ap-helper.sudoers" /etc/sudoers.d/bt-signature-detector-ap
visudo -cf /etc/sudoers.d/bt-signature-detector-ap >/dev/null
if ! nmcli -t -f NAME connection show | grep -Fxq BLE-Detector; then
  nmcli connection add type wifi ifname wlan0 con-name BLE-Detector autoconnect no ssid BLE-Detector \
    802-11-wireless.mode ap 802-11-wireless.band bg 802-11-wireless.channel 6 \
    802-11-wireless-security.key-mgmt wpa-psk 802-11-wireless-security.proto rsn \
    802-11-wireless-security.pairwise ccmp 802-11-wireless-security.group ccmp \
    802-11-wireless-security.pmf 1 \
    802-11-wireless-security.psk easypassword \
    ipv4.method manual ipv4.addresses 192.168.4.1/24 ipv4.never-default yes ipv6.method disabled
fi
nmcli connection modify BLE-Detector 802-11-wireless-security.pmf 1
if [[ ! -e /etc/bt-signature-detector/dnsmasq-ap.conf ]]; then
cat > /etc/bt-signature-detector/dnsmasq-ap.conf <<'EOF'
interface=wlan0
bind-interfaces
port=0
dhcp-range=192.168.4.20,192.168.4.200,255.255.255.0,12h
dhcp-option=option:router,192.168.4.1
EOF
fi
chmod 0640 /etc/bt-signature-detector/dnsmasq-ap.conf
chown root:bt-detector /etc/bt-signature-detector/dnsmasq-ap.conf
install -m 0644 "$ROOT_DIR/systemd/bt-signature-detector-web.service" /etc/systemd/system/bt-signature-detector-web.service
systemctl daemon-reload
systemctl enable --now bt-signature-detector-bluetooth.service
systemctl enable --now bt-signature-detector-ap.service
systemctl enable --now bt-signature-detector-dhcp.service
systemctl enable --now bt-signature-detector.service
systemctl enable --now bt-signature-detector-web.service
echo "Installed. Configure a device-specific passive bluetooth.or_patterns before expecting detections."
