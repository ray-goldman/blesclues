#!/usr/bin/env sh
set -eu
exec /opt/bt-signature-detector/active/bin/python -m bt_signature_detector.device_browser "$@"
