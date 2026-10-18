#!/bin/sh
set -eu
if [ "$#" -ne 0 ]; then echo "arguments are not accepted" >&2; exit 2; fi
exec /usr/bin/systemctl restart bt-signature-detector.service
