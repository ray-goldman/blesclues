#!/bin/sh
set -eu
if [ "$#" -ne 0 ]; then echo "arguments are not accepted" >&2; exit 2; fi
IFS= read -r staged_id || { echo "staged update id is required" >&2; exit 2; }
if IFS= read -r extra; then echo "only one update id is accepted" >&2; exit 2; fi
case "$staged_id" in *[!0-9a-f]*|'') echo "invalid update id" >&2; exit 2;; esac
[ "${#staged_id}" -eq 32 ] || { echo "invalid update id" >&2; exit 2; }
exec /usr/bin/systemctl start "bt-signature-detector-updater@${staged_id}.service"
