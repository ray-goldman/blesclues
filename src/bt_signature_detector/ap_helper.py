from __future__ import annotations

import argparse
import json
import os
import sys

from .access_point import AccessPointClient


def main(argv=None):
    if os.geteuid() != 0:
        print("AP helper must run as root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    read = sub.add_parser("status")
    update = sub.add_parser("update")
    group = update.add_mutually_exclusive_group(required=True)
    group.add_argument("--changes")
    group.add_argument("--changes-stdin", action="store_true")
    activate = sub.add_parser("activate")
    activate.add_argument("--config", required=True)
    sub.add_parser("deactivate")
    args = parser.parse_args(argv)
    client = AccessPointClient()
    if args.action == "deactivate":
        try:
            client.deactivate()
            return 0
        except (OSError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    if args.action == "activate":
        from .config import load_app_config
        try:
            access_point = load_app_config(__import__("pathlib").Path(args.config)).access_point
            client.activate(access_point.country, enabled=access_point.enabled)
            return 0
        except (ValueError, OSError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    if args.action == "status":
        status = client.read()
        print(json.dumps({"active": status.active, "ssid": status.ssid, "interface": status.interface, "error": status.error}))
        return 0 if status.error is None else 1
    try:
        changes = json.loads(sys.stdin.read() if args.changes_stdin else args.changes)
        client.update(AccessPointClient.PROFILE, changes)
        print('{"ok":true}')
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__": raise SystemExit(main())
