#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile

import yaml

from bt_signature_detector.config import validate_config_data


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: migrate_hidden_ap_config.py CONFIG COUNTRY", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    country = sys.argv[2].upper()
    if len(country) != 2 or not country.isalpha():
        print("Country must be a two-letter code", file=sys.stderr)
        return 2

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        print("Configuration root must be a mapping", file=sys.stderr)
        return 2
    ap = data.setdefault("access_point", {})
    if not isinstance(ap, dict):
        print("access_point must be a mapping", file=sys.stderr)
        return 2
    legacy_profile = ap.get("profile_name") == "BLE-Detector" or ap.get("ssid") == "BLE-Detector"
    ap.update({
        "ssid": "Detector-Admin",
        "hidden": True,
        "country": country,
        "profile_name": "Detector-Admin",
    })
    ap.setdefault("passphrase", "easypassword")
    if legacy_profile:
        ap["enabled"] = False
        ap["passphrase"] = "easypassword"
    else:
        ap.setdefault("enabled", False)
    validate_config_data(data)

    stat = path.stat()
    mode = stat.st_mode & 0o777
    fd, temp_name = tempfile.mkstemp(prefix=".detector-migrate-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            yaml.safe_dump(data, output, sort_keys=False, allow_unicode=True)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_name, mode)
        try:
            os.chown(temp_name, stat.st_uid, stat.st_gid)
        except (AttributeError, OSError, NotImplementedError):
            pass
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
