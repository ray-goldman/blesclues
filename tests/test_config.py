from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bt_signature_detector.config import load_app_config, validate_config_data


def valid_config() -> dict[str, object]:
    return {
        "schema_version": 1,
        "bluetooth": {
            "adapter": None,
            "scan_mode": "passive",
            "or_patterns": [{"start_position": 0, "ad_data_type": 1, "pattern": "06"}],
            "reconnect_initial_seconds": 1,
            "reconnect_max_seconds": 30,
        },
        "detection": {
            "global_min_rssi": -100,
            "cooldown_seconds": 300,
            "absence_seconds": 120,
            "min_observations": 3,
            "signature_file": "signatures.yaml",
        },
        "storage": {"path": "events.sqlite3", "retention_days": 30, "max_events": 10000},
        "logging": {"level": "INFO", "debug": False},
        "notifications": {"queue_size": 64, "timeout_seconds": 5},
        "access_point": {"enabled": False, "ssid": "Detector-Admin", "passphrase": "easypassword", "hidden": True},
        "web": {"enabled": True, "port": 8080, "password_hash_file": "ui-password.hash"},
        "updates": {"enabled": True, "manifest_url": None},
    }


class ConfigTests(unittest.TestCase):
    def test_valid_passive_config_loads_typed_defaults(self) -> None:
        config = validate_config_data(valid_config())
        self.assertEqual(config.bluetooth.scan_mode, "passive")
        self.assertEqual(config.detection.cooldown_seconds, 300)
        self.assertEqual(config.detection.min_observations, 3)
        self.assertFalse(config.access_point.enabled)
        self.assertEqual(config.access_point.ssid, "Detector-Admin")
        self.assertTrue(config.access_point.hidden)
        self.assertFalse(config.wifi_scanning.enabled)
        self.assertEqual(config.wifi_scanning.interval_seconds, 15)

    def test_wifi_scanning_and_admin_access_point_are_mutually_exclusive(self) -> None:
        data = valid_config()
        data["access_point"] = {"enabled": True}
        data["wifi_scanning"] = {"enabled": True}
        with self.assertRaisesRegex(ValueError, "cannot both be true"):
            validate_config_data(data)

    def test_passive_config_requires_or_patterns(self) -> None:
        data = valid_config()
        data["bluetooth"] = {"scan_mode": "passive", "or_patterns": []}
        with self.assertRaisesRegex(ValueError, "bluetooth.or_patterns"):
            validate_config_data(data)

    def test_passive_config_accepts_empty_manual_filters_when_signature_derives_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "signatures.yaml").write_text('''schema_version: 1
signatures:
  - id: watched
    label: Watched
    watchlist: List
    manufacturer_data: {"76": "01"}
''', encoding="utf-8")
            data = valid_config()
            data["bluetooth"] = {"scan_mode": "passive", "or_patterns": []}
            self.assertEqual(validate_config_data(data, base_dir=root).bluetooth.or_patterns, ())

    def test_empty_manual_filters_still_fail_without_compatible_enabled_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "signatures.yaml").write_text('''schema_version: 1
signatures:
  - id: address
    label: Address only
    watchlist: List
    observed_identifiers: ["aa"]
''', encoding="utf-8")
            data = valid_config()
            data["bluetooth"] = {"scan_mode": "passive", "or_patterns": []}
            with self.assertRaisesRegex(ValueError, "bluetooth.or_patterns"):
                validate_config_data(data, base_dir=root)

    def test_rejects_invalid_yaml_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "detector.yaml")
            path.write_text("schema_version: [", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "detector.yaml"):
                load_app_config(path)

        data = valid_config()
        data["bluetooth"] = {"scan_mode": "passive", "or_patterns": [{"start_position": 0, "ad_data_type": 1, "pattern": "06"}], "surprise": True}
        with self.assertRaisesRegex(ValueError, "bluetooth.surprise"):
            validate_config_data(data)

    def test_rejects_out_of_range_thresholds(self) -> None:
        data = valid_config()
        data["detection"] = {**valid_config()["detection"], "cooldown_seconds": -1}
        with self.assertRaisesRegex(ValueError, "cooldown_seconds"):
            validate_config_data(data)

    def test_release_feed_requires_valid_https_url(self) -> None:
        data = valid_config()
        data["updates"] = {"enabled": True, "manifest_url": "http://updates.example.org/feed.json"}
        with self.assertRaisesRegex(ValueError, "updates.manifest_url"):
            validate_config_data(data)


if __name__ == "__main__":
    unittest.main()
