import json
import importlib
import unittest


SIGNATURES = json.dumps({
    "scoring": {"alert_threshold": 40, "correlation_window_sec": 60, "correlation_bonus": 20},
    "signatures": [
        {"id": "axon_ble_oui", "vendor": "Axon", "protocol": "ble", "match": {"mac_prefix": "00:25:DF"}, "score": 50},
        {"id": "axon_ble_name", "vendor": "Axon", "protocol": "ble", "match": {"name_regex": "(?i)taser international"}, "score": 40},
        {"id": "cp_one", "vendor": "CradlePoint", "protocol": "wifi", "match": {"bssid_prefix": "00:30:44"}, "score": 25},
        {"id": "cp_two", "vendor": "CradlePoint", "protocol": "wifi", "match": {"bssid_prefix": "00:E0:1C"}, "score": 25},
        {"id": "flock_oui", "vendor": "Flock Safety", "protocol": "wifi", "match": {"mac_prefix": "B4:1E:52"}, "score": 40},
        {"id": "flock_ssid", "vendor": "Flock Safety", "protocol": "wifi", "match": {"ssid_regex": "(?i)^flock camera net\\."}, "score": 40},
        {"id": "flock_legacy", "vendor": "Flock Safety", "protocol": "wifi", "match": {"ssid_regex": "(?i)^flock-[0-9a-f]{6}$"}, "score": 40},
        {"id": "flock_ble", "vendor": "Flock Safety", "protocol": "ble", "match": {"name_regex": "(?i)^flock"}, "score": 20},
    ],
})
SSID_PATTERNS = """# pattern<TAB>vendor<TAB>confidence<TAB>notes
(?i)^flock camera net\\.\tFlock Safety\thigh\tLocally administered MAC is common
(?i)^flock-[0-9a-f]{6}$\tFlock Safety\thigh\tLegacy form
(?i)^penguin\tFlock Safety\tlow\tGeneric name; verify
(?i)^pigvision\tFlock Safety\tmedium\tPattern source note
(?i)^(IBR|COR|R)\\d{3,4}-\tCradlepoint\tlow\tUnverified model pattern
"""
BLE_NAMES = """# pattern<TAB>vendor<TAB>confidence<TAB>notes
(?i)taser international\tAxon\thigh\tPair with BLE OUI
(?i)^axon\tAxon\tmedium\tUnverified prefix
(?i)^flock\tFlock Safety\tmedium\tBeaconing may be unreliable
(?i)^FS_\tFlock Safety\tlow\tShort prefix
"""
OUIS = """oui,vendor,protocol,device_class,confidence,speed_trap_relevance,notes,source
00:25:DF,Taser International (Axon),ble,body_cam|holster_sensor|signal_unit,high,high,Private security also uses this OUI,source-a
00:30:44,CradlePoint Inc,wifi,in_vehicle_lte_router,medium,medium,False positives on fleets,source-b
00:E0:1C,CradlePoint Inc,wifi,in_vehicle_lte_router,medium,medium,False positives on fleets,source-c
B4:1E:52,Flock Safety,wifi,alpr_camera,high,low,Fixed camera indicator,source-d
"""


class BuiltInRuleTests(unittest.TestCase):
    def catalog_api(self):
        try:
            return importlib.import_module("bt_signature_detector.builtin_rules")
        except ModuleNotFoundError:
            self.fail("built-in rule catalog module is not implemented")

    def test_source_files_normalize_to_thirteen_rules_and_merge_duplicates(self):
        rules = self.catalog_api().parse_source_catalog(SIGNATURES, SSID_PATTERNS, BLE_NAMES, OUIS)

        self.assertEqual(len(rules), 13)
        flock_ble = next(rule for rule in rules if rule.rule_id == "flock_ble")
        self.assertEqual(flock_ble.score, 20)  # Explicit signature score wins confidence fallback.
        self.assertEqual(flock_ble.confidence, "medium")
        flock_ssid = next(rule for rule in rules if rule.match_type == "ssid_regex" and "camera net" in rule.pattern)
        self.assertEqual(flock_ssid.score, 40)
        axon_oui = next(rule for rule in rules if rule.match_type == "mac_prefix" and rule.pattern == "00:25:DF")
        self.assertEqual(axon_oui.score, 50)
        self.assertIn("source-a", axon_oui.source)
        self.assertIn("Private security", axon_oui.notes)
        self.assertEqual(axon_oui.device_class, ("body_cam", "holster_sensor", "signal_unit"))

    def test_confidence_mapping_and_source_metadata_are_preserved(self):
        rules = self.catalog_api().parse_source_catalog(SIGNATURES, SSID_PATTERNS, BLE_NAMES, OUIS)
        by_pattern = {rule.pattern: rule for rule in rules}

        self.assertEqual(by_pattern["(?i)^penguin"].score, 10)
        self.assertEqual(by_pattern["(?i)^pigvision"].score, 25)
        self.assertEqual(by_pattern["(?i)^axon"].score, 25)
        self.assertIn("Unverified", by_pattern["(?i)^axon"].notes)
        self.assertEqual(by_pattern["(?i)^pigvision"].vendor, "Flock Safety")

    def test_source_scoring_settings_are_preserved(self):
        catalog = self.catalog_api()
        settings = catalog.parse_scoring_settings(SIGNATURES)

        self.assertEqual(settings.alert_threshold, 40)
        self.assertEqual(settings.correlation_bonus, 20)
        self.assertEqual(settings.correlation_window_seconds, 60)

    def test_invalid_regex_and_oui_are_rejected(self):
        bad_regex = SIGNATURES.replace("(?i)^flock", "(?i)[")
        with self.assertRaisesRegex(ValueError, "regex"):
            self.catalog_api().parse_source_catalog(bad_regex, SSID_PATTERNS, BLE_NAMES, OUIS)

        bad_oui = OUIS.replace("00:25:DF", "00:25:GG")
        with self.assertRaisesRegex(ValueError, "OUI"):
            self.catalog_api().parse_source_catalog(SIGNATURES, SSID_PATTERNS, BLE_NAMES, bad_oui)

    def test_packaged_catalog_loads_thirteen_valid_rules(self):
        catalog = self.catalog_api()
        rules = catalog.load_builtin_rules()

        self.assertEqual(len(rules), 13)
        self.assertTrue(all(isinstance(rule, catalog.BuiltInRule) for rule in rules))
        self.assertEqual({rule.protocol for rule in rules}, {"ble", "wifi"})


if __name__ == "__main__":
    unittest.main()
