import unittest
from datetime import datetime, timezone

from bt_signature_detector.builtin_rules import BuiltInRule
from bt_signature_detector.wifi_scanner import WifiObservation, match_wifi_rules, parse_iw_scan, scan_wifi


class WifiScannerTests(unittest.TestCase):
    def test_iw_parser_handles_colons_signal_and_channels(self):
        result = parse_iw_scan("""BSS 00:30:44:12:34:56(on wlan0)
\tfreq: 2437
\tsignal: -45.00 dBm
\tSSID: Camera West
\tRSN:
BSS 02:AA:BB:CC:DD:EE(on wlan0)
\tfreq: 2462
\tsignal: -55.00 dBm
\tSSID: Guest
\tWPA:
""")
        self.assertEqual(len(result), 2)
        self.assertEqual((result[0].ssid, result[0].bssid, result[0].signal, result[0].channel), ("Camera West", "00:30:44:12:34:56", -45, 6))

    def test_scan_invokes_networkmanager_without_association(self):
        class Runner:
            def __init__(self): self.command = None
            def __call__(self, command, **kwargs):
                self.command = command
                return type("Result", (), {"returncode": 0, "stdout": "BSS 00:30:44:12:34:56(on wlan0)\n\\tfreq: 2437\n\\tsignal: -60.00 dBm\n\\tSSID: Guest", "stderr": ""})()
        runner = Runner()
        found = scan_wifi(runner=runner)
        self.assertEqual(len(found), 1)
        self.assertEqual(runner.command, ["iw", "dev", "wlan0", "scan"])

    def test_wifi_matching_includes_ssid_for_local_admin_bssid_but_skips_oui(self):
        rules = (
            BuiltInRule("oui", "wifi", "Router", "bssid_prefix", "00:30:44", "medium", 25, "fixture", ""),
            BuiltInRule("ssid", "wifi", "Camera", "ssid_regex", "(?i)^camera", "high", 40, "fixture", ""),
        )
        local = WifiObservation("Camera van", "02:30:44:00:00:01", None, None, None, datetime.now(timezone.utc))
        self.assertEqual([r.rule_id for r in match_wifi_rules(rules, local)], ["ssid"])
        global_bssid = WifiObservation("Guest", "00:30:44:00:00:01", None, None, None, datetime.now(timezone.utc))
        self.assertEqual([r.rule_id for r in match_wifi_rules(rules, global_bssid)], ["oui"])

    def test_bad_command_output_fails_and_hidden_ssids_do_not_match(self):
        with self.assertRaisesRegex(ValueError, "scan output"):
            parse_iw_scan("not-an-iw-scan")
        rule = BuiltInRule("ssid", "wifi", "Camera", "ssid_regex", "(?i)^camera", "high", 40, "fixture", "")
        hidden = WifiObservation("", "00:30:44:00:00:01", None, None, None, datetime.now(timezone.utc))
        self.assertEqual(match_wifi_rules((rule,), hidden), ())


if __name__ == "__main__":
    unittest.main()
