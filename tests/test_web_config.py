import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from bt_signature_detector.web import WebServices, create_app


class WebConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        project = Path(__file__).resolve().parents[1]
        self.config = root / "detector.yaml"
        self.config.write_text((project / "config" / "detector.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        self.restart_calls = []
        self.ap_calls = []
        self.mode_calls = []
        self.fail_mode = False
        self.update_manager = SimpleNamespace(manifest_url=None)
        def set_mode(mode):
            self.mode_calls.append(mode)
            if self.fail_mode: raise RuntimeError("radio transition failed")
        app = create_app(WebServices(root / "password", root / "session", config_file=self.config,
            ap_update=lambda changes: self.ap_calls.append(changes),
            set_wifi_mode=set_mode,
            restart_scanner=lambda: self.restart_calls.append(True), update_manager=self.update_manager))
        self.app = app
        self.client = app.test_client()
        self.client.post("/setup", data={"password": "long-enough-ui-password"})

    def csrf(self):
        with self.client.session_transaction() as session: return session["csrf_token"]

    def test_invalid_update_is_atomic(self):
        original = self.config.read_bytes()
        response = self.client.post("/api/settings", json={"cooldown_seconds": 999999}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.config.read_bytes(), original)

    def test_hidden_wifi_can_be_enabled_and_credentials_are_not_returned(self):
        response = self.client.post("/api/settings", json={"access_point_enabled": True, "ssid": "Field Admin", "passphrase": "new-secure-pass"},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.ap_calls, [{"ssid": "Field Admin", "passphrase": "new-secure-pass"}])
        self.assertEqual(self.mode_calls, ["admin_ap"])
        settings = self.client.get("/api/settings").json
        self.assertTrue(settings["access_point_enabled"])
        self.assertEqual(settings["ssid"], "Field Admin")
        self.assertNotIn("passphrase", settings)

    def test_wifi_scan_mode_disables_admin_ap_in_one_transaction(self):
        response = self.client.post("/api/settings", json={"wifi_scanning_enabled": True},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        settings = self.client.get("/api/settings").json
        self.assertTrue(settings["wifi_scanning_enabled"])
        self.assertFalse(settings["access_point_enabled"])
        self.assertEqual(self.mode_calls, ["scan"])

    def test_mode_start_failure_restores_configuration(self):
        original = self.config.read_bytes()
        self.fail_mode = True
        response = self.client.post("/api/settings", json={"wifi_scanning_enabled": True},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.config.read_bytes(), original)

    def test_failed_wifi_mode_transition_persists_idle_for_boot_reconciliation(self):
        import yaml
        config = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        config["access_point"]["enabled"] = True
        self.config.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        self.fail_mode = True
        response = self.client.post("/api/settings", json={"wifi_scanning_enabled": True},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 400)
        restored = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        self.assertFalse(restored["access_point"]["enabled"])
        self.assertFalse(restored["wifi_scanning"]["enabled"])

    def test_opposite_wifi_settings_updates_are_serialized_with_radio_transition(self):
        entered_first = threading.Event()
        release_first = threading.Event()
        observed = []
        services = self.app.extensions["web_services"]
        def set_mode(mode):
            import yaml
            saved = yaml.safe_load(self.config.read_text(encoding="utf-8"))
            observed.append((mode, saved["wifi_scanning"]["enabled"], saved["access_point"]["enabled"]))
            if len(observed) == 1:
                entered_first.set()
                self.assertTrue(release_first.wait(2))
        services.set_wifi_mode = set_mode
        clients = [self.app.test_client(), self.app.test_client()]
        headers = []
        for client in clients:
            client.post("/login", data={"password": "long-enough-ui-password"})
            with client.session_transaction() as session:
                headers.append({"X-CSRF-Token": session["csrf_token"]})
        responses = []
        first = threading.Thread(target=lambda: responses.append(clients[0].post(
            "/api/settings", json={"wifi_scanning_enabled": True}, headers=headers[0])))
        second = threading.Thread(target=lambda: responses.append(clients[1].post(
            "/api/settings", json={"access_point_enabled": True}, headers=headers[1])))
        first.start()
        self.assertTrue(entered_first.wait(2))
        second.start()
        time.sleep(0.05)
        self.assertEqual(len(observed), 1)
        release_first.set()
        first.join(2)
        second.join(2)
        self.assertEqual(len(responses), 2)
        self.assertEqual(observed, [("scan", True, False), ("admin_ap", False, True)])
        import yaml
        saved = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        self.assertEqual((saved["wifi_scanning"]["enabled"], saved["access_point"]["enabled"]), (False, True))

    def test_detection_changes_restart_scanner(self):
        response = self.client.post("/api/settings", json={"cooldown_seconds": 600},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.restart_calls, [True])

    def test_bluez_filter_patterns_are_exposed_and_saved_with_scanner_restart(self):
        settings = self.client.get("/api/settings").json
        self.assertEqual(settings["or_patterns"], [
            {"start_position": 0, "ad_data_type": 255, "pattern": "010203"},
        ])
        response = self.client.post("/api/settings", json={"or_patterns": [
            {"start_position": 0, "ad_data_type": 255, "pattern": "010203"},
            {"start_position": 2, "ad_data_type": 255, "pattern": "A1B2"},
        ]}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.restart_calls, [True])
        saved = self.client.get("/api/settings").json["or_patterns"]
        self.assertEqual(saved[-1], {"start_position": 2, "ad_data_type": 255, "pattern": "a1b2"})

    def test_invalid_bluez_filter_pattern_is_rejected_without_config_change(self):
        original = self.config.read_bytes()
        response = self.client.post("/api/settings", json={"or_patterns": [
            {"start_position": 0, "ad_data_type": 255, "pattern": "not-hex"},
        ]}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(self.restart_calls, [])

    def test_release_feed_url_is_https_validated_and_updated_live(self):
        response = self.client.post("/api/settings", json={"manifest_url": "https://updates.example.org/stable.json"},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.update_manager.manifest_url, "https://updates.example.org/stable.json")
        original = self.config.read_bytes()
        bad = self.client.post("/api/settings", json={"manifest_url": "http://updates.example.org/stable.json"},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(self.config.read_bytes(), original)


if __name__ == "__main__": unittest.main()
