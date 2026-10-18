import tempfile
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
        self.ap_calls = []
        self.restart_calls = []
        self.update_manager = SimpleNamespace(manifest_url=None)
        app = create_app(WebServices(root / "password", root / "session", config_file=self.config,
            ap_update=lambda changes: self.ap_calls.append(changes),
            restart_scanner=lambda: self.restart_calls.append(True), update_manager=self.update_manager))
        self.client = app.test_client()
        self.client.post("/setup", data={"password": "long-enough-ui-password"})

    def csrf(self):
        with self.client.session_transaction() as session: return session["csrf_token"]

    def test_invalid_update_is_atomic(self):
        original = self.config.read_bytes()
        response = self.client.post("/api/settings", json={"cooldown_seconds": 999999}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.config.read_bytes(), original)

    def test_allowed_updates_call_ap_helper_and_never_return_secret(self):
        response = self.client.post("/api/settings", json={"ssid": "New detector", "passphrase": "new-secure-pass"},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.ap_calls, [{"ssid": "New detector", "passphrase": "new-secure-pass"}])
        settings = self.client.get("/api/settings").json
        self.assertEqual(settings["ssid"], "New detector")
        self.assertNotIn("passphrase", settings)

    def test_detection_changes_restart_scanner(self):
        response = self.client.post("/api/settings", json={"cooldown_seconds": 600},
            headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.restart_calls, [True])

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
