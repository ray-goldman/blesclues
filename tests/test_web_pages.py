import tempfile
import unittest
from pathlib import Path

from bt_signature_detector.web import WebServices, create_app


class WatchPageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = create_app(WebServices(root / "password.hash", root / "session.key",
            scans=lambda: [{"identifier": "aa:bb:cc:dd", "name": "Beacon"}]))
        self.client = self.app.test_client()

    def test_navigation_and_new_pages_require_authentication(self):
        self.assertEqual(self.client.get("/live").status_code, 302)
        self.assertEqual(self.client.get("/watchlists").status_code, 302)
        self.client.post("/setup", data={"password": "a-good-password"})
        for path in ("/", "/live", "/devices", "/watchlists", "/settings", "/updates"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            for label in (b"Monitor", b"Live Feed", b"Devices", b"Watch Lists", b"Settings", b"Updates"):
                self.assertIn(label, response.data, (path, label))
            self.assertIn(b"Build Alpha 4", response.data, path)

    def test_live_page_uses_redacted_scans_and_is_separate_from_monitor(self):
        self.client.post("/setup", data={"password": "a-good-password"})
        page = self.client.get("/live")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"/static/live.js", page.data)
        self.assertIn(b"temporary memory", page.data)
        self.assertIn(b"Nearby networks", page.data)
        self.assertNotIn(b"aa:bb:cc:dd", page.data)
        self.assertEqual(self.client.get("/api/scans").json["scans"][0]["identifier"], "redacted")
        live_script = self.client.get("/static/live.js")
        self.assertIn(b"/api/scans", live_script.data)
        self.assertIn(b"/api/wifi/observations", live_script.data)
        live_script.close()
        monitor = self.client.get("/")
        self.assertNotIn(b'id="scans"', monitor.data)
        monitor_script = self.client.get("/static/app.js")
        self.assertNotIn(b"/api/scans", monitor_script.data)
        monitor_script.close()

    def test_settings_explains_exclusive_radio_modes_and_exposes_scan_control(self):
        self.client.post("/setup", data={"password": "a-good-password"})
        page = self.client.get("/settings")
        self.assertIn(b"exclusive modes", page.data)
        self.assertIn(b"wifi_scanning_enabled", page.data)
        asset = self.client.get("/static/settings.js")
        self.assertIn(b"wifi_scanning_enabled", asset.data)
        self.assertIn(b"/api/detections/rules", asset.data)
        asset.close()
        self.assertIn(b"raw advertisement bytes", page.data)
        self.assertIn(b"can hide matching devices", page.data)

    def test_watchlists_page_has_empty_state_and_api_contract_script(self):
        self.client.post("/setup", data={"password": "a-good-password"})
        page = self.client.get("/watchlists")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"/static/watchlists.js", page.data)
        asset_response = self.client.get("/static/watchlists.js")
        asset = asset_response.data
        asset_response.close()
        self.assertIn(b"No watch lists yet", page.data)
        for text in (b"Browser scan only", b"Partial", b"Disabled", b"X-CSRF-Token"):
            self.assertIn(text, asset)


if __name__ == "__main__":
    unittest.main()
