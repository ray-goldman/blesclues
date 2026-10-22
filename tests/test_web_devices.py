import tempfile
import unittest
from pathlib import Path

from bt_signature_detector.company_ids import CompanyIdentifierRegistry
from bt_signature_detector.web import WebServices, create_app


class DevicePageWebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        registry_path = root / "companies.json"
        registry_path.write_text('{"source_url":"source","retrieved_at":"now","companies":{"0x004C":"Apple, Inc."}}', encoding="utf-8")
        self.services = WebServices(
            password_hash_file=root / "password.hash",
            session_key_file=root / "session.key",
            status=lambda: {"scanner": "active", "scanner_state": "error",
                            "scanner_error": "adapter unavailable", "scan_mode": "active",
                            "configured_scan_mode": "passive"},
            devices=lambda: [{"identifier": "aa:bb:cc:dd", "name": "Beacon", "rssi": -51,
                              "manufacturer_data": {"76": "AABB", "999": "CC"}}],
            max_live_scans=1, company_identifiers=CompanyIdentifierRegistry.from_json(registry_path))
        self.app = create_app(self.services)
        self.client = self.app.test_client()

    def login(self):
        self.client.post("/setup", data={"password": "a-good-password"})

    def csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_devices_status_and_inventory_require_authentication(self):
        self.assertEqual(self.client.get("/api/devices/status").status_code, 401)
        self.assertEqual(self.client.get("/api/devices").status_code, 401)
        self.login()
        status = self.client.get("/api/devices/status").json
        self.assertEqual(status["configured_scan_mode"], "passive")
        self.assertEqual(status["scan_mode"], "passive")
        self.assertNotIn("browser_active", status)
        self.assertEqual(status["scanner_state"], "error")
        self.assertEqual(status["scanner_error"], "adapter unavailable")
        rows = self.client.get("/api/devices").json["devices"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identifier"], "aa:bb:cc:dd")
        self.assertEqual(rows[0]["manufacturer_names"], {"76": "Apple, Inc."})
        self.assertEqual(rows[0]["manufacturer_data"]["999"], "CC")
        self.assertNotIn("999", rows[0]["manufacturer_names"])

    def test_devices_endpoints_cannot_change_radio_mode(self):
        self.login()
        headers = {"X-CSRF-Token": self.csrf()}
        self.assertEqual(self.client.post("/api/devices/start", headers=headers).status_code, 404)
        self.assertEqual(self.client.post("/api/devices/stop", headers=headers).status_code, 404)

    def test_devices_page_is_a_passive_live_view(self):
        self.login()
        response = self.client.get("/devices")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Devices", response.data)
        self.assertIn(b"Pause updates", response.data)
        self.assertIn(b"Resume updates", response.data)
        self.assertNotIn(b"Start device scan", response.data)
        self.assertNotIn(b"Stop scan", response.data)
        script_response = self.client.get("/static/devices.js")
        script = script_response.data
        script_response.close()
        self.assertIn(b"Watch this", script)
        self.assertIn(b"manufacturer_data", script)
        self.assertIn(b"service_uuids", script)
        self.assertIn(b"service_data", script)
        self.assertIn(b"observed_identifiers", script)
        self.assertIn(b"watch-prefix", script)
        self.assertIn(b"name_contains", script)
        self.assertIn(b"clearInterval(devicePollTimer)", script)
        self.assertIn(b"state.replaceChildren", script)
        self.assertNotIn(b"state.innerHTML = `<i></i>${failed", script)
        self.assertNotIn(b"/api/devices/start", script)
        self.assertNotIn(b"/api/devices/stop", script)

    def test_devices_page_has_pause_resume_and_small_screen_layout_hooks(self):
        self.login()
        page = self.client.get("/devices").data
        script_response = self.client.get("/static/devices.js")
        script = script_response.data
        script_response.close()
        css_response = self.client.get("/static/style.css")
        css = css_response.data
        css_response.close()
        self.assertIn(b'id="pause-updates"', page)
        self.assertIn(b'id="resume-updates"', page)
        self.assertIn(b"clearInterval(wifiPollTimer)", script)
        self.assertIn(b"pausedInventory", script)
        self.assertNotIn(b"setBrowserMode", script)
        self.assertIn(b"data-label=", script)
        self.assertIn(b'class="empty-row"', script)
        self.assertIn(b"@media (max-width: 760px)", css)
        self.assertIn(b"device-table tr", css)

    def test_watch_dialog_offers_name_regex_address_prefix_and_company_id(self):
        self.login()
        response = self.client.get("/static/devices.js")
        script = response.data
        response.close()
        self.assertIn(b"name_regex", script)
        self.assertIn(b"identifier_prefixes", script)
        self.assertIn(b"manufacturer_ids", script)
        self.assertIn(b"MAC prefix", script)
        self.assertIn(b"SIG company ID", script)
        self.assertIn(b"Nested or ambiguous repeated groups are rejected", script)


if __name__ == "__main__":
    unittest.main()
