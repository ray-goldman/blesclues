import tempfile
import unittest
import subprocess
from pathlib import Path

from bt_signature_detector.company_ids import CompanyIdentifierRegistry
from bt_signature_detector.web import WebServices, create_app


class DeviceBrowserWebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        registry_path = root / "companies.json"
        registry_path.write_text('{"source_url":"source","retrieved_at":"now","companies":{"0x004C":"Apple, Inc."}}', encoding="utf-8")
        self.calls = []
        self.browser_active = True
        self.services = WebServices(
            password_hash_file=root / "password.hash",
            session_key_file=root / "session.key",
            status=lambda: {"scanner": "active", "scanner_state": "error",
                            "scanner_error": "adapter unavailable", "scan_mode": "active",
                            "configured_scan_mode": "passive"},
            devices=lambda: [{"identifier": "aa:bb:cc:dd", "name": "Beacon", "rssi": -51,
                              "manufacturer_data": {"76": "AABB", "999": "CC"}}],
            browser_mode=lambda: self.browser_active,
            set_browser_mode=lambda active: self.calls.append(active) or setattr(self, "browser_active", active) or active,
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
        self.assertEqual(status["scan_mode"], "active")
        self.assertTrue(status["browser_active"])
        self.assertEqual(status["scanner_state"], "error")
        self.assertEqual(status["scanner_error"], "adapter unavailable")
        rows = self.client.get("/api/devices").json["devices"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["identifier"], "aa:bb:cc:dd")
        self.assertEqual(rows[0]["manufacturer_names"], {"76": "Apple, Inc."})
        self.assertEqual(rows[0]["manufacturer_data"]["999"], "CC")
        self.assertNotIn("999", rows[0]["manufacturer_names"])

    def test_mode_changes_require_csrf_and_call_only_boolean_callback(self):
        self.login()
        self.assertEqual(self.client.post("/api/devices/start").status_code, 403)
        headers = {"X-CSRF-Token": self.csrf()}
        self.assertEqual(self.client.post("/api/devices/start", headers=headers).json["browser_active"], True)
        self.assertEqual(self.client.post("/api/devices/stop", headers=headers).json["browser_active"], False)
        self.assertEqual(self.calls, [True, False])

    def test_helper_failure_returns_service_unavailable(self):
        self.login()
        self.services.set_browser_mode = lambda active: (_ for _ in ()).throw(OSError("systemctl failed"))
        response = self.client.post("/api/devices/start", headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 503)
        self.assertIn("systemctl failed", response.json["error"])

    def test_helper_exit_status_stderr_is_bounded_sanitized_and_redacted(self):
        self.login()
        diagnostic = "\x1b[31mhelper failed\x1b[0m passphrase=private-value " + ("x" * 700)
        self.services.set_browser_mode = lambda active: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, ["helper"], stderr=diagnostic))
        response = self.client.post("/api/devices/start", headers={"X-CSRF-Token": self.csrf()})
        error = response.json["error"]
        self.assertEqual(response.status_code, 503)
        self.assertIn("status 1", error)
        self.assertIn("helper failed", error)
        self.assertIn("passphrase=[redacted]", error)
        self.assertNotIn("private-value", error)
        self.assertNotIn("\x1b", error)
        self.assertLessEqual(len(error.split(": ", 1)[1]), 500)

    def test_timeout_and_sudo_denial_have_actionable_messages(self):
        self.login()
        headers = {"X-CSRF-Token": self.csrf()}
        self.services.set_browser_mode = lambda active: (_ for _ in ()).throw(subprocess.TimeoutExpired("sudo", 40))
        timeout = self.client.post("/api/devices/start", headers=headers)
        self.assertIn("timed out", timeout.json["error"])
        self.services.set_browser_mode = lambda active: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, ["sudo"], stderr="sudo: a password is required"))
        denied = self.client.post("/api/devices/start", headers=headers)
        self.assertIn("status 1", denied.json["error"])
        self.assertIn("password is required", denied.json["error"])

    def test_devices_page_is_separate_and_explains_active_scan(self):
        self.login()
        response = self.client.get("/devices")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Devices", response.data)
        self.assertIn(b"scan requests", response.data)
        self.assertIn(b"does not connect to or pair", response.data)
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
        self.assertIn(b"device-action-error", response.data)
        self.assertIn(b"setInterval(loadDevices, 2000)", script)
        self.assertIn(b"dismiss-device-error", script)

    def test_devices_page_has_pause_resume_and_small_screen_layout_hooks(self):
        self.login()
        page = self.client.get("/devices").data
        script_response = self.client.get("/static/devices.js")
        script = script_response.data
        script_response.close()
        css_response = self.client.get("/static/style.css")
        css = css_response.data
        css_response.close()
        self.assertIn(b'id="pause-browser"', page)
        self.assertIn(b"Resume scan", script)
        self.assertIn(b"pausedInventory", script)
        self.assertIn(b"data-label=", script)
        self.assertIn(b'class="empty-row"', script)
        self.assertIn(b"@media (max-width: 1260px)", css)
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
