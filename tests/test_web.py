import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from bt_signature_detector.web import WebServices, _serve_dashboard, create_app
from bt_signature_detector.models import Confidence, DetectionEvent
from datetime import datetime, timezone


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app(WebServices(password_hash_file=self.root / "password.hash",
            session_key_file=self.root / "session.key", status=lambda: {"scanner": "running"},
            scans=lambda: [{"name": "beacon", "identifier": "aa:bb:cc:dd"}], events=lambda limit: [],
            wifi_status=lambda: {"mode": "scan", "scan_active": True, "admin_ap_active": False},
            wifi_observations=lambda: [{"ssid": "Camera", "bssid": "00:30:44:11:22:33"}]))
        self.client = self.app.test_client()

    def csrf(self):
        with self.client.session_transaction() as session: return session["csrf_token"]

    def test_dashboard_binds_to_ethernet_and_optional_access_point_addresses(self):
        app = object()
        sockets = [Mock(), Mock()]
        with patch("bt_signature_detector.web._dashboard_socket", side_effect=sockets) as open_socket, \
                patch("waitress.serve") as serve:
            _serve_dashboard(app, 8080, ["192.168.0.201", "192.168.4.1"])
        self.assertEqual(open_socket.call_args_list, [
            unittest.mock.call("192.168.0.201", 8080),
            unittest.mock.call("192.168.4.1", 8080),
        ])
        serve.assert_called_once_with(app, sockets=sockets)

    def login(self):
        self.client.post("/setup", data={"password": "a-good-password"})
        with self.client.session_transaction() as session: session.clear()
        self.client.post("/login", data={"password": "a-good-password"})

    def test_first_run_setup_login_logout_and_password_api(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/api/status").status_code, 401)
        self.assertEqual(self.client.post("/setup", data={"password": "short"}).status_code, 400)
        self.assertEqual(self.client.post("/setup", data={"password": "a-good-password"}).status_code, 200)
        with self.client.session_transaction() as session: session.clear()
        self.assertEqual(self.client.post("/login", data={"password": "wrong-password"}).status_code, 401)
        self.assertEqual(self.client.post("/login", data={"password": "a-good-password"}).status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.post("/logout", headers={"X-CSRF-Token": self.csrf()}).status_code, 200)

    def test_api_requires_login_csrf_and_redacts_bounded_scans(self):
        self.assertEqual(self.client.get("/api/scans").status_code, 401)
        self.assertEqual(self.client.get("/api/wifi/status").status_code, 401)
        self.assertEqual(self.client.get("/api/wifi/observations").status_code, 401)
        self.assertEqual(self.client.get("/api/detections/rules").status_code, 401)
        self.login()
        self.assertEqual(self.client.get("/api/status").json["scanner"], "running")
        scans = self.client.get("/api/scans").json["scans"]
        self.assertEqual(scans[0]["identifier"], "redacted")
        self.assertEqual(self.client.post("/api/settings", json={"ssid": "fake"}).status_code, 403)
        self.assertEqual(self.client.post("/logout").status_code, 403)

    def test_wifi_status_and_live_observations_are_authenticated_and_bounded(self):
        self.login()
        status = self.client.get("/api/wifi/status")
        observations = self.client.get("/api/wifi/observations")
        self.assertEqual(status.json["mode"], "scan")
        self.assertTrue(status.json["scan_active"])
        self.assertEqual(observations.json["observations"][0]["ssid"], "Camera")
        catalog = self.client.get("/api/detections/rules").json
        self.assertEqual(len(catalog["rules"]), 13)
        self.assertEqual(catalog["scoring"]["alert_threshold"], 40)

    def test_scored_wifi_event_metadata_is_available_in_event_history(self):
        stamp = datetime.now(timezone.utc)
        event = DetectionEvent("builtin:flock", "Flock Safety", Confidence.POSSIBLE, "00:11:22:33:44:55",
            stamp, stamp, -50, 1, protocol="wifi", vendor="Flock Safety", base_score=25,
            correlation_bonus=20, effective_score=45, source_note="SSID rule", observed_ssid="camera-net")
        self.app.extensions["web_services"].events = lambda limit: [event]
        self.login()
        row = self.client.get("/api/events").json["events"][0]
        self.assertEqual((row["protocol"], row["base_score"], row["effective_score"]), ("wifi", 25, 45))
        self.assertEqual(row["observed_ssid"], "camera-net")

    def test_dashboard_static_assets_are_served(self):
        response = self.client.get("/static/style.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"--blue", response.data)
        response.close()

    def test_update_routes_require_auth_csrf_and_explicit_apply(self):
        class Updates:
            def status(self): return {"staged": []}
            def check(self): return {"version": "1.2.3"}
            def upload(self, stream): return {"id": "abc"}
            def stage_download(self): return {"id": "abc"}
            def apply(self, staged_id): return {"success": True, "id": staged_id}
        self.app.extensions["web_services"].update_manager = Updates()
        self.assertEqual(self.client.get("/api/updates/status").status_code, 401)
        self.login()
        self.assertEqual(self.client.post("/api/updates/check").status_code, 403)
        headers = {"X-CSRF-Token": self.csrf()}
        self.assertEqual(self.client.post("/api/updates/check", headers=headers).json["version"], "1.2.3")
        self.assertEqual(self.client.post("/api/updates/apply", json={"id":"abc", "confirm":False}, headers=headers).status_code, 400)
        self.assertEqual(self.client.post("/api/updates/apply", json={"id":"abc", "confirm":True}, headers=headers).json["success"], True)


if __name__ == "__main__": unittest.main()
