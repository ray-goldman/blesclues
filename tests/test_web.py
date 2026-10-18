import tempfile
import unittest
from pathlib import Path

from bt_signature_detector.web import WebServices, create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app(WebServices(password_hash_file=self.root / "password.hash",
            session_key_file=self.root / "session.key", status=lambda: {"scanner": "running"},
            scans=lambda: [{"name": "beacon", "identifier": "aa:bb:cc:dd"}], events=lambda limit: []))
        self.client = self.app.test_client()

    def csrf(self):
        with self.client.session_transaction() as session: return session["csrf_token"]

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
        self.login()
        self.assertEqual(self.client.get("/api/status").json["scanner"], "running")
        scans = self.client.get("/api/scans").json["scans"]
        self.assertEqual(scans[0]["identifier"], "redacted")
        self.assertEqual(self.client.post("/api/settings", json={"ssid": "fake"}).status_code, 403)
        self.assertEqual(self.client.post("/logout").status_code, 403)

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
