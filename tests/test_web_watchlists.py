import tempfile
import unittest
from pathlib import Path
from threading import Event, Thread

from bt_signature_detector.watchlists import WatchListStore
from bt_signature_detector.company_ids import CompanyIdentifierRegistry
from bt_signature_detector.web import WebServices, create_app


class WatchListApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.signature_file = self.root / "signatures.yaml"
        self.signature_file.write_text('''schema_version: 1
signatures:
  - id: builtin
    label: Built in
    service_uuids: ["180d"]
''', encoding="utf-8")
        self.store = WatchListStore(self.signature_file)
        self.registry_path = self.root / "companies.json"
        self.registry_path.write_text('{"source_url":"source","retrieved_at":"now","companies":{"0x004C":"Apple, Inc."}}', encoding="utf-8")
        self.restart_calls = 0
        def restart():
            self.restart_calls += 1
            if self.fail_restart:
                raise RuntimeError("scanner restart failed")
        self.fail_restart = False
        self.app = create_app(WebServices(self.root / "password.hash", self.root / "session.key",
                                          watchlists=self.store, restart_scanner=restart,
                                          company_identifiers=CompanyIdentifierRegistry.from_json(self.registry_path)))
        self.client = self.app.test_client()
        self.client.post("/setup", data={"password": "a-good-password"})

    def csrf(self, client=None):
        with (client or self.client).session_transaction() as session:
            return session["csrf_token"]

    def post(self, path, body, client=None):
        client = client or self.client
        return client.post(path, json=body, headers={"X-CSRF-Token": self.csrf(client)})

    def test_list_create_rename_enable_and_delete(self):
        self.assertEqual(self.client.get("/api/watchlists").json, {"watchlists": []})
        created = self.post("/api/watchlists/rules", {"label": "Door", "list_name": "Home", "service_uuids": ["180f"]})
        self.assertEqual(created.status_code, 201)
        rule = created.json["rule"]
        self.assertEqual(rule["confidence"], "unknown")
        self.assertEqual(rule["min_observations"], 3)
        self.assertFalse(rule["alert_enabled"])
        lists = self.client.get("/api/watchlists").json["watchlists"]
        self.assertEqual(lists[0]["name"], "Home")
        self.assertEqual(lists[0]["rules"][0]["filter_coverage"], "full")
        self.assertEqual(self.post("/api/watchlists/rename", {"old_name": "Home", "new_name": "House"}).status_code, 200)
        self.assertEqual(self.post(f"/api/watchlists/rules/{rule['id']}/enabled", {"enabled": False}).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/watchlists/rules/{rule['id']}", headers={"X-CSRF-Token": self.csrf()}).status_code, 200)
        other = self.post("/api/watchlists/rules", {"label": "Other", "list_name": "Other", "observed_identifiers": ["aa"]})
        self.assertEqual(other.status_code, 201)
        self.assertEqual(self.post("/api/watchlists/delete", {"name": "Other"}).status_code, 200)
        self.assertEqual([sig.signature_id for sig in self.store.list_signatures()], ["builtin"])

    def test_ignore_list_api_reuses_rule_criteria_and_crud_contract(self):
        created = self.post("/api/ignorelists/rules", {"label": "Quiet beacon", "list_name": "Quiet", "name_regex": "^Axon-[0-9]+$", "identifier_prefixes": ["aa:bb:cc"]})
        self.assertEqual(created.status_code, 201, created.json)
        rule = created.json["rule"]
        self.assertEqual(rule["ignorelist_name"], "Quiet")
        self.assertEqual(rule["criteria"]["name_regex"], "^Axon-[0-9]+$")
        self.assertEqual(self.client.get("/api/ignorelists").json["ignorelists"][0]["rules"][0]["id"], rule["id"])
        self.assertEqual(self.post("/api/ignorelists/rename", {"old_name": "Quiet", "new_name": "Muted"}).status_code, 200)
        self.assertEqual(self.post(f"/api/ignorelists/rules/{rule['id']}/enabled", {"enabled": False}).status_code, 200)
        listed = self.client.get("/api/ignorelists").json["ignorelists"][0]
        self.assertEqual(listed["name"], "Muted")
        self.assertFalse(listed["rules"][0]["enabled"])
        self.assertEqual(self.client.delete(f"/api/ignorelists/rules/{rule['id']}", headers={"X-CSRF-Token": self.csrf()}).status_code, 200)

    def test_auth_and_csrf_reject_every_mutation_before_store_or_restart(self):
        unauth = self.app.test_client()
        calls = self.restart_calls
        operations = [
            ("post", "/api/watchlists/rules", {"label": "A", "list_name": "A", "service_uuids": ["180d"]}),
            ("post", "/api/watchlists/rename", {"old_name": "A", "new_name": "B"}),
            ("post", "/api/watchlists/rules/builtin/enabled", {"enabled": False}),
            ("delete", "/api/watchlists/rules/builtin", None),
            ("post", "/api/watchlists/delete", {"name": "A"}),
        ]
        for method, path, body in operations:
            response = getattr(unauth, method)(path, json=body) if body is not None else getattr(unauth, method)(path)
            self.assertEqual(response.status_code, 401)
            response = getattr(self.client, method)(path, json=body, headers={"X-CSRF-Token": "invalid"}) if body is not None else getattr(self.client, method)(path, headers={"X-CSRF-Token": "invalid"})
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.restart_calls, calls)
        self.assertEqual([sig.signature_id for sig in self.store.list_signatures()], ["builtin"])

    def test_failed_restart_rolls_back_mutations(self):
        self.fail_restart = True
        before = self.signature_file.read_bytes()
        response = self.post("/api/watchlists/rules", {"label": "Door", "list_name": "Home", "service_uuids": ["180f"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("restart failed", response.json["error"])
        self.assertEqual(self.signature_file.read_bytes(), before)

        first = self.store.create_rule({"label": "Door", "list_name": "Home", "service_uuids": ["180f"]})
        self.store.create_rule({"label": "Window", "list_name": "Home", "service_uuids": ["1810"]})
        baseline = self.signature_file.read_bytes()
        operations = [
            self.post(f"/api/watchlists/rules/{first.signature_id}/enabled", {"enabled": False}),
            self.post("/api/watchlists/rename", {"old_name": "Home", "new_name": "House"}),
            self.client.delete(f"/api/watchlists/rules/{first.signature_id}", headers={"X-CSRF-Token": self.csrf()}),
            self.post("/api/watchlists/delete", {"name": "Home"}),
        ]
        for response in operations:
            self.assertEqual(response.status_code, 400)
            self.assertIn("restart failed", response.json["error"])
            self.assertEqual(self.signature_file.read_bytes(), baseline)

    def test_invalid_api_shapes_are_rejected(self):
        response = self.post("/api/watchlists/rules", {"label": "Bad", "list_name": "Home", "enabled": False})
        self.assertEqual(response.status_code, 400)

    def test_create_rule_supports_name_regex_identifier_prefix_and_company_id(self):
        response = self.post("/api/watchlists/rules", {
            "label": "Axon pattern", "list_name": "Roadside", "name_regex": "^Axon-[0-9]+$",
            "identifier_prefixes": ["AA:BB:CC"], "manufacturer_ids": [76],
        })
        self.assertEqual(response.status_code, 201, response.json)
        rule = response.json["rule"]
        self.assertEqual(rule["criteria"]["name_regex"], "^Axon-[0-9]+$")
        self.assertEqual(rule["criteria"]["identifier_prefixes"], ["aa:bb:cc"])
        self.assertEqual(rule["criteria"]["manufacturer_ids"], [76])
        response = self.post("/api/watchlists/rules", {"label": "Bad", "list_name": "Home", "service_uuids": ["nope"]})
        self.assertEqual(response.status_code, 400)

    def test_ignore_rules_filter_current_wifi_observations_but_not_event_history(self):
        self.store.create_ignore_rule({"label": "Lab network", "list_name": "Quiet Wi-Fi", "protocol": "wifi", "ssid_regex": "^Lab-"})
        services = self.app.extensions["web_services"]
        services.wifi_observations = lambda: [
            {"ssid": "Lab-Camera", "bssid": "00:11:22:33:44:55", "signal": -50, "channel": 6, "security": "WPA", "observed_at": "2026-10-21T12:00:00+00:00"},
            {"ssid": "Guest", "bssid": "00:11:22:33:44:66", "signal": -60, "channel": 11, "security": "WPA", "observed_at": "2026-10-21T12:00:00+00:00"},
        ]
        response = self.client.get("/api/wifi/observations")
        self.assertEqual([item["ssid"] for item in response.json["observations"]], ["Guest"])

    def test_manufacturer_names_enrich_watch_rule_and_scans_keep_unknown_ids(self):
        self.post("/api/watchlists/rules", {"label": "Apple beacon", "list_name": "Devices", "manufacturer_data": {"76": "AABB"}})
        rule = self.client.get("/api/watchlists").json["watchlists"][0]["rules"][0]
        self.assertEqual(rule["manufacturer_names"], {"76": "Apple, Inc."})
        services = self.app.extensions["web_services"]
        services.scans = lambda: [{"identifier": "raw", "manufacturer_data": {"76": "AABB", "999": "CC"}}]
        scans = self.client.get("/api/scans").json["scans"][0]
        self.assertEqual(scans["manufacturer_names"], {"76": "Apple, Inc."})
        self.assertEqual(scans["manufacturer_data"]["999"], "CC")
        self.assertNotIn("999", scans["manufacturer_names"])

    def test_two_concurrent_creates_do_not_lose_updates(self):
        entered = Event()
        release = Event()
        original_restart = self.app.extensions["web_services"].restart_scanner
        count = 0
        def slow_restart():
            nonlocal count
            count += 1
            if count == 1:
                entered.set()
                release.wait(2)
            original_restart()
        self.app.extensions["web_services"].restart_scanner = slow_restart
        results = []
        def create(label):
            client = self.app.test_client()
            with client.session_transaction() as session:
                session["authenticated"] = True
                session["csrf_token"] = "token"
            results.append(client.post("/api/watchlists/rules", json={"label": label, "list_name": "Home", "service_uuids": ["180f"]}, headers={"X-CSRF-Token": "token"}).status_code)
        first = Thread(target=create, args=("One",))
        second = Thread(target=create, args=("Two",))
        first.start()
        self.assertTrue(entered.wait(1))
        second.start()
        release.set()
        first.join(3)
        second.join(3)
        self.assertEqual(sorted(results), [201, 201])
        self.assertEqual(len([sig for sig in self.store.list_signatures() if sig.watchlist]), 2)


if __name__ == "__main__":
    unittest.main()
