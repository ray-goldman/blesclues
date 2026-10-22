import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bt_signature_detector.watchlists import WatchListStore


class WatchListStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "signatures.yaml"
        self.path.write_text('''schema_version: 1
signatures:
  - id: builtin
    label: Built in
    service_uuids: ["180d"]
''', encoding="utf-8")
        self.store = WatchListStore(self.path)

    def test_create_rename_enable_and_delete_preserves_builtin(self):
        rule = self.store.create_rule({"label": "Door sensor", "list_name": "Home", "service_uuids": ["180f"]})
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.watchlist, "Home")
        self.assertEqual(rule.min_observations, 3)
        self.assertFalse(rule.alert_enabled)
        self.store.rename_list("home", "Household")
        self.assertEqual(self.store.list_signatures()[1].watchlist, "Household")
        self.store.set_enabled(rule.signature_id, False)
        self.assertFalse(self.store.list_signatures()[1].enabled)
        self.store.delete_rule(rule.signature_id)
        self.assertEqual([s.signature_id for s in self.store.list_signatures()], ["builtin"])

    def test_delete_list_removes_members_but_keeps_other_rules(self):
        first = self.store.create_rule({"label": "First", "list_name": "Home", "service_uuids": ["180f"]})
        self.store.create_rule({"label": "Second", "list_name": "home", "service_uuids": ["1810"]})
        self.store.create_rule({"label": "Third", "list_name": "Car", "service_uuids": ["1811"]})
        self.store.delete_list("HOME")
        self.assertEqual([rule.watchlist for rule in self.store.list_signatures()], [None, "Car"])
        self.assertNotEqual(first.signature_id, "builtin")

    def test_invalid_rule_and_casefold_name_rejection_leave_file_unchanged(self):
        self.store.create_rule({"label": "One", "list_name": "Home", "service_uuids": ["180f"]})
        self.store.create_rule({"label": "Two", "list_name": "Car", "service_uuids": ["1810"]})
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.store.create_rule({"label": "Bad", "list_name": "  ", "service_uuids": ["180d"]})
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(ValueError):
            self.store.rename_list("Home", "CAR")
        self.assertEqual(self.path.read_bytes(), before)

    def test_generated_ids_are_unique_and_labels_are_bounded(self):
        first = self.store.create_rule({"label": "First", "list_name": "Home", "service_uuids": ["180f"]})
        second = self.store.create_rule({"label": "Second", "list_name": "Home", "service_uuids": ["1810"]})
        self.assertNotEqual(first.signature_id, second.signature_id)
        before = self.path.read_bytes()
        for data in (
            {"label": "x" * 121, "list_name": "Home", "service_uuids": ["180d"]},
            {"label": "Long list", "list_name": "x" * 81, "service_uuids": ["180d"]},
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.store.create_rule(data)
            self.assertEqual(self.path.read_bytes(), before)

    def test_rejects_invalid_complete_yaml_and_failed_replace_preserves_original(self):
        before = self.path.read_bytes()
        with patch("bt_signature_detector.watchlists.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                self.store.create_rule({"label": "Fail", "list_name": "Home", "service_uuids": ["180f"]})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(self.store.list_signatures()), 1)

    def test_transaction_restores_file_bytes_when_restart_fails(self):
        before = self.path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "restart"):
            self.store.transaction(
                lambda: self.store.create_rule({"label": "Temp", "list_name": "Home", "service_uuids": ["180f"]}),
                restart=lambda: (_ for _ in ()).throw(RuntimeError("restart failed")))
        self.assertEqual(self.path.read_bytes(), before)

    def test_ignore_lists_create_rename_toggle_and_delete_without_changing_watch_lists(self):
        watched = self.store.create_rule({"label": "Track", "list_name": "Home", "service_uuids": ["180f"]})
        ignored = self.store.create_ignore_rule({"label": "Ignore Axon", "list_name": "Quiet", "name_regex": "^Axon-[0-9]+$", "identifier_prefixes": ["aa:bb:cc"]})
        self.assertEqual(ignored.ignorelist, "Quiet")
        self.assertIsNone(ignored.watchlist)
        self.store.rename_ignore_list("quiet", "Muted")
        self.store.set_ignore_rule_enabled(ignored.signature_id, False)
        ignored_after = next(item for item in self.store.list_signatures() if item.signature_id == ignored.signature_id)
        self.assertEqual(ignored_after.ignorelist, "Muted")
        self.assertFalse(ignored_after.enabled)
        self.store.delete_ignore_rule(ignored.signature_id)
        self.assertEqual([item.signature_id for item in self.store.list_signatures()], ["builtin", watched.signature_id])


if __name__ == "__main__":
    unittest.main()
