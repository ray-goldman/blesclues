import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bt_signature_detector.models import Confidence, DetectionEvent
from bt_signature_detector.store import EventStore


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events.sqlite3"
        self.store = EventStore(self.path, retention_days=1, max_events=2)
        self.now = datetime(2026, 1, 2, tzinfo=timezone.utc)

    def event(self, seconds=0):
        stamp = self.now + timedelta(seconds=seconds)
        return DetectionEvent("sig", "Signature", Confidence.POSSIBLE, "device", stamp, stamp, -60, 3)

    def test_schema_persistence_and_recent_order(self):
        self.store.record(self.event(1))
        self.store.record(self.event(2))
        rows = self.store.recent(10)
        self.assertEqual([row.last_seen.second for row in rows], [2, 1])
        self.assertEqual(rows[0].signature_id, "sig")

    def test_retention_by_age_and_max_count(self):
        self.store.record(self.event(-90000))
        self.store.record(self.event(1))
        self.store.record(self.event(2))
        self.store.record(self.event(3))
        self.assertEqual(self.store.prune(self.now), 2)
        self.assertEqual(len(self.store.recent(10)), 2)


if __name__ == "__main__":
    unittest.main()
