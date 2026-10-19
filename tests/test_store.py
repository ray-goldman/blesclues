import tempfile
import unittest
import sqlite3
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

    def test_migrates_existing_table_and_persists_watchlist_name(self):
        old_path = Path(self.directory.name) / "old.sqlite3"
        db = sqlite3.connect(old_path)
        try:
            db.execute("""CREATE TABLE detections (
                event_id TEXT PRIMARY KEY, signature_id TEXT NOT NULL, signature_name TEXT NOT NULL,
                confidence TEXT NOT NULL, observed_identifier TEXT NOT NULL, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, strongest_rssi INTEGER, observation_count INTEGER NOT NULL)""")
            stamp = self.now.isoformat()
            db.execute("INSERT INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       ("old", "sig", "Signature", "possible", "device", stamp, stamp, -60, 3))
            db.commit()
        finally:
            db.close()
        migrated = EventStore(old_path)
        self.assertIsNone(migrated.recent()[0].watchlist_name)
        event = DetectionEvent("watched", "Watched", Confidence.UNKNOWN, "device", self.now, self.now, -50, 3,
                               watchlist_name="Roadside")
        migrated.record(event)
        rows = {row.signature_id: row for row in migrated.recent(10)}
        self.assertEqual(rows["watched"].watchlist_name, "Roadside")

    def test_persists_builtin_detection_metadata(self):
        event = DetectionEvent("builtin:axon", "Axon", Confidence.POSSIBLE, "00:25:DF:01:02:03",
            self.now, self.now, None, 1, protocol="ble", vendor="Axon", base_score=25,
            correlation_bonus=20, effective_score=45, source_note="source catalog",
            observed_name="Taser International")
        self.store.record(event)
        result = self.store.recent()[0]
        self.assertEqual((result.protocol, result.vendor, result.base_score), ("ble", "Axon", 25))
        self.assertEqual((result.correlation_bonus, result.effective_score), (20, 45))
        self.assertEqual(result.source_note, "source catalog")
        self.assertEqual(result.observed_name, "Taser International")
        self.assertIsNone(result.observed_ssid)


if __name__ == "__main__":
    unittest.main()
