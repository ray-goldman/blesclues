import unittest
from datetime import datetime, timedelta, timezone

from bt_signature_detector.models import Advertisement, Confidence, Signature
from bt_signature_detector.state import DetectionFilter


class StateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.signature = Signature("demo", "Demo", Confidence.POSSIBLE, min_rssi=-80, min_observations=3)
        self.filter = DetectionFilter(cooldown_seconds=300, absence_seconds=60, global_min_rssi=-90, clock=lambda: self.now)

    def observe(self, identifier="id-a", rssi=-70):
        return self.filter.observe(Advertisement(identifier, rssi=rssi, timestamp=self.now), [self.signature])

    def test_threshold_count_timestamps_and_strongest_rssi(self):
        self.assertEqual(self.observe(rssi=-80), [])
        self.now += timedelta(seconds=1)
        self.assertEqual(self.observe(rssi=-70), [])
        self.now += timedelta(seconds=1)
        events = self.observe(rssi=-60)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].observation_count, 3)
        self.assertEqual(events[0].strongest_rssi, -60)
        self.assertEqual(events[0].first_seen, datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_randomized_identifiers_have_separate_state(self):
        self.observe("random-1")
        self.observe("random-2")
        self.observe("random-3")
        self.assertEqual(self.filter.observe(Advertisement("random-1", rssi=-70), [self.signature]), [])

    def test_cooldown_suppression_and_expiry(self):
        for _ in range(3):
            events = self.observe()
        self.assertEqual(len(events), 1)
        for _ in range(3):
            events = self.observe()
        self.assertEqual(events, [])
        self.now += timedelta(seconds=300)
        for _ in range(3):
            events = self.observe()
        self.assertEqual(len(events), 1)

    def test_absence_expire_resets_observation_window(self):
        self.observe()
        self.now += timedelta(seconds=61)
        self.assertEqual(self.filter.expire(self.now), 1)
        self.assertEqual(self.observe(), [])


if __name__ == "__main__":
    unittest.main()
