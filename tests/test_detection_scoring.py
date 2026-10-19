import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bt_signature_detector.builtin_rules import BuiltInRule, BuiltinScoringSettings


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "volatile.sqlite3"
        self.rule = BuiltInRule("rule", "ble", "Vendor", "name_regex", "(?i)test", "medium", 25, "fixture", "")
        from bt_signature_detector.detection_scoring import CrossProtocolScorer, RuleHit
        self.CrossProtocolScorer, self.RuleHit = CrossProtocolScorer, RuleHit
        self.scorer = CrossProtocolScorer(settings= BuiltinScoringSettings(40, 60, 20), db_path=self.path)
        self.when = datetime(2026, 10, 18, tzinfo=timezone.utc)

    def hit(self, protocol, seconds=0, score=None):
        rule = BuiltInRule("rule", protocol, "Vendor", "name_regex" if protocol == "ble" else "ssid_regex", "(?i)test", "medium", score or 25, "fixture", "")
        return self.RuleHit(rule, protocol, "device", "test" if protocol == "ble" else None,
                            "test" if protocol == "wifi" else None, self.when + timedelta(seconds=seconds))

    def test_score_39_does_not_qualify_and_40_does(self):
        low = self.scorer.observe(self.hit("ble", score=39))
        high = self.scorer.observe(self.hit("ble", seconds=1, score=40))
        self.assertFalse(low.qualifies)
        self.assertTrue(high.qualifies)

    def test_opposite_protocol_in_either_order_gets_bonus(self):
        self.assertEqual(self.scorer.observe(self.hit("ble")).correlation_bonus, 0)
        wifi = self.scorer.observe(self.hit("wifi", seconds=1))
        self.assertEqual((wifi.correlation_bonus, wifi.effective_score, wifi.qualifies), (20, 45, True))
        self.scorer = self.CrossProtocolScorer(settings=BuiltinScoringSettings(40, 60, 20), db_path=self.path)
        self.scorer.observe(self.hit("wifi", seconds=10))
        ble = self.scorer.observe(self.hit("ble", seconds=11))
        self.assertEqual(ble.correlation_bonus, 20)

    def test_exactly_sixty_seconds_includes_bonus_but_expired_window_does_not(self):
        self.scorer.observe(self.hit("ble", seconds=100))
        self.assertEqual(self.scorer.observe(self.hit("wifi", seconds=160)).correlation_bonus, 20)
        self.scorer = self.CrossProtocolScorer(settings=BuiltinScoringSettings(40, 60, 20), db_path=self.path)
        self.scorer.observe(self.hit("ble", seconds=200))
        self.assertEqual(self.scorer.observe(self.hit("wifi", seconds=261)).correlation_bonus, 0)

    def test_repeated_hits_from_same_protocol_do_not_correlate(self):
        first = self.scorer.observe(self.hit("ble", seconds=0))
        second = self.scorer.observe(self.hit("ble", seconds=1))
        self.assertEqual(first.correlation_bonus, 0)
        self.assertEqual(second.correlation_bonus, 0)


if __name__ == "__main__":
    unittest.main()
