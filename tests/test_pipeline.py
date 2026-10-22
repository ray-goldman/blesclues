import unittest
from datetime import datetime, timezone

from bt_signature_detector.models import Advertisement, Confidence, Signature
from bt_signature_detector.builtin_rules import BuiltInRule, BuiltinScoringSettings
from bt_signature_detector.detection_scoring import CrossProtocolScorer
from bt_signature_detector.pipeline import DetectionPipeline, match_ble_rules
from bt_signature_detector.wifi_scanner import WifiObservation
import tempfile
from pathlib import Path


class PipelineTests(unittest.TestCase):
    def test_builtin_ble_rules_match_oui_and_names_but_skip_local_admin_oui(self):
        rules = (
            BuiltInRule("axon-oui", "ble", "Axon", "mac_prefix", "00:25:DF", "high", 50, "fixture", ""),
            BuiltInRule("axon-name", "ble", "Axon", "name_regex", "(?i)taser international", "high", 40, "fixture", ""),
            BuiltInRule("flock", "ble", "Flock", "name_regex", "(?i)^flock", "medium", 25, "fixture", ""),
            BuiltInRule("fs", "ble", "Flock", "name_regex", "(?i)^FS_", "low", 10, "fixture", ""),
        )
        self.assertEqual([r.rule_id for r in match_ble_rules(rules, Advertisement("00-25-df-11-22-33"))], ["axon-oui"])
        self.assertEqual([r.rule_id for r in match_ble_rules(rules, Advertisement("02:25:DF:11:22:33"))], [])
        self.assertEqual([r.rule_id for r in match_ble_rules(rules, Advertisement("02:25:DF:11:22:33", name="Taser International"))], ["axon-name"])
        self.assertEqual([r.rule_id for r in match_ble_rules(rules, Advertisement("00:00:00:00:00:00", name="Flock unit"))], ["flock"])
        self.assertEqual([r.rule_id for r in match_ble_rules(rules, Advertisement("00:00:00:00:00:00", name="FS_unit"))], ["fs"])
        self.assertEqual(match_ble_rules(rules, Advertisement("00:00:00:00:00:00", name="unrelated")), ())

    def test_qualifying_builtin_match_creates_scored_history_event(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = BuiltInRule("axon-oui", "ble", "Axon", "mac_prefix", "00:25:DF", "high", 50, "fixture", "OUI caveat")
            scorer = CrossProtocolScorer(settings=BuiltinScoringSettings(40, 60, 20), db_path=Path(directory) / "window.sqlite")
            class Store:
                def __init__(self): self.events = []
                def record(self, event): self.events.append(event)
            store = Store()
            pipeline = DetectionPipeline((), store=store, builtin_rules=(rule,), builtin_scorer=scorer)
            event = pipeline.process(Advertisement("00:25:DF:11:22:33", rssi=-55))[0]
            self.assertEqual((event.protocol, event.vendor, event.base_score, event.effective_score), ("ble", "Axon", 50, 50))
            self.assertEqual(event.source_note, "fixture; OUI caveat")
            self.assertEqual(store.events, [event])

    def test_watchlist_event_after_threshold_and_disabled_rules_are_ignored(self):
        enabled = Signature("watched", "Watched", Confidence.UNKNOWN, exact_identifiers=("aa",), watchlist="Roadside")
        disabled = Signature("disabled", "Disabled", Confidence.POSSIBLE, exact_identifiers=("aa",), watchlist="Roadside", enabled=False)
        pipeline = DetectionPipeline((enabled, disabled), cooldown_seconds=0)
        for _ in range(2):
            self.assertEqual(pipeline.process(Advertisement("aa", rssi=-50)), [])
        events = pipeline.process(Advertisement("aa", rssi=-50))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].signature_id, "watched")
        self.assertEqual(events[0].watchlist_name, "Roadside")

    def test_device_cache_receives_each_advertisement_without_changing_detection(self):
        signature = Signature("demo", "Demo", Confidence.POSSIBLE, exact_identifiers=("aa",))
        class DeviceCache:
            def __init__(self): self.items = []
            def add(self, item): self.items.append(item)
        cache = DeviceCache()
        pipeline = DetectionPipeline((signature,), device_cache=cache)
        for _ in range(3):
            events = pipeline.process(Advertisement("aa", rssi=-50, timestamp=datetime.now(timezone.utc)))
        self.assertEqual(len(cache.items), 3)
        self.assertEqual(len(events), 1)
        self.assertEqual(pipeline.advertisements_processed, 3)

    def test_store_failure_is_counted_and_scanning_continues(self):
        signature = Signature("demo", "Demo", Confidence.POSSIBLE, exact_identifiers=("aa",))
        class Store:
            def record(self, event): raise OSError("disk full")
        pipeline = DetectionPipeline((signature,), cooldown_seconds=0, store=Store())
        for _ in range(3):
            events = pipeline.process(Advertisement("aa", rssi=-50, timestamp=datetime.now(timezone.utc)))
        self.assertEqual(len(events), 1)
        self.assertEqual(pipeline.store_errors, 1)
        self.assertEqual(pipeline.advertisements_processed, 3)

    def test_matching_ignore_rule_hides_ble_before_live_cache_and_detection(self):
        ignored = Signature("ignored", "Noise", Confidence.UNKNOWN, name_pattern="^Axon-", name_mode="regex", ignorelist="Quiet")
        watched = Signature("watched", "Watch", Confidence.POSSIBLE, name_pattern="^Axon-", name_mode="regex", watchlist="Watch")
        class Cache:
            def __init__(self): self.items = []
            def add(self, item): self.items.append(item)
        class Store:
            def __init__(self): self.events = []
            def record(self, event): self.events.append(event)
        cache, store = Cache(), Store()
        pipeline = DetectionPipeline((ignored, watched), store=store, scan_cache=cache, device_cache=cache, cooldown_seconds=0)
        events = pipeline.process(Advertisement("AA:BB:CC:00:00:01", name="Axon-1234", rssi=-45))
        self.assertEqual(events, [])
        self.assertEqual(cache.items, [])
        self.assertEqual(store.events, [])

    def test_matching_ignore_rule_hides_wifi_before_detection(self):
        ignored = Signature("ignored-wifi", "Lab network", Confidence.UNKNOWN, protocol="wifi",
            ssid_pattern="^Lab-", ssid_mode="regex", ignorelist="Quiet Wi-Fi")
        pipeline = DetectionPipeline((ignored,), cooldown_seconds=0)
        observation = WifiObservation("Lab-Camera", "00:11:22:33:44:55", -45, 6, "WPA", datetime.now(timezone.utc))
        self.assertEqual(pipeline.process_wifi_observation(observation), [])


if __name__ == "__main__": unittest.main()
