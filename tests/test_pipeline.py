import unittest
from datetime import datetime, timezone

from bt_signature_detector.models import Advertisement, Confidence, Signature
from bt_signature_detector.pipeline import DetectionPipeline


class PipelineTests(unittest.TestCase):
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


if __name__ == "__main__": unittest.main()
