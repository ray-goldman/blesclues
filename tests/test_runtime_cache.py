import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from bt_signature_detector.models import Advertisement
from bt_signature_detector.runtime_cache import RuntimeScanCache


class RuntimeCacheTests(unittest.TestCase):
    def test_scan_cache_is_bounded_and_readable_without_event_store(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run" / "scans.json"
            cache = RuntimeScanCache(path, limit=2)
            for i in range(3):
                cache.add(Advertisement(f"private-{i}", name="Beacon", rssi=-50,
                    timestamp=datetime.now(timezone.utc)))
            cache.flush()
            rows = RuntimeScanCache.read(path, 2)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[-1]["identifier"], "private-2")


if __name__ == "__main__": unittest.main()
