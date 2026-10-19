import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bt_signature_detector.models import Advertisement
from bt_signature_detector.runtime_cache import RuntimeDeviceCache, RuntimeScanCache, RuntimeWifiCache, write_runtime_status
from bt_signature_detector.wifi_scanner import WifiObservation


class RuntimeCacheTests(unittest.TestCase):
    def test_wifi_observations_replace_bounded_volatile_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run" / "wifi-observations.json"
            cache = RuntimeWifiCache(path, limit=2)
            stamp = datetime.now(timezone.utc)
            observations = [WifiObservation(f"net-{i}", f"00:00:00:00:00:{i:02X}", 50, 6, "WPA2", stamp)
                            for i in range(3)]
            cache.replace(observations)
            self.assertEqual(len(cache.recent()), 2)
            self.assertEqual(RuntimeWifiCache.read(path, 1)[0]["ssid"], "net-2")
            cache.replace(())
            self.assertEqual(RuntimeWifiCache.read(path), [])

    def test_scanner_status_is_atomically_written_as_runtime_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run" / "scanner-status.json"
            write_runtime_status(path, {"state": "error", "error": "adapter unavailable"})
            self.assertEqual(__import__("json").loads(path.read_text()),
                {"state": "error", "error": "adapter unavailable"})
            self.assertEqual(list(path.parent.glob(".scanner-status-*")), [])

    def test_device_inventory_deduplicates_and_preserves_first_seen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run" / "devices.json"
            cache = RuntimeDeviceCache(path)
            first = datetime.now(timezone.utc)
            cache.add(Advertisement("aa", name="Beacon", rssi=-70,
                manufacturer_data={76: b"\x01"}, service_uuids=("uuid-a",), timestamp=first))
            cache.add(Advertisement("aa", rssi=-50, manufacturer_data={76: b"\x02"}, timestamp=first + timedelta(seconds=2)))
            rows = cache.recent()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["identifier"], "aa")
            self.assertEqual(rows[0]["name"], "Beacon")
            self.assertEqual(rows[0]["rssi"], -50)
            self.assertEqual(rows[0]["first_seen"], first.isoformat())
            self.assertEqual(rows[0]["last_seen"], (first + timedelta(seconds=2)).isoformat())
            self.assertEqual(rows[0]["manufacturer_data"], {"76": "02"})
            self.assertEqual(rows[0]["service_uuids"], ["uuid-a"])

    def test_device_inventory_keeps_bounded_service_data_for_watch_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = RuntimeDeviceCache(Path(directory) / "devices.json")
            cache.add(Advertisement("aa", service_data={"180f": bytes.fromhex("aabbcc")},
                                    timestamp=datetime.now(timezone.utc)))
            self.assertEqual(cache.recent()[0]["service_data"], {"180f": "AABBCC"})

    def test_rotated_address_is_a_separate_inventory_row(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = RuntimeDeviceCache(Path(directory) / "devices.json")
            cache.add(Advertisement("address-one"))
            cache.add(Advertisement("address-two"))
            self.assertEqual({row["identifier"] for row in cache.recent()}, {"address-one", "address-two"})

    def test_device_inventory_is_bounded_by_most_recent_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = RuntimeDeviceCache(Path(directory) / "devices.json", limit=2)
            base = datetime.now(timezone.utc)
            cache.add(Advertisement("old", timestamp=base))
            cache.add(Advertisement("newer", timestamp=base + timedelta(seconds=1)))
            cache.add(Advertisement("newest", timestamp=base + timedelta(seconds=2)))
            self.assertEqual({row["identifier"] for row in cache.recent()}, {"newer", "newest"})

    def test_device_inventory_expires_entries_after_absence_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = RuntimeDeviceCache(Path(directory) / "devices.json", absence_seconds=10)
            cache.add(Advertisement("stale", timestamp=datetime.now(timezone.utc) - timedelta(seconds=11)))
            self.assertEqual(cache.recent(), [])

    def test_device_inventory_snapshot_is_volatile_and_bounded_on_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run" / "devices.json"
            cache = RuntimeDeviceCache(path, limit=2)
            for identifier in ("one", "two", "three"):
                cache.add(Advertisement(identifier))
            cache.flush()
            rows = RuntimeDeviceCache.read(path, 1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["identifier"], "three")

    def test_scan_cache_is_bounded_and_readable_without_event_store(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run" / "scans.json"
            cache = RuntimeScanCache(path, limit=2)
            for i in range(3):
                cache.add(Advertisement(f"private-{i}", name="Beacon", rssi=-50,
                    manufacturer_data={76: bytes.fromhex("a1b2c3")},
                    timestamp=datetime.now(timezone.utc)))
            cache.flush()
            rows = RuntimeScanCache.read(path, 2)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[-1]["identifier"], "private-2")
            self.assertEqual(rows[-1]["manufacturer_data"], {"76": "A1B2C3"})


if __name__ == "__main__": unittest.main()
