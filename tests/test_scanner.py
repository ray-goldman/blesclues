import asyncio
from pathlib import Path
import unittest
from types import SimpleNamespace

from bt_signature_detector.config import BluetoothConfig, OrPatternConfig
from bt_signature_detector.scan_mode import effective_bluetooth_config
from bt_signature_detector.scanner import BleScanner
from bt_signature_detector.models import Confidence, Signature


class FakeBackend:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
    async def start(self): self.started = True
    async def stop(self): self.stopped = True


class ScannerTests(unittest.IsolatedAsyncioTestCase):
    def test_effective_config_unions_manual_and_derived_filters_once(self):
        rule = Signature("m", "Manufacturer", Confidence.UNKNOWN, manufacturer_id=76,
                         manufacturer_pattern=b"\x01", watchlist="List")
        derived = OrPatternConfig(0, 0xFF, b"L\x00\x01")
        manual = OrPatternConfig(0, 0xFF, b"manual")
        effective = effective_bluetooth_config(BluetoothConfig(or_patterns=(manual, derived)),
            signatures=(rule,))
        self.assertEqual(effective.scan_mode, "passive")
        self.assertEqual(effective.or_patterns, (manual, derived))

    def test_effective_config_always_preserves_the_configured_radio_mode(self):
        configured = BluetoothConfig(or_patterns=(OrPatternConfig(0, 255, b"\x01"),))
        effective = effective_bluetooth_config(configured)
        self.assertEqual(effective, configured)

    def test_configured_active_mode_is_preserved_without_browser_marker(self):
        configured = BluetoothConfig(scan_mode="active", or_patterns=())
        effective = effective_bluetooth_config(configured)
        self.assertEqual(effective, configured)

    async def test_active_scanner_omits_passive_blueZ_filter(self):
        created = []

        def factory(**kwargs):
            created.append(FakeBackend(**kwargs))
            return created[-1]

        scanner = BleScanner(BluetoothConfig(scan_mode="active"), scanner_factory=factory)
        stop = asyncio.Event()
        task = asyncio.create_task(scanner.run(lambda _: asyncio.sleep(0), stop))
        await asyncio.sleep(0.01)
        stop.set()
        await task
        self.assertEqual(created[0].kwargs["scanning_mode"], "active")
        self.assertNotIn("bluez", created[0].kwargs)

    async def test_scanner_reports_adapter_start_failures_for_dashboard_status(self):
        statuses = []

        class FailingBackend(FakeBackend):
            async def start(self): raise RuntimeError("adapter unavailable")

        scanner = BleScanner(BluetoothConfig(scan_mode="active"),
            scanner_factory=lambda **kwargs: FailingBackend(**kwargs),
            reconnect_initial_seconds=0.01, reconnect_max_seconds=0.01)
        stop = asyncio.Event()
        task = asyncio.create_task(scanner.run(lambda _: asyncio.sleep(0), stop,
            status_callback=statuses.append))
        await asyncio.sleep(0.02)
        stop.set()
        await task

        self.assertTrue(any(status.get("state") == "error" and "adapter unavailable" in status.get("error", "")
            for status in statuses))

    async def test_scanner_preserves_platform_address_type(self):
        class ReportingBackend(FakeBackend):
            async def start(self):
                callback = self.kwargs["detection_callback"]
                callback(SimpleNamespace(address="aa", name="Beacon", address_type="random", rssi=-60),
                    SimpleNamespace(manufacturer_data={}, service_data={}, service_uuids=(), rssi=-59))
        scanner = BleScanner(BluetoothConfig(scan_mode="active"),
            scanner_factory=lambda **kwargs: ReportingBackend(**kwargs))
        received = []
        stop = asyncio.Event()
        task = asyncio.create_task(scanner.run(lambda item: _append(received, item), stop))
        await asyncio.sleep(0.01)
        stop.set()
        await task
        self.assertEqual(received[0].address_type, "random")

    async def test_sync_detection_pipeline_callback_is_not_scheduled_as_coroutine(self):
        processed = []
        stop = asyncio.Event()

        class SingleAdvertisementBackend(FakeBackend):
            async def start(self):
                stop.set()
                self.kwargs["detection_callback"](
                    SimpleNamespace(address="aa", name="Beacon", rssi=-60),
                    SimpleNamespace(manufacturer_data={}, service_data={}, service_uuids=(), rssi=-59))

        scanner = BleScanner(BluetoothConfig(scan_mode="active"),
            scanner_factory=lambda **kwargs: SingleAdvertisementBackend(**kwargs))
        with self.assertNoLogs("bt_signature_detector.scanner", level="ERROR"):
            await scanner.run(lambda item: processed.append(item) or [], stop)
        self.assertEqual(len(processed), 1)

    async def test_passive_or_patterns_and_advertisement_normalization(self):
        created = []
        def factory(**kwargs):
            backend = FakeBackend(**kwargs)
            created.append(backend)
            return backend
        scanner = BleScanner(BluetoothConfig(or_patterns=(OrPatternConfig(0, 255, b"\x01\x02"),)),
                             scanner_factory=factory, reconnect_initial_seconds=0.01, reconnect_max_seconds=0.02)
        received = []
        stop = asyncio.Event()
        task = asyncio.create_task(scanner.run(lambda item: _append(received, item), stop))
        await asyncio.sleep(0.03)
        stop.set()
        await task
        self.assertTrue(created)
        self.assertEqual(created[0].kwargs["scanning_mode"], "passive")
        self.assertIn("bluez", created[0].kwargs)

    async def test_passive_error_retries_without_switching_mode(self):
        modes = []
        class Failing(FakeBackend):
            async def start(self):
                modes.append(self.kwargs["scanning_mode"])
                raise RuntimeError("adapter down")
        def factory(**kwargs): return Failing(**kwargs)
        scanner = BleScanner(BluetoothConfig(or_patterns=(OrPatternConfig(0, 255, b"\x01"),)),
                             scanner_factory=factory, reconnect_initial_seconds=0.001, reconnect_max_seconds=0.002)
        stop = asyncio.Event()
        task = asyncio.create_task(scanner.run(lambda _: asyncio.sleep(0), stop))
        await asyncio.sleep(0.05)
        stop.set()
        await task
        self.assertGreaterEqual(len(modes), 2)
        self.assertEqual(set(modes), {"passive"})


async def _append(destination, item):
    destination.append(item)


if __name__ == "__main__": unittest.main()
