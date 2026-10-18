import asyncio
import unittest
from types import SimpleNamespace

from bt_signature_detector.config import BluetoothConfig, OrPatternConfig
from bt_signature_detector.scanner import BleScanner


class FakeBackend:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
    async def start(self): self.started = True
    async def stop(self): self.stopped = True


class ScannerTests(unittest.IsolatedAsyncioTestCase):
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
        await asyncio.sleep(0.01)
        stop.set()
        await task
        self.assertGreaterEqual(len(modes), 2)
        self.assertEqual(set(modes), {"passive"})


async def _append(destination, item):
    destination.append(item)


if __name__ == "__main__": unittest.main()
