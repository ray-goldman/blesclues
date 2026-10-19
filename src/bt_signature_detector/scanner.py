from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Callable

from .config import BluetoothConfig
from .models import Advertisement

logger = logging.getLogger(__name__)


class BleScanner:
    """Advertisement-only Bleak adapter with bounded reconnects."""

    def __init__(self, config: BluetoothConfig, *, scanner_factory=None,
                 reconnect_initial_seconds: float | None = None,
                 reconnect_max_seconds: float | None = None) -> None:
        self.config = config
        self.scanner_factory = scanner_factory
        self.initial_delay = reconnect_initial_seconds or config.reconnect_initial_seconds
        self.max_delay = reconnect_max_seconds or config.reconnect_max_seconds
        if config.scan_mode == "passive" and not config.or_patterns:
            raise ValueError("passive BLE scanning requires configured BlueZ or_patterns")

    def _factory(self, callback):
        if self.scanner_factory:
            factory = self.scanner_factory
        else:
            try:
                from bleak import BleakScanner
            except ImportError as exc:
                raise RuntimeError("Bleak is required for live scanning; install the project dependencies") from exc
            factory = BleakScanner
        kwargs = {"detection_callback": callback, "scanning_mode": self.config.scan_mode}
        if self.config.adapter:
            kwargs["adapter"] = self.config.adapter
        if self.config.scan_mode == "passive":
            kwargs["bluez"] = {"or_patterns": [(p.start_position, p.ad_data_type, p.pattern) for p in self.config.or_patterns]}
        return factory(**kwargs)

    async def run(self, on_advertisement: Callable[[Advertisement], object],
                  stop_event: asyncio.Event,
                  status_callback: Callable[[dict], None] | None = None) -> None:
        loop = asyncio.get_running_loop()
        pending: set[asyncio.Task] = set()

        def report(state: str, error: str | None = None) -> None:
            if status_callback is not None:
                try:
                    status_callback({"state": state, "error": error[:256] if error else None})
                except Exception:
                    logger.warning("scanner status callback failed", exc_info=True)

        def callback(device, adv):
            manufacturer_data = dict(getattr(adv, "manufacturer_data", {}) or {})
            service_data = dict(getattr(adv, "service_data", {}) or {})
            item = Advertisement(
                identifier=str(getattr(device, "address", "unknown")),
                name=getattr(adv, "local_name", None) or getattr(device, "name", None),
                manufacturer_data={int(k): bytes(v) for k, v in manufacturer_data.items()},
                service_uuids=tuple(getattr(adv, "service_uuids", ()) or ()),
                service_data={str(k): bytes(v) for k, v in service_data.items()},
                rssi=getattr(adv, "rssi", getattr(device, "rssi", None)),
                address_type=getattr(device, "address_type", None),
            )
            try:
                result = on_advertisement(item)
                if inspect.isawaitable(result):
                    task = loop.create_task(result)
                    pending.add(task)
                    task.add_done_callback(pending.discard)
                    task.add_done_callback(lambda t: logger.error("advertisement callback failed", exc_info=t.exception()) if not t.cancelled() and t.exception() else None)
            except Exception:
                logger.exception("advertisement callback failed")

        delay = self.initial_delay
        while not stop_event.is_set():
            backend = None
            try:
                backend = self._factory(callback)
                report("starting")
                await backend.start()
                report("scanning")
                delay = self.initial_delay
                await stop_event.wait()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                report("error", str(exc))
                logger.error("BLE scanner failed; retrying in %.1f seconds: %s", delay, exc)
            finally:
                if backend is not None:
                    try:
                        await backend.stop()
                    except Exception:
                        logger.debug("scanner stop failed", exc_info=True)
            if not stop_event.is_set():
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
                delay = min(self.max_delay, delay * 2)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        report("stopped")
