"""Long-running, non-root Wi-Fi discovery service entry point."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

from .builtin_rules import load_builtin_rules
from .config import load_app_config
from .detection_scoring import CrossProtocolScorer
from .notifications.dispatcher import NotificationDispatcher
from .pipeline import DetectionPipeline
from .runtime_cache import RuntimeWifiCache
from .signatures import load_signatures
from .store import EventStore
from .wifi_scanner import scan_wifi

logger = logging.getLogger(__name__)


async def run_wifi_scan_service(config_path: Path, *, scanner: Callable = scan_wifi,
                                stop_event=None,
                                runtime_dir: Path = Path("/run/bt-signature-detector")) -> None:
    config = load_app_config(config_path)
    if not config.wifi_scanning.enabled:
        raise RuntimeError("Wi-Fi scanning is disabled in configuration")
    if config.access_point.enabled:
        raise RuntimeError("Wi-Fi scanning cannot start while the admin access point is enabled")
    rules = load_builtin_rules()
    signature_path = config.detection.signature_file
    if not signature_path.is_absolute():
        signature_path = config_path.resolve().parent / signature_path
    store = EventStore(config.storage.path, retention_days=config.storage.retention_days,
                       max_events=config.storage.max_events)
    from .cli import create_notifiers
    dispatcher = NotificationDispatcher(create_notifiers(config), queue_size=config.notifications.queue_size,
                                        timeout_seconds=config.notifications.timeout_seconds)
    pipeline = DetectionPipeline(load_signatures(signature_path), store=store, dispatcher=dispatcher,
        cooldown_seconds=config.detection.cooldown_seconds, absence_seconds=config.detection.absence_seconds,
        global_min_rssi=config.detection.global_min_rssi,
        builtin_rules=rules,
        builtin_scorer=CrossProtocolScorer(db_path=runtime_dir / "correlation.sqlite3"))
    cache = RuntimeWifiCache(runtime_dir / "wifi-observations.json", config.web.max_live_scans)
    await dispatcher.start()
    try:
        while stop_event is None or not stop_event.is_set():
            try:
                # Watch-list rules are editable without restarting the optional Wi-Fi service.
                pipeline.signatures = load_signatures(signature_path)
                observations = await asyncio.to_thread(scanner)
                cache.replace(observations)
                for observation in observations:
                    pipeline.process_wifi_observation(observation)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("Wi-Fi scan failed: %s", str(exc)[:300])
            if stop_event is None:
                await asyncio.sleep(config.wifi_scanning.interval_seconds)
            elif await asyncio.to_thread(stop_event.wait, config.wifi_scanning.interval_seconds):
                break
    finally:
        await dispatcher.close()
