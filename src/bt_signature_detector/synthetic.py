from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta, timezone

from .models import Advertisement


async def run_synthetic(on_advertisement, stop_event: asyncio.Event) -> None:
    """Emit a clearly synthetic sample three times, without radio access."""
    start = datetime.now(timezone.utc)
    for index in range(3):
        if stop_event.is_set():
            return
        result = on_advertisement(Advertisement("synthetic:demo", name="Synthetic detector demo",
            manufacturer_data={65535: bytes.fromhex("a1b2")}, rssi=-55,
            timestamp=start + timedelta(seconds=index)))
        if inspect.isawaitable(result):
            await result
