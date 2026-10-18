from __future__ import annotations

import asyncio
import logging
from typing import Sequence

from ..models import DetectionEvent, Confidence
from .base import Notifier

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    def __init__(self, notifiers: Sequence[Notifier], *, queue_size: int = 64,
                 timeout_seconds: float = 5.0) -> None:
        self.notifiers = tuple(notifiers)
        self.timeout = timeout_seconds
        self.queues = [asyncio.Queue(maxsize=queue_size) for _ in self.notifiers]
        self.tasks: list[asyncio.Task] = []
        self.dropped = 0
        self.errors = 0
        self._started = False

    async def start(self) -> None:
        if self._started: return
        self._started = True
        self.tasks = [asyncio.create_task(self._worker(notifier, queue))
                      for notifier, queue in zip(self.notifiers, self.queues)]

    def submit(self, event: DetectionEvent) -> bool:
        if event.confidence is not Confidence.CONFIRMED or not event.alert_enabled:
            return False
        accepted = True
        for queue in self.queues:
            try: queue.put_nowait(event)
            except asyncio.QueueFull:
                self.dropped += 1
                accepted = False
        return accepted

    async def _worker(self, notifier: Notifier, queue: asyncio.Queue) -> None:
        while True:
            event = await queue.get()
            try:
                if event is None: return
                try:
                    await asyncio.wait_for(notifier.send(event), timeout=self.timeout)
                except Exception:
                    self.errors += 1
                    logger.exception("notification backend failed")
            finally:
                queue.task_done()

    async def close(self) -> None:
        if not self._started: return
        await asyncio.gather(*(queue.join() for queue in self.queues))
        for queue in self.queues: await queue.put(None)
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self._started = False
