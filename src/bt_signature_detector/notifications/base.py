from __future__ import annotations

from typing import Protocol

from ..models import DetectionEvent


class Notifier(Protocol):
    async def send(self, event: DetectionEvent) -> None: ...
    async def test(self) -> None: ...
