from __future__ import annotations

import asyncio
from pathlib import Path

from ..models import DetectionEvent


class AudioNotifier:
    def __init__(self, sound_path: Path, player: str = "aplay") -> None:
        self.sound_path = Path(sound_path)
        self.player = player

    async def _play(self) -> None:
        process = await asyncio.create_subprocess_exec(self.player, str(self.sound_path),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        code = await process.wait()
        if code:
            raise RuntimeError(f"audio player exited with status {code}")

    async def send(self, event: DetectionEvent) -> None:
        await self._play()

    async def test(self) -> None:
        await self._play()
