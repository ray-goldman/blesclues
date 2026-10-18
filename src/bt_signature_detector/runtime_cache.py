from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import tempfile
import threading
import time

from .models import Advertisement


class RuntimeScanCache:
    """Bounded, volatile scan cache for the UI; never uses the durable event store."""
    def __init__(self, path: Path, limit: int = 100) -> None:
        self.path = Path(path)
        self.limit = limit
        self._items = deque(maxlen=limit)
        self._lock = threading.Lock()
        self._last_flush = 0.0

    def add(self, advertisement: Advertisement) -> None:
        item = {"identifier": advertisement.identifier, "name": advertisement.name,
            "rssi": advertisement.rssi, "timestamp": advertisement.timestamp.isoformat()}
        with self._lock:
            self._items.append(item)
            now = time.monotonic()
            if now - self._last_flush >= 1.0:
                self._flush()
                self._last_flush = now

    def flush(self) -> None:
        with self._lock:
            self._flush()
            self._last_flush = time.monotonic()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".scans-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(list(self._items), output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            try:
                import grp
                os.chown(name, -1, grp.getgrnam("bt-detector").gr_gid)
            except (ImportError, KeyError, PermissionError): pass
            os.chmod(name, 0o640)
            os.replace(name, self.path)
        finally:
            try: os.unlink(name)
            except FileNotFoundError: pass

    def recent(self) -> list[dict]:
        with self._lock: return list(self._items)

    @staticmethod
    def read(path: Path, limit: int = 100) -> list[dict]:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
            return value[-limit:] if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []
