from __future__ import annotations

from collections import deque
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Sequence

from .models import Advertisement
from .wifi_scanner import WifiObservation


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
            "rssi": advertisement.rssi,
            "timestamp": advertisement.timestamp.isoformat(),
            "manufacturer_data": {str(company_id): value[:32].hex().upper()
                for company_id, value in advertisement.manufacturer_data.items()}}
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


class RuntimeDeviceCache:
    """Bounded, deduplicated device view serialized only to volatile runtime storage."""
    def __init__(self, path: Path, *, limit: int = 100, absence_seconds: int = 120) -> None:
        self.path = Path(path)
        self.limit = limit
        self.absence_seconds = absence_seconds
        self._items: OrderedDict[str, dict] = OrderedDict()
        self._lock = threading.Lock()
        self._last_flush = 0.0

    def add(self, advertisement: Advertisement) -> None:
        key = advertisement.identifier
        observed = advertisement.timestamp
        with self._lock:
            self._expire(datetime.now(timezone.utc))
            current = self._items.get(key)
            if current is None:
                current = {
                    "identifier": key,
                    "first_seen": observed.isoformat(),
                    "last_seen": observed.isoformat(),
                }
            current["last_seen"] = observed.isoformat()
            if advertisement.name is not None:
                current["name"] = advertisement.name
            if advertisement.address_type is not None:
                current["address_type"] = advertisement.address_type
            current["rssi"] = advertisement.rssi
            if advertisement.manufacturer_data:
                current["manufacturer_data"] = {
                    str(company_id): value[:32].hex().upper()
                    for company_id, value in advertisement.manufacturer_data.items()
                }
            if advertisement.service_uuids:
                current["service_uuids"] = list(advertisement.service_uuids)
            if advertisement.service_data:
                current["service_data"] = {str(uuid): value[:32].hex().upper()
                    for uuid, value in advertisement.service_data.items()}
            self._items[key] = current
            self._items.move_to_end(key)
            while len(self._items) > self.limit:
                self._items.popitem(last=False)
            now = time.monotonic()
            if now - self._last_flush >= 1.0:
                self._flush()
                self._last_flush = now

    def _expire(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.absence_seconds)
        expired = [key for key, item in self._items.items()
            if _parse_time(item.get("last_seen")) < cutoff]
        for key in expired:
            del self._items[key]

    def recent(self) -> list[dict]:
        with self._lock:
            self._expire(datetime.now(timezone.utc))
            return [dict(item) for item in self._items.values()]

    def flush(self) -> None:
        with self._lock:
            self._expire(datetime.now(timezone.utc))
            self._flush()
            self._last_flush = time.monotonic()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".devices-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(list(self._items.values()), output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            try:
                import grp
                os.chown(name, -1, grp.getgrnam("bt-detector").gr_gid)
            except (ImportError, KeyError, PermissionError):
                pass
            os.chmod(name, 0o640)
            os.replace(name, self.path)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    @staticmethod
    def read(path: Path, limit: int = 100, absence_seconds: int = 120) -> list[dict]:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(value, list):
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=absence_seconds)
        rows = [item for item in value if isinstance(item, dict)
            and _parse_time(item.get("last_seen")) >= cutoff]
        return rows[-limit:]


class RuntimeWifiCache:
    """Replace-only, bounded live AP snapshot written to volatile runtime storage."""
    def __init__(self, path: Path, limit: int = 100) -> None:
        self.path = Path(path)
        self.limit = limit
        self._items: list[dict] = []
        self._lock = threading.Lock()

    def replace(self, observations: Sequence[WifiObservation]) -> None:
        items = [{"ssid": item.ssid, "bssid": item.bssid, "signal": item.signal,
            "channel": item.channel, "security": item.security,
            "observed_at": item.observed_at.isoformat()} for item in observations[-self.limit:]]
        with self._lock:
            self._items = items
            self._flush()

    def recent(self) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._items]

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".wifi-observations-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(self._items, output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            try:
                import grp
                os.chown(name, -1, grp.getgrnam("bt-detector").gr_gid)
            except (ImportError, KeyError, PermissionError):
                pass
            os.chmod(name, 0o640)
            os.replace(name, self.path)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    @staticmethod
    def read(path: Path, limit: int = 100) -> list[dict]:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return value[-limit:] if isinstance(value, list) and all(isinstance(row, dict) for row in value) else []


def _parse_time(value: object) -> datetime:
    try:
        timestamp = datetime.fromisoformat(str(value))
        if timestamp.tzinfo is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def write_runtime_status(path: Path, status: dict) -> None:
    """Atomically publish compact status data to a volatile runtime file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".scanner-status-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(status, output, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, 0o640)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
