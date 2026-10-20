from __future__ import annotations

import os
from pathlib import Path
import tempfile
from threading import RLock
from typing import Callable, Mapping, TypeVar
from uuid import uuid4

import yaml

from .models import Signature
from .signatures import load_signatures

T = TypeVar("T")


class WatchListStore:
    """Validated, atomic edits to the existing signature YAML document."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = RLock()

    def _read(self) -> tuple[dict[str, object], bytes, int]:
        raw = self.path.read_bytes()
        mode = self.path.stat().st_mode & 0o777
        try:
            data = yaml.safe_load(raw.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise ValueError(f"{self.path}: unable to load signatures: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("signatures"), list):
            raise ValueError(f"{self.path}: expected schema_version 1 and signatures list")
        # Validate the complete source before allowing any mutation.
        load_signatures(self.path)
        return data, raw, mode

    def list_signatures(self) -> tuple[Signature, ...]:
        with self._lock:
            return load_signatures(self.path)

    def _write(self, data: dict[str, object], mode: int) -> None:
        serialized = yaml.safe_dump(data, sort_keys=False, allow_unicode=True).encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, mode)
            load_signatures(temp_path)
            os.replace(temp_path, self.path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def _mutate(self, operation: Callable[[dict[str, object]], T]) -> T:
        with self._lock:
            data, _raw, mode = self._read()
            result = operation(data)
            self._write(data, mode)
            return result

    def create_rule(self, rule_data: Mapping[str, object]) -> Signature:
        allowed = {"label", "list_name", "match_mode", "observed_identifiers", "identifier_prefixes", "name_exact", "name_contains", "name_regex",
                   "manufacturer_data", "manufacturer_ids", "service_uuids", "service_data", "protocol", "ssid_exact", "ssid_contains", "ssid_regex",
                   "bssid_exact", "bssid_prefixes", "wifi_channels", "wifi_security"}
        unknown = set(rule_data) - allowed
        if unknown:
            raise ValueError(f"{sorted(unknown)[0]} is not a supported watch rule field")
        label = rule_data.get("label")
        list_name = rule_data.get("list_name")
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 120:
            raise ValueError("label must be 1 to 120 characters")
        if not isinstance(list_name, str) or not 1 <= len(list_name.strip()) <= 80:
            raise ValueError("list_name must be 1 to 80 characters")
        label = label.strip()
        list_name = list_name.strip()
        rule: dict[str, object] = {
            "id": str(uuid4()),
            "label": label,
            "confidence": "unknown",
            "match_mode": rule_data.get("match_mode", "all"),
            "min_observations": 3,
            "alert_enabled": False,
            "watchlist": list_name,
            "enabled": True,
        }
        rule.update({key: value for key, value in rule_data.items() if key not in {"label", "list_name"}})

        def add(data: dict[str, object]) -> Signature:
            rows = data["signatures"]
            assert isinstance(rows, list)
            existing = load_signatures(self.path)
            canonical = next((sig.watchlist for sig in existing if sig.watchlist and sig.watchlist.casefold() == list_name.casefold()), list_name)
            rule["watchlist"] = canonical
            rows.append(rule)
            self._validate_data(data)
            return next(sig for sig in load_signatures_from_data(data, self.path) if sig.signature_id == rule["id"])

        return self._mutate(add)

    def rename_list(self, old_name: str, new_name: str) -> None:
        if not isinstance(old_name, str) or not 1 <= len(old_name.strip()) <= 80:
            raise ValueError("old_name must be 1 to 80 characters")
        if not isinstance(new_name, str) or not 1 <= len(new_name.strip()) <= 80:
            raise ValueError("new_name must be 1 to 80 characters")
        old_key, new_name = old_name.strip().casefold(), new_name.strip()
        new_key = new_name.casefold()

        def rename(data: dict[str, object]) -> None:
            rows = data["signatures"]
            assert isinstance(rows, list)
            signatures = load_signatures(self.path)
            matched = [sig for sig in signatures if sig.watchlist and sig.watchlist.casefold() == old_key]
            if not matched:
                raise ValueError("watch list was not found")
            if any(sig.watchlist and sig.watchlist.casefold() == new_key and sig.watchlist.casefold() != old_key for sig in signatures):
                raise ValueError("a watch list with that name already exists")
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("watchlist"), str) and row["watchlist"].strip().casefold() == old_key:
                    row["watchlist"] = new_name
            self._validate_data(data)

        self._mutate(rename)

    def set_enabled(self, signature_id: str, enabled: bool) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be true or false")

        def set_value(data: dict[str, object]) -> None:
            row = self._find_rule(data, signature_id)
            row["enabled"] = enabled
            self._validate_data(data)

        self._mutate(set_value)

    def delete_rule(self, signature_id: str) -> None:
        def delete(data: dict[str, object]) -> None:
            rows = data["signatures"]
            assert isinstance(rows, list)
            target = self._find_rule(data, signature_id)
            rows.remove(target)
            self._validate_data(data)

        self._mutate(delete)

    def delete_list(self, name: str) -> None:
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError("name must be 1 to 80 characters")
        key = name.strip().casefold()

        def delete(data: dict[str, object]) -> None:
            rows = data["signatures"]
            assert isinstance(rows, list)
            kept = [row for row in rows if not (isinstance(row, dict) and isinstance(row.get("watchlist"), str)
                    and row["watchlist"].strip().casefold() == key)]
            if len(kept) == len(rows):
                raise ValueError("watch list was not found")
            data["signatures"] = kept
            self._validate_data(data)

        self._mutate(delete)

    def transaction(self, operation: Callable[[], T], *, restart: Callable[[], None]) -> T:
        """Keep a mutation and service reload serialized; restore bytes on failure."""
        with self._lock:
            original = self.path.read_bytes()
            mode = self.path.stat().st_mode & 0o777
            try:
                result = operation()
                restart()
                return result
            except BaseException:
                self._restore(original, mode)
                raise

    def _restore(self, content: bytes, mode: int) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".rollback", dir=self.path.parent)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, mode)
            os.replace(temp_path, self.path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def _find_rule(self, data: dict[str, object], signature_id: str) -> dict[str, object]:
        rows = data["signatures"]
        assert isinstance(rows, list)
        for row in rows:
            if isinstance(row, dict) and row.get("id") == signature_id:
                if not isinstance(row.get("watchlist"), str):
                    raise ValueError("built-in signatures cannot be changed here")
                return row
        raise ValueError("watch rule was not found")

    def _validate_data(self, data: dict[str, object]) -> None:
        load_signatures_from_data(data, self.path)


def load_signatures_from_data(data: dict[str, object], path: Path) -> tuple[Signature, ...]:
    serialized = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.validate.", suffix=".yaml", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(serialized)
        return load_signatures(temp_path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
