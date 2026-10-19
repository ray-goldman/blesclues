"""Score built-in sightings with a volatile, site-level cross-protocol window.

The window only indicates that BLE and Wi-Fi rules were both observed nearby
in time. It is a heuristic for prioritization, not proof of a shared device or
identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from contextlib import contextmanager

from .builtin_rules import BuiltInRule, BuiltinScoringSettings, load_builtin_scoring


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule: BuiltInRule
    protocol: str
    observed_identifier: str
    observed_name: str | None
    observed_ssid: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        if self.protocol not in {"ble", "wifi"} or self.rule.protocol != self.protocol:
            raise ValueError("hit protocol must match its built-in rule")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("hit timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ScoredHit:
    hit: RuleHit
    base_score: int
    correlation_bonus: int
    effective_score: int
    qualifies: bool


class CrossProtocolScorer:
    """Score sightings using a bounded, shared SQLite database in volatile storage."""

    def __init__(self, *, settings: BuiltinScoringSettings | None = None,
                 db_path: Path = Path("/run/bt-signature-detector/correlation.sqlite3"),
                 max_rows: int = 256) -> None:
        self.settings = settings or load_builtin_scoring()
        self.db_path = Path(db_path)
        self.max_rows = max_rows
        self._lock = threading.Lock()
        if max_rows < 2:
            raise ValueError("max_rows must be at least two")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS hits (observed_at REAL NOT NULL, protocol TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS hits_time ON hits(observed_at DESC)")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def observe(self, hit: RuleHit) -> ScoredHit:
        stamp = hit.observed_at.astimezone(timezone.utc).timestamp()
        cutoff = stamp - self.settings.correlation_window_seconds
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM hits WHERE observed_at < ?", (cutoff,))
            opposite = "wifi" if hit.protocol == "ble" else "ble"
            correlated = db.execute(
                "SELECT 1 FROM hits WHERE protocol = ? AND observed_at >= ? AND observed_at <= ? LIMIT 1",
                (opposite, cutoff, stamp),
            ).fetchone() is not None
            db.execute("INSERT INTO hits(observed_at, protocol) VALUES (?, ?)", (stamp, hit.protocol))
            db.execute("DELETE FROM hits WHERE rowid IN (SELECT rowid FROM hits ORDER BY observed_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
                       (self.max_rows,))
        bonus = self.settings.correlation_bonus if correlated else 0
        effective = min(100, hit.rule.score + bonus)
        return ScoredHit(hit, hit.rule.score, bonus, effective, effective >= self.settings.alert_threshold)
