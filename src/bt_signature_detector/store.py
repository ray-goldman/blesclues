from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from contextlib import contextmanager

from .models import Confidence, DetectionEvent


class EventStore:
    def __init__(self, path: Path, *, retention_days: int = 30, max_events: int = 10000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.max_events = max_events
        self._writes_since_prune = 0
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS detections (
                event_id TEXT PRIMARY KEY, signature_id TEXT NOT NULL, signature_name TEXT NOT NULL,
                confidence TEXT NOT NULL, observed_identifier TEXT NOT NULL, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, strongest_rssi INTEGER, observation_count INTEGER NOT NULL)""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(detections)")}
            if "watchlist_name" not in columns:
                db.execute("ALTER TABLE detections ADD COLUMN watchlist_name TEXT")
            metadata_columns = {
                "protocol": "TEXT", "vendor": "TEXT", "base_score": "INTEGER",
                "correlation_bonus": "INTEGER", "effective_score": "INTEGER",
                "source_note": "TEXT", "observed_name": "TEXT", "observed_ssid": "TEXT",
            }
            for name, column_type in metadata_columns.items():
                if name not in columns:
                    db.execute(f"ALTER TABLE detections ADD COLUMN {name} {column_type}")
            db.execute("CREATE INDEX IF NOT EXISTS detections_last_seen ON detections(last_seen DESC)")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def record(self, event: DetectionEvent) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO detections (event_id, signature_id, signature_name, confidence, observed_identifier, first_seen, last_seen, strongest_rssi, observation_count, watchlist_name, protocol, vendor, base_score, correlation_bonus, effective_score, source_note, observed_name, observed_ssid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                event.event_id, event.signature_id, event.signature_name, event.confidence.value,
                event.observed_identifier, event.first_seen.isoformat(), event.last_seen.isoformat(),
                event.strongest_rssi, event.observation_count, event.watchlist_name, event.protocol,
                event.vendor, event.base_score, event.correlation_bonus, event.effective_score,
                event.source_note, event.observed_name, event.observed_ssid))
        self._writes_since_prune += 1
        if self._writes_since_prune >= 100:
            self.prune(datetime.now(timezone.utc))
            self._writes_since_prune = 0

    def recent(self, limit: int = 100) -> list[DetectionEvent]:
        if limit < 0:
            raise ValueError("limit must not be negative")
        with self._connect() as db:
            rows = db.execute("SELECT * FROM detections ORDER BY last_seen DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [DetectionEvent(row["signature_id"], row["signature_name"], Confidence(row["confidence"]),
            row["observed_identifier"], datetime.fromisoformat(row["first_seen"]), datetime.fromisoformat(row["last_seen"]),
            row["strongest_rssi"], row["observation_count"], row["event_id"], watchlist_name=row["watchlist_name"],
            protocol=row["protocol"], vendor=row["vendor"], base_score=row["base_score"],
            correlation_bonus=row["correlation_bonus"], effective_score=row["effective_score"],
            source_note=row["source_note"], observed_name=row["observed_name"], observed_ssid=row["observed_ssid"]) for row in rows]

    def prune(self, now: datetime) -> int:
        cutoff = (now - timedelta(days=self.retention_days)).isoformat()
        with self._connect() as db:
            before = db.total_changes
            db.execute("DELETE FROM detections WHERE last_seen < ?", (cutoff,))
            db.execute("DELETE FROM detections WHERE event_id IN (SELECT event_id FROM detections ORDER BY last_seen DESC, rowid DESC LIMIT -1 OFFSET ?)", (self.max_events,))
            return db.total_changes - before
