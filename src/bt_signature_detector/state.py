from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Sequence

from .models import Advertisement, DetectionEvent, Signature


@dataclass(slots=True)
class _ObservationState:
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    strongest_rssi: int | None = None
    last_alert: datetime | None = None


class DetectionFilter:
    def __init__(self, *, cooldown_seconds: int = 300, absence_seconds: int = 120,
                 global_min_rssi: int | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.absence = timedelta(seconds=absence_seconds)
        self.global_min_rssi = global_min_rssi
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._states: dict[tuple[str, str], _ObservationState] = {}

    def observe(self, advertisement: Advertisement, matches: Sequence[Signature]) -> list[DetectionEvent]:
        now = self.clock()
        events: list[DetectionEvent] = []
        for signature in matches:
            key = (signature.signature_id, advertisement.identifier)
            state = self._states.get(key)
            if state is None or now - state.last_seen > self.absence:
                state = _ObservationState(advertisement.timestamp, advertisement.timestamp)
                self._states[key] = state
            state.last_seen = advertisement.timestamp
            threshold = max(-127 if self.global_min_rssi is None else self.global_min_rssi,
                            signature.min_rssi if signature.min_rssi is not None else -127)
            if advertisement.rssi is None or advertisement.rssi < threshold:
                continue
            state.count += 1
            if state.strongest_rssi is None or advertisement.rssi > state.strongest_rssi:
                state.strongest_rssi = advertisement.rssi
            minimum = max(3, signature.min_observations)
            if state.count < minimum or (state.last_alert is not None and now - state.last_alert < self.cooldown):
                continue
            state.last_alert = now
            events.append(DetectionEvent(signature.signature_id, signature.name, signature.confidence,
                advertisement.identifier, state.first_seen, advertisement.timestamp,
                state.strongest_rssi, state.count, alert_enabled=signature.alert_enabled))
        return events

    def expire(self, now: datetime) -> int:
        expired = [key for key, state in self._states.items() if now - state.last_seen > self.absence]
        for key in expired:
            del self._states[key]
        return len(expired)
