from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from uuid import uuid4


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Advertisement:
    identifier: str
    name: str | None = None
    manufacturer_data: Mapping[int, bytes] = field(default_factory=dict)
    service_uuids: tuple[str, ...] = ()
    service_data: Mapping[str, bytes] = field(default_factory=dict)
    rssi: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("advertisement timestamp must be timezone-aware")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(timezone.utc))
        object.__setattr__(self, "manufacturer_data", MappingProxyType(dict(self.manufacturer_data)))
        object.__setattr__(self, "service_data", MappingProxyType(dict(self.service_data)))
        object.__setattr__(self, "service_uuids", tuple(self.service_uuids))


@dataclass(frozen=True, slots=True)
class Signature:
    signature_id: str
    name: str
    confidence: Confidence
    manufacturer_id: int | None = None
    manufacturer_pattern: bytes | None = None
    manufacturer_mask: bytes | None = None
    service_uuids: tuple[str, ...] = ()
    service_data: Mapping[str, bytes] = field(default_factory=dict)
    name_pattern: str | None = None
    name_mode: str = "exact"
    exact_identifiers: tuple[str, ...] = ()
    min_rssi: int | None = None
    min_observations: int = 3
    match_mode: str = "all"
    evidence: str = ""
    alert_enabled: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_uuids", tuple(self.service_uuids))
        object.__setattr__(self, "service_data", MappingProxyType(dict(self.service_data)))
        object.__setattr__(self, "exact_identifiers", tuple(self.exact_identifiers))


@dataclass(frozen=True, slots=True)
class Match:
    signature: Signature


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    signature_id: str
    signature_name: str
    confidence: Confidence
    observed_identifier: str
    first_seen: datetime
    last_seen: datetime
    strongest_rssi: int | None
    observation_count: int
    event_id: str = field(default_factory=lambda: str(uuid4()))
    alert_enabled: bool = False

    def __post_init__(self) -> None:
        for field_name in ("first_seen", "last_seen"):
            value = getattr(self, field_name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field_name} must be timezone-aware")
            object.__setattr__(self, field_name, value.astimezone(timezone.utc))

