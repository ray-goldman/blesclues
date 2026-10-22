from __future__ import annotations

from dataclasses import replace
from typing import Sequence

from .config import BluetoothConfig
from .models import Signature
from .watch_filters import derived_watch_filters


def effective_bluetooth_config(config: BluetoothConfig,
                               signatures: Sequence[Signature] = ()) -> BluetoothConfig:
    """Add compatible watch filters while preserving the configured radio mode."""
    combined = tuple(dict.fromkeys((*config.or_patterns, *derived_watch_filters(signatures))))
    return replace(config, or_patterns=combined)
