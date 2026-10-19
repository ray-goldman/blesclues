from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Sequence

from .config import BluetoothConfig
from .models import Signature
from .watch_filters import derived_watch_filters


def effective_bluetooth_config(config: BluetoothConfig, *, override_file: Path,
                               signatures: Sequence[Signature] = ()) -> BluetoothConfig:
    """Apply the temporary browser override without changing saved settings."""
    combined = tuple(dict.fromkeys((*config.or_patterns, *derived_watch_filters(signatures))))
    try:
        state = json.loads(Path(override_file).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return replace(config, or_patterns=combined)
    if isinstance(state, dict) and state.get("mode") == "active":
        return replace(config, scan_mode="active", or_patterns=())
    return replace(config, or_patterns=combined)
