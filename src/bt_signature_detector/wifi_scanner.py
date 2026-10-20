"""Non-associating Wi-Fi discovery and built-in rule matching."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
import subprocess
from typing import Callable, Sequence

from .builtin_rules import BuiltInRule


@dataclass(frozen=True, slots=True)
class WifiObservation:
    ssid: str
    bssid: str
    signal: int | None
    channel: int | None
    security: str | None
    observed_at: datetime


def _unescape_nmcli(value: str) -> str:
    return re.sub(r"\\([\\:n])", lambda match: {"\\": "\\", ":": ":", "n": "\n"}[match.group(1)], value)


def _channel_for_frequency(freq: int) -> int | None:
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472 and (freq - 2407) % 5 == 0:
        return (freq - 2407) // 5
    if 5000 <= freq < 5900 and freq % 5 == 0:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115 and (freq - 5950) % 5 == 0:
        return (freq - 5950) // 5
    return None


def parse_iw_scan(output: str, *, observed_at: datetime | None = None) -> tuple[WifiObservation, ...]:
    if not isinstance(output, str):
        raise ValueError("scan output must be text")
    stamp = observed_at or datetime.now(timezone.utc)
    rows: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSS "):
            if current:
                rows.append(current)
            match = re.match(r"BSS\s+([0-9A-Fa-f:]{17})", stripped)
            current = {"BSSID": match.group(1).upper()} if match else {}
        elif current is not None:
            if stripped.startswith("SSID:"):
                current["SSID"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("freq:"):
                current["FREQ"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("signal:"):
                current["SIGNAL"] = stripped.split(":", 1)[1].strip().split()[0]
            elif stripped.startswith(("RSN:", "WPA:")):
                current["SECURITY"] = "WPA"
            elif "Privacy" in stripped:
                current.setdefault("SECURITY", "WEP")
    if current:
        rows.append(current)
    if output.strip() and not rows:
        raise ValueError("scan output did not contain valid iw BSS records")
    observations = []
    for row in rows:
        bssid = row.get("BSSID", "").upper()
        if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", bssid):
            continue
        try:
            signal = round(float(row["SIGNAL"])) if row.get("SIGNAL") else None
            frequency_value = float(row["FREQ"]) if row.get("FREQ") else None
            if frequency_value is not None and not frequency_value.is_integer():
                continue
            frequency = int(frequency_value) if frequency_value is not None else None
            channel = _channel_for_frequency(frequency) if frequency is not None else None
        except (ValueError, OverflowError):
            continue
        if signal is not None and not -127 <= signal <= 0:
            continue
        if frequency is not None and channel is None:
            continue
        observations.append(WifiObservation(row.get("SSID", ""), bssid, signal, channel,
            row.get("SECURITY") or None, stamp))
    return tuple(observations)


def scan_wifi(*, runner: Callable = subprocess.run, interface: str = "wlan0") -> tuple[WifiObservation, ...]:
    """Request an active 802.11 scan; never associate, authenticate, or inject frames."""
    command = ["iw", "dev", interface, "scan"]
    result = runner(command, capture_output=True, text=True, timeout=25, check=False)
    if result.returncode:
        detail = (result.stderr or "").strip()[:300]
        raise RuntimeError(f"Wi-Fi scan failed (exit {result.returncode})" + (f": {detail}" if detail else ""))
    return parse_iw_scan(result.stdout)


def _global_bssid(value: str) -> str | None:
    if not re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", value):
        return None
    canonical = value.upper()
    if int(canonical[:2], 16) & 0x02:
        return None
    return canonical


def match_wifi_rules(rules: Sequence[BuiltInRule], observation: WifiObservation) -> tuple[BuiltInRule, ...]:
    bssid = _global_bssid(observation.bssid)
    matches = []
    for rule in rules:
        if rule.protocol != "wifi":
            continue
        if rule.match_type == "bssid_prefix" and bssid:
            if bssid.replace(":", "").startswith(rule.pattern.replace(":", "").replace("-", "").upper()):
                matches.append(rule)
        elif rule.match_type == "ssid_regex" and observation.ssid and re.search(rule.pattern, observation.ssid):
            matches.append(rule)
    return tuple(matches)
