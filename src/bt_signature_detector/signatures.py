from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
import re

import yaml

from .models import Advertisement, Confidence, Signature


def _uuid(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a UUID string")
    compact = value.lower().replace("-", "")
    if not re.fullmatch(r"(?:[0-9a-f]{4}|[0-9a-f]{8}|[0-9a-f]{32})", compact):
        raise ValueError(f"{path} must be a 16, 32, or 128-bit UUID")
    if len(compact) == 4:
        compact = "0000" + compact
    if len(compact) == 8:
        compact += "00001000800000805f9b34fb"
    return f"{compact[:8]}-{compact[8:12]}-{compact[12:16]}-{compact[16:20]}-{compact[20:]}"


def _hex(value: object, path: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a hexadecimal string")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{path} must be a hexadecimal string") from exc
    if not result:
        raise ValueError(f"{path} must not be empty")
    return result


def load_signatures(path: Path) -> tuple[Signature, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: unable to load signatures: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("signatures"), list):
        raise ValueError(f"{path}: expected schema_version 1 and signatures list")
    allowed = {"id", "label", "confidence", "match_mode", "manufacturer_data", "service_uuids", "service_data", "name_exact", "name_contains", "observed_identifiers", "min_rssi", "min_observations", "evidence", "alert_enabled"}
    result = []
    seen = set()
    for index, item in enumerate(data["signatures"]):
        prefix = f"signatures[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{prefix} must be a mapping")
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"{prefix}.{sorted(unknown)[0]} is not supported")
        identifier, label = item.get("id"), item.get("label")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in seen:
            raise ValueError(f"{prefix}.id must be a unique non-empty string")
        if not isinstance(label, str) or not label.strip():
            raise ValueError(f"{prefix}.label must be a non-empty string")
        seen.add(identifier)
        mode = item.get("match_mode", "all")
        if mode not in {"all", "any"}:
            raise ValueError(f"{prefix}.match_mode must be all or any")
        predicates = []
        manufacturer_id = None
        manufacturer_pattern = manufacturer_mask = None
        raw_manufacturer = item.get("manufacturer_data", {})
        if not isinstance(raw_manufacturer, dict):
            raise ValueError(f"{prefix}.manufacturer_data must be a mapping")
        if len(raw_manufacturer) > 1:
            raise ValueError(f"{prefix}.manufacturer_data supports one company identifier per signature")
        for key, value in raw_manufacturer.items():
            try:
                manufacturer_id = int(key)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{prefix}.manufacturer_data key must be a company identifier") from exc
            if not 0 <= manufacturer_id <= 65535:
                raise ValueError(f"{prefix}.manufacturer_data key is out of range")
            if isinstance(value, str):
                manufacturer_pattern = _hex(value, f"{prefix}.manufacturer_data.{key}")
            elif isinstance(value, dict) and set(value) <= {"pattern", "mask"} and "pattern" in value:
                manufacturer_pattern = _hex(value["pattern"], f"{prefix}.manufacturer_data.{key}.pattern")
                manufacturer_mask = _hex(value["mask"], f"{prefix}.manufacturer_data.{key}.mask") if "mask" in value else None
                if manufacturer_mask is not None and len(manufacturer_mask) != len(manufacturer_pattern):
                    raise ValueError(f"{prefix}.manufacturer_data.{key}.mask must match pattern length")
            else:
                raise ValueError(f"{prefix}.manufacturer_data.{key} must be hex or pattern/mask mapping")
            predicates.append(True)
        service_uuids_raw = item.get("service_uuids", [])
        if not isinstance(service_uuids_raw, list):
            raise ValueError(f"{prefix}.service_uuids must be a list")
        service_uuids = tuple(_uuid(value, f"{prefix}.service_uuids") for value in service_uuids_raw)
        if service_uuids:
            predicates.append(True)
        service_data_raw = item.get("service_data", {})
        if not isinstance(service_data_raw, dict):
            raise ValueError(f"{prefix}.service_data must be a mapping")
        service_data = {_uuid(key, f"{prefix}.service_data key"): _hex(value, f"{prefix}.service_data.{key}") for key, value in service_data_raw.items()}
        if service_data:
            predicates.append(True)
        name_exact, name_contains = item.get("name_exact"), item.get("name_contains")
        if name_exact is not None and name_contains is not None:
            raise ValueError(f"{prefix} may define only one of name_exact and name_contains")
        name_pattern = name_exact if name_exact is not None else name_contains
        if name_pattern is not None:
            if not isinstance(name_pattern, str) or not name_pattern:
                raise ValueError(f"{prefix} name predicate must be a non-empty string")
            predicates.append(True)
        exact_raw = item.get("observed_identifiers", [])
        if not isinstance(exact_raw, list) or not all(isinstance(value, str) and value for value in exact_raw):
            raise ValueError(f"{prefix}.observed_identifiers must be a list of non-empty strings")
        exact_identifiers = tuple(value.lower() for value in exact_raw)
        if exact_identifiers:
            predicates.append(True)
        if not predicates:
            raise ValueError(f"{prefix} must define at least one predicate")
        confidence_raw = item.get("confidence", "unknown")
        try:
            confidence = Confidence(confidence_raw)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{prefix}.confidence is invalid") from exc
        min_rssi = item.get("min_rssi")
        if min_rssi is not None and (isinstance(min_rssi, bool) or not isinstance(min_rssi, int) or not -127 <= min_rssi <= 20):
            raise ValueError(f"{prefix}.min_rssi must be from -127 to 20")
        observations = item.get("min_observations", 3)
        if isinstance(observations, bool) or not isinstance(observations, int) or observations < 3:
            raise ValueError(f"{prefix}.min_observations must be at least 3")
        alert_enabled = item.get("alert_enabled", False)
        if not isinstance(alert_enabled, bool): raise ValueError(f"{prefix}.alert_enabled must be true or false")
        evidence = item.get("evidence", "")
        if not isinstance(evidence, str): raise ValueError(f"{prefix}.evidence must be a string")
        result.append(Signature(identifier, label, confidence, manufacturer_id, manufacturer_pattern, manufacturer_mask, service_uuids, service_data, name_pattern, "contains" if name_contains is not None else "exact", exact_identifiers, min_rssi, observations, mode, evidence, alert_enabled))
    return tuple(result)


def match_signature(signature: Signature, advertisement: Advertisement) -> bool:
    checks = []
    if signature.manufacturer_id is not None and signature.manufacturer_pattern is not None:
        observed = advertisement.manufacturer_data.get(signature.manufacturer_id)
        if observed is None or len(observed) < len(signature.manufacturer_pattern):
            checks.append(False)
        else:
            mask = signature.manufacturer_mask or bytes([255]) * len(signature.manufacturer_pattern)
            checks.append(all((a & m) == (p & m) for a, p, m in zip(observed, signature.manufacturer_pattern, mask)))
    if signature.service_uuids:
        observed_uuids = {_uuid(value, "advertisement.service_uuids") for value in advertisement.service_uuids}
        checks.append(bool(observed_uuids.intersection(signature.service_uuids)))
    for uuid, pattern in signature.service_data.items():
        observed = advertisement.service_data.get(uuid)
        checks.append(observed is not None and observed.startswith(pattern))
    if signature.name_pattern is not None:
        name = advertisement.name or ""
        checks.append(name == signature.name_pattern if signature.name_mode == "exact" else signature.name_pattern.casefold() in name.casefold())
    if signature.exact_identifiers:
        checks.append(advertisement.identifier.lower() in signature.exact_identifiers)
    return bool(checks) and (all(checks) if signature.match_mode == "all" else any(checks))
