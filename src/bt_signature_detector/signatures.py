from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
import re

import yaml

from .models import Advertisement, Confidence, Signature

MAX_SIGNATURE_ID_LENGTH = 128
MAX_SIGNATURE_LABEL_LENGTH = 120
MAX_CRITERION_VALUES = 32
MAX_HEX_PATTERN_BYTES = 62
MAX_NAME_UTF8_BYTES = 248
MAX_IDENTIFIER_LENGTH = 128
MAX_EVIDENCE_LENGTH = 2000


def _has_ambiguous_repetition(pattern: str) -> bool:
    """Reject nested or ambiguous repeated groups that can backtrack exponentially."""
    groups: list[dict[str, bool]] = []
    in_class = False
    escaped = False
    previous_group: dict[str, bool] | None = None
    previous_was_quantifier = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if escaped:
            escaped = False
            previous_group = None
            previous_was_quantifier = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            previous_group = None
            previous_was_quantifier = False
            index += 1
            continue
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            previous_group = None
            previous_was_quantifier = False
            index += 1
            continue
        if char == "(":
            groups.append({"repeat": False, "alternate": False})
            previous_group = None
            previous_was_quantifier = False
        elif char == ")" and groups:
            closed = groups.pop()
            if groups:
                groups[-1]["repeat"] |= closed["repeat"]
                groups[-1]["alternate"] |= closed["alternate"]
            previous_group = closed
            previous_was_quantifier = False
        elif char == "|":
            if groups:
                groups[-1]["alternate"] = True
            previous_group = None
            previous_was_quantifier = False
        else:
            quantifier_end = index
            is_quantifier = char in "*+?" and not (char == "?" and (index == 0 or pattern[index - 1] in "(*+?|"))
            if char == "{" and index + 1 < len(pattern) and pattern[index + 1].isdigit():
                close = pattern.find("}", index + 1)
                if close != -1 and re.fullmatch(r"\d+(?:,\d*)?", pattern[index + 1:close]):
                    is_quantifier = True
                    quantifier_end = close
            # A trailing ? makes a quantifier lazy; it is not a second repeat.
            if char == "?" and previous_was_quantifier:
                is_quantifier = False
            if is_quantifier:
                if (previous_group is not None and (previous_group["repeat"] or previous_group["alternate"])):
                    return True
                if groups:
                    if groups[-1]["repeat"]:
                        return True
                    groups[-1]["repeat"] = True
                previous_group = None
                previous_was_quantifier = True
                index = quantifier_end
            else:
                previous_group = None
                previous_was_quantifier = False
        index += 1
    return False


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
    if len(result) > MAX_HEX_PATTERN_BYTES:
        raise ValueError(f"{path} must be at most {MAX_HEX_PATTERN_BYTES} bytes")
    return result


def load_signatures(path: Path) -> tuple[Signature, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: unable to load signatures: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("signatures"), list):
        raise ValueError(f"{path}: expected schema_version 1 and signatures list")
    allowed = {"id", "label", "confidence", "match_mode", "manufacturer_data", "manufacturer_ids", "service_uuids", "service_data", "name_exact", "name_contains", "name_regex", "observed_identifiers", "identifier_prefixes", "min_rssi", "min_observations", "evidence", "alert_enabled", "watchlist", "enabled"}
    result = []
    seen = set()
    watchlists: dict[str, str] = {}
    for index, item in enumerate(data["signatures"]):
        prefix = f"signatures[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{prefix} must be a mapping")
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"{prefix}.{sorted(unknown)[0]} is not supported")
        identifier, label = item.get("id"), item.get("label")
        if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > MAX_SIGNATURE_ID_LENGTH or identifier in seen:
            raise ValueError(f"{prefix}.id must be a unique non-empty string of at most {MAX_SIGNATURE_ID_LENGTH} characters")
        if not isinstance(label, str) or not label.strip() or len(label) > MAX_SIGNATURE_LABEL_LENGTH:
            raise ValueError(f"{prefix}.label must be a non-empty string of at most {MAX_SIGNATURE_LABEL_LENGTH} characters")
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
        manufacturer_ids_raw = item.get("manufacturer_ids", [])
        if (not isinstance(manufacturer_ids_raw, list) or len(manufacturer_ids_raw) > MAX_CRITERION_VALUES
                or not all(not isinstance(value, bool) and isinstance(value, int) and 0 <= value <= 65535 for value in manufacturer_ids_raw)):
            raise ValueError(f"{prefix}.manufacturer_ids must be a list of at most {MAX_CRITERION_VALUES} company IDs from 0 to 65535")
        manufacturer_ids = tuple(dict.fromkeys(manufacturer_ids_raw))
        if manufacturer_ids:
            predicates.append(True)
        service_uuids_raw = item.get("service_uuids", [])
        if not isinstance(service_uuids_raw, list) or len(service_uuids_raw) > MAX_CRITERION_VALUES:
            raise ValueError(f"{prefix}.service_uuids must be a list of at most {MAX_CRITERION_VALUES} values")
        service_uuids = tuple(_uuid(value, f"{prefix}.service_uuids") for value in service_uuids_raw)
        if service_uuids:
            predicates.append(True)
        service_data_raw = item.get("service_data", {})
        if not isinstance(service_data_raw, dict) or len(service_data_raw) > MAX_CRITERION_VALUES:
            raise ValueError(f"{prefix}.service_data must be a mapping with at most {MAX_CRITERION_VALUES} entries")
        service_data = {_uuid(key, f"{prefix}.service_data key"): _hex(value, f"{prefix}.service_data.{key}") for key, value in service_data_raw.items()}
        if service_data:
            predicates.append(True)
        name_exact, name_contains, name_regex = item.get("name_exact"), item.get("name_contains"), item.get("name_regex")
        if sum(value is not None for value in (name_exact, name_contains, name_regex)) > 1:
            raise ValueError(f"{prefix} may define only one name predicate")
        name_pattern = name_exact if name_exact is not None else name_contains if name_contains is not None else name_regex
        if name_pattern is not None:
            if not isinstance(name_pattern, str) or not name_pattern or len(name_pattern.encode("utf-8")) > MAX_NAME_UTF8_BYTES:
                raise ValueError(f"{prefix} name predicate must be non-empty and at most {MAX_NAME_UTF8_BYTES} UTF-8 bytes")
            if name_regex is not None:
                try:
                    re.compile(name_regex)
                except re.error as exc:
                    raise ValueError(f"{prefix}.name_regex is invalid: {exc}") from exc
                if _has_ambiguous_repetition(name_regex):
                    raise ValueError(f"{prefix}.name_regex uses nested or ambiguous repetition; simplify it to keep scanning responsive")
            predicates.append(True)
        exact_raw = item.get("observed_identifiers", [])
        if (not isinstance(exact_raw, list) or len(exact_raw) > MAX_CRITERION_VALUES
                or not all(isinstance(value, str) and 0 < len(value) <= MAX_IDENTIFIER_LENGTH for value in exact_raw)):
            raise ValueError(f"{prefix}.observed_identifiers must contain at most {MAX_CRITERION_VALUES} non-empty strings of at most {MAX_IDENTIFIER_LENGTH} characters")
        exact_identifiers = tuple(value.lower() for value in exact_raw)
        if exact_identifiers:
            predicates.append(True)
        identifier_prefixes_raw = item.get("identifier_prefixes", [])
        if (not isinstance(identifier_prefixes_raw, list) or len(identifier_prefixes_raw) > MAX_CRITERION_VALUES
                or not all(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){0,2}[0-9a-fA-F]{2}", value) for value in identifier_prefixes_raw)):
            raise ValueError(f"{prefix}.identifier_prefixes must contain one to three complete MAC octets")
        identifier_prefixes = tuple(dict.fromkeys(value.lower() for value in identifier_prefixes_raw))
        if identifier_prefixes:
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
        watchlist = item.get("watchlist")
        if watchlist is not None:
            if not isinstance(watchlist, str):
                raise ValueError(f"{prefix}.watchlist must be a string")
            watchlist = watchlist.strip()
            if not watchlist or len(watchlist) > 80:
                raise ValueError(f"{prefix}.watchlist must be 1 to 80 characters after trimming")
            normalized_watchlist = watchlist.casefold()
            existing_name = watchlists.get(normalized_watchlist)
            if existing_name is not None:
                watchlist = existing_name
            else:
                watchlists[normalized_watchlist] = watchlist
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(f"{prefix}.enabled must be true or false")
        evidence = item.get("evidence", "")
        if not isinstance(evidence, str) or len(evidence) > MAX_EVIDENCE_LENGTH:
            raise ValueError(f"{prefix}.evidence must be a string of at most {MAX_EVIDENCE_LENGTH} characters")
        result.append(Signature(identifier, label, confidence, manufacturer_id, manufacturer_pattern, manufacturer_mask,
            service_uuids, service_data, name_pattern,
            "regex" if name_regex is not None else "contains" if name_contains is not None else "exact",
            exact_identifiers, min_rssi, observations, mode, evidence, alert_enabled, watchlist, enabled,
            identifier_prefixes, manufacturer_ids))
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
    if signature.manufacturer_ids:
        checks.append(any(company_id in advertisement.manufacturer_data for company_id in signature.manufacturer_ids))
    if signature.service_uuids:
        observed_uuids = {_uuid(value, "advertisement.service_uuids") for value in advertisement.service_uuids}
        checks.append(bool(observed_uuids.intersection(signature.service_uuids)))
    for uuid, pattern in signature.service_data.items():
        observed = advertisement.service_data.get(uuid)
        checks.append(observed is not None and observed.startswith(pattern))
    if signature.name_pattern is not None:
        name = advertisement.name or ""
        if signature.name_mode == "regex":
            checks.append(re.search(signature.name_pattern, name) is not None)
        else:
            checks.append(name == signature.name_pattern if signature.name_mode == "exact" else signature.name_pattern.casefold() in name.casefold())
    if signature.exact_identifiers:
        checks.append(advertisement.identifier.lower() in signature.exact_identifiers)
    if signature.identifier_prefixes:
        identifier = advertisement.identifier.lower()
        checks.append(any(identifier.startswith(prefix) for prefix in signature.identifier_prefixes))
    return bool(checks) and (all(checks) if signature.match_mode == "all" else any(checks))
