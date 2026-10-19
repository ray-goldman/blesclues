from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
import io
import json
import re
from importlib.resources import files


MAX_RULES = 256
MAX_REGEX_LENGTH = 256
CONFIDENCE_SCORE = {"high": 40, "medium": 25, "low": 10}
VALID_PROTOCOLS = {"ble", "wifi"}
VALID_MATCH_TYPES = {"mac_prefix", "name_regex", "bssid_prefix", "ssid_regex"}


@dataclass(frozen=True, slots=True)
class BuiltinScoringSettings:
    alert_threshold: int
    correlation_window_seconds: int
    correlation_bonus: int


@dataclass(frozen=True, slots=True)
class BuiltInRule:
    rule_id: str
    protocol: str
    vendor: str
    match_type: str
    pattern: str
    confidence: str
    score: int
    source: str
    notes: str
    device_class: tuple[str, ...] = ()
    relevance: str | None = None
    false_positives: tuple[str, ...] = ()


def parse_scoring_settings(signatures_json: str) -> BuiltinScoringSettings:
    try:
        data = json.loads(signatures_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("signatures.json must contain valid JSON") from exc
    scoring = data.get("scoring") if isinstance(data, dict) else None
    if not isinstance(scoring, dict):
        raise ValueError("signatures.json scoring must be a mapping")
    values = (
        scoring.get("alert_threshold"),
        scoring.get("correlation_window_sec"),
        scoring.get("correlation_bonus"),
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("scoring threshold, window, and bonus must be integers")
    threshold, window, bonus = values
    if not 1 <= threshold <= 100 or not 1 <= window <= 3600 or not 0 <= bonus <= 100:
        raise ValueError("scoring values are outside supported bounds")
    return BuiltinScoringSettings(threshold, window, bonus)


def _canonical_oui(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}", value.strip()):
        raise ValueError("OUI must contain exactly three hexadecimal octets")
    return value.strip().upper()


def _validate_rule(rule: BuiltInRule) -> BuiltInRule:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", rule.rule_id):
        raise ValueError("built-in rule ID is invalid")
    if rule.protocol not in VALID_PROTOCOLS or rule.match_type not in VALID_MATCH_TYPES:
        raise ValueError("built-in rule protocol or match type is invalid")
    if (rule.protocol, rule.match_type) not in {
        ("ble", "mac_prefix"), ("ble", "name_regex"),
        ("wifi", "bssid_prefix"), ("wifi", "ssid_regex"),
    }:
        raise ValueError("built-in rule match type does not match its protocol")
    if not isinstance(rule.vendor, str) or not rule.vendor.strip() or len(rule.vendor) > 120:
        raise ValueError("built-in rule vendor is invalid")
    if rule.match_type in {"mac_prefix", "bssid_prefix"}:
        _canonical_oui(rule.pattern)
    else:
        if not isinstance(rule.pattern, str) or not rule.pattern or len(rule.pattern) > MAX_REGEX_LENGTH:
            raise ValueError("built-in regex must be non-empty and at most 256 characters")
        try:
            re.compile(rule.pattern)
        except re.error as exc:
            raise ValueError(f"built-in regex is invalid: {exc}") from exc
    if rule.confidence not in {"high", "medium", "low"}:
        raise ValueError("built-in rule confidence is invalid")
    if isinstance(rule.score, bool) or not isinstance(rule.score, int) or not 1 <= rule.score <= 100:
        raise ValueError("built-in rule score must be from 1 to 100")
    if not isinstance(rule.source, str) or not rule.source or not isinstance(rule.notes, str):
        raise ValueError("built-in rule source metadata is invalid")
    if len(rule.source) > 500 or len(rule.notes) > 2000:
        raise ValueError("built-in rule source metadata is too long")
    if rule.relevance is not None and rule.relevance not in {"high", "medium", "low"}:
        raise ValueError("built-in rule relevance is invalid")
    if (not isinstance(rule.device_class, tuple) or not all(isinstance(value, str) for value in rule.device_class)
            or not isinstance(rule.false_positives, tuple) or not all(isinstance(value, str) for value in rule.false_positives)):
        raise ValueError("built-in rule metadata lists are invalid")
    if len(rule.device_class) > 16 or len(rule.false_positives) > 16:
        raise ValueError("built-in rule metadata has too many entries")
    return rule


def _normal_pattern(match_type: str, pattern: str) -> str:
    if match_type in {"mac_prefix", "bssid_prefix"}:
        return _canonical_oui(pattern)
    value = pattern.strip()
    return value.lower() if value.startswith("(?i)") else value


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    return slug[:96] or "rule"


def _add_or_merge(rules: dict[tuple[str, str, str], BuiltInRule], rule: BuiltInRule, *, explicit_score: bool = False) -> None:
    rule = _validate_rule(rule)
    key = (rule.protocol, rule.match_type, _normal_pattern(rule.match_type, rule.pattern))
    previous = rules.get(key)
    if previous is None:
        rules[key] = rule
        return
    sources = list(dict.fromkeys([*previous.source.split("; "), *rule.source.split("; ")]))
    notes = list(dict.fromkeys(note for note in (previous.notes, rule.notes) if note))
    class_names = tuple(dict.fromkeys((*previous.device_class, *rule.device_class)))
    false_positives = tuple(dict.fromkeys((*previous.false_positives, *rule.false_positives)))
    score = previous.score if "signatures.json" in previous.source or not explicit_score else rule.score
    if "signatures.json" in rule.source:
        score = rule.score
    confidence = rule.confidence if rule.source != "signatures.json" else previous.confidence
    rules[key] = BuiltInRule(
        rule_id=previous.rule_id,
        protocol=previous.protocol,
        vendor=previous.vendor if previous.vendor != "Unknown" else rule.vendor,
        match_type=previous.match_type,
        pattern=previous.pattern,
        confidence=confidence,
        score=score,
        source="; ".join(sources),
        notes="; ".join(notes),
        device_class=class_names,
        relevance=previous.relevance or rule.relevance,
        false_positives=false_positives,
    )


def _signature_rules(source: str) -> tuple[list[BuiltInRule], set[tuple[str, str, str]]]:
    try:
        data = json.loads(source)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("signatures.json must contain valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("signatures"), list):
        raise ValueError("signatures.json must contain a signatures list")
    rules: list[BuiltInRule] = []
    explicit: set[tuple[str, str, str]] = set()
    if len(data["signatures"]) > MAX_RULES:
        raise ValueError("signatures.json has too many rules")
    for index, row in enumerate(data["signatures"]):
        if not isinstance(row, dict):
            raise ValueError(f"signatures[{index}] must be an object")
        protocol, vendor, criteria = row.get("protocol"), row.get("vendor"), row.get("match")
        if protocol not in VALID_PROTOCOLS or not isinstance(vendor, str) or not isinstance(criteria, dict) or len(criteria) != 1:
            raise ValueError(f"signatures[{index}] has invalid protocol, vendor, or match")
        key, pattern = next(iter(criteria.items()))
        match_type = {"mac_prefix": "mac_prefix" if protocol == "ble" else "bssid_prefix",
                      "bssid_prefix": "bssid_prefix", "name_regex": "name_regex", "ssid_regex": "ssid_regex"}.get(key)
        if not isinstance(pattern, str):
            raise ValueError(f"signatures[{index}] pattern must be a string")
        score = row.get("score")
        if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 100:
            raise ValueError(f"signatures[{index}] score must be from 1 to 100")
        confidence = row.get("confidence", "high" if score >= 40 else "medium" if score >= 25 else "low")
        device_class = row.get("device_class", [])
        false_positives = row.get("false_positives", [])
        if not isinstance(device_class, list) or not all(isinstance(value, str) for value in device_class):
            raise ValueError(f"signatures[{index}] device_class must be a list of strings")
        if not isinstance(false_positives, list) or not all(isinstance(value, str) for value in false_positives):
            raise ValueError(f"signatures[{index}] false_positives must be a list of strings")
        rule = BuiltInRule(
            rule_id=str(row.get("id", "")), protocol=protocol, vendor=vendor,
            match_type=match_type or "", pattern=pattern, confidence=confidence, score=score,
            source="signatures.json", notes="", device_class=tuple(device_class),
            relevance=row.get("speed_trap_relevance"), false_positives=tuple(false_positives),
        )
        validated = _validate_rule(rule)
        key_tuple = (validated.protocol, validated.match_type, _normal_pattern(validated.match_type, validated.pattern))
        explicit.add(key_tuple)
        rules.append(validated)
    return rules, explicit


def _tab_rules(source: str, *, protocol: str, filename: str) -> list[BuiltInRule]:
    rules = []
    for line_number, line in enumerate(source.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        columns = line.split("\t", 3)
        if len(columns) != 4:
            raise ValueError(f"{filename}:{line_number} must have four tab-separated columns")
        pattern, vendor, confidence, notes = (value.strip() for value in columns)
        if confidence not in CONFIDENCE_SCORE:
            raise ValueError(f"{filename}:{line_number} confidence is invalid")
        match_type = "name_regex" if protocol == "ble" else "ssid_regex"
        rules.append(_validate_rule(BuiltInRule(
            rule_id=_slug(f"{vendor}_{match_type}_{pattern}"), protocol=protocol, vendor=vendor,
            match_type=match_type, pattern=pattern, confidence=confidence,
            score=CONFIDENCE_SCORE[confidence], source=filename, notes=notes,
        )))
    return rules


def _oui_rules(source: str) -> list[BuiltInRule]:
    reader = csv.DictReader(io.StringIO(source))
    required = {"oui", "vendor", "protocol", "device_class", "confidence", "speed_trap_relevance", "notes", "source"}
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        raise ValueError("ouis.csv is missing required columns")
    rules = []
    for line_number, row in enumerate(reader, 2):
        protocol = row["protocol"].strip().lower()
        if protocol not in VALID_PROTOCOLS:
            raise ValueError(f"ouis.csv:{line_number} protocol is invalid")
        confidence = row["confidence"].strip().lower()
        if confidence not in CONFIDENCE_SCORE:
            raise ValueError(f"ouis.csv:{line_number} confidence is invalid")
        match_type = "mac_prefix" if protocol == "ble" else "bssid_prefix"
        pattern = _canonical_oui(row["oui"])
        classes = tuple(value for value in row["device_class"].split("|") if value)
        rules.append(_validate_rule(BuiltInRule(
            rule_id=_slug(f"{row['vendor']}_{protocol}_{pattern}"), protocol=protocol,
            vendor=row["vendor"].strip(), match_type=match_type, pattern=pattern,
            confidence=confidence, score=CONFIDENCE_SCORE[confidence], source=f"ouis.csv:{row['source'].strip()}",
            notes=row["notes"].strip(), device_class=classes,
            relevance=row["speed_trap_relevance"].strip() or None,
        )))
    return rules


def parse_source_catalog(signatures_json: str, ssid_patterns: str,
                         ble_name_patterns: str, ouis_csv: str) -> tuple[BuiltInRule, ...]:
    signatures, explicit = _signature_rules(signatures_json)
    merged: dict[tuple[str, str, str], BuiltInRule] = {}
    for rule in signatures:
        _add_or_merge(merged, rule, explicit_score=True)
    for rule in _tab_rules(ssid_patterns, protocol="wifi", filename="ssid_patterns.txt"):
        _add_or_merge(merged, rule, explicit_score=(rule.protocol, rule.match_type, _normal_pattern(rule.match_type, rule.pattern)) in explicit)
    for rule in _tab_rules(ble_name_patterns, protocol="ble", filename="ble_name_patterns.txt"):
        _add_or_merge(merged, rule, explicit_score=(rule.protocol, rule.match_type, _normal_pattern(rule.match_type, rule.pattern)) in explicit)
    for rule in _oui_rules(ouis_csv):
        _add_or_merge(merged, rule, explicit_score=(rule.protocol, rule.match_type, _normal_pattern(rule.match_type, rule.pattern)) in explicit)
    if len(merged) > MAX_RULES:
        raise ValueError("built-in rule catalog has too many rules")
    return tuple(sorted(merged.values(), key=lambda rule: rule.rule_id))


def parse_normalized_catalog(source: str) -> tuple[tuple[BuiltInRule, ...], BuiltinScoringSettings]:
    try:
        data = json.loads(source)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("normalized built-in catalog must contain valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list) or not isinstance(data.get("scoring"), dict):
        raise ValueError("normalized built-in catalog must contain rules and scoring")
    settings = parse_scoring_settings(json.dumps({"scoring": data["scoring"]}))
    if len(data["rules"]) > MAX_RULES:
        raise ValueError("normalized built-in catalog has too many rules")
    parsed = []
    seen: set[tuple[str, str, str]] = set()
    for index, row in enumerate(data["rules"]):
        if not isinstance(row, dict):
            raise ValueError(f"rules[{index}] must be an object")
        try:
            rule = BuiltInRule(
                rule_id=row["rule_id"], protocol=row["protocol"], vendor=row["vendor"],
                match_type=row["match_type"], pattern=row["pattern"], confidence=row["confidence"],
                score=row["score"], source=row["source"], notes=row["notes"],
                device_class=tuple(row.get("device_class", ())), relevance=row.get("relevance"),
                false_positives=tuple(row.get("false_positives", ())),
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"rules[{index}] has invalid fields") from exc
        _validate_rule(rule)
        key = (rule.protocol, rule.match_type, _normal_pattern(rule.match_type, rule.pattern))
        if key in seen:
            raise ValueError("normalized built-in catalog contains duplicate predicates")
        seen.add(key)
        parsed.append(rule)
    return tuple(parsed), settings


def load_builtin_rules() -> tuple[BuiltInRule, ...]:
    source = files("bt_signature_detector").joinpath("data/default_detection_rules.json").read_text(encoding="utf-8")
    rules, _settings = parse_normalized_catalog(source)
    return rules


def load_builtin_scoring() -> BuiltinScoringSettings:
    source = files("bt_signature_detector").joinpath("data/default_detection_rules.json").read_text(encoding="utf-8")
    _rules, settings = parse_normalized_catalog(source)
    return settings


def catalog_as_json(rules: tuple[BuiltInRule, ...], scoring: BuiltinScoringSettings) -> str:
    scoring_data = {
        "alert_threshold": scoring.alert_threshold,
        "correlation_window_sec": scoring.correlation_window_seconds,
        "correlation_bonus": scoring.correlation_bonus,
    }
    return json.dumps({"scoring": scoring_data, "rules": [asdict(rule) for rule in rules]}, ensure_ascii=False, indent=2) + "\n"
