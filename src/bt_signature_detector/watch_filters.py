from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .config import OrPatternConfig
from .models import Signature


@dataclass(frozen=True, slots=True)
class RuleFilterCoverage:
    status: str
    patterns: tuple[OrPatternConfig, ...]


def _uuid_ad_bytes(value: str) -> tuple[int, bytes] | None:
    compact = value.replace("-", "").lower()
    suffix = "00001000800000805f9b34fb"
    if len(compact) == 32 and compact.endswith(suffix):
        first = compact[:8]
        if first.startswith("0000"):
            return 2, bytes.fromhex(first[4:])[::-1]
        return 4, bytes.fromhex(first)[::-1]
    if len(compact) == 32:
        return 16, bytes.fromhex(compact)[::-1]
    return None


def _predicate_patterns(signature: Signature) -> tuple[tuple[OrPatternConfig, ...], int]:
    patterns: list[OrPatternConfig] = []
    total = 0
    if signature.manufacturer_id is not None and signature.manufacturer_pattern is not None:
        total += 1
        mask = signature.manufacturer_mask
        if mask is None or all(byte == 0xFF for byte in mask):
            company = signature.manufacturer_id.to_bytes(2, "little")
            patterns.append(OrPatternConfig(0, 0xFF, company + signature.manufacturer_pattern))
    if signature.manufacturer_ids:
        total += 1
        patterns.extend(OrPatternConfig(0, 0xFF, company_id.to_bytes(2, "little"))
                        for company_id in signature.manufacturer_ids)
    if signature.service_uuids:
        total += 1
        for value in signature.service_uuids:
            parsed = _uuid_ad_bytes(value)
            if parsed is not None:
                width, payload = parsed
                patterns.extend((OrPatternConfig(0, width, payload),
                                 OrPatternConfig(0, width + 1, payload)))
    for value, prefix in signature.service_data.items():
        total += 1
        parsed = _uuid_ad_bytes(value)
        if parsed is not None:
            width, payload = parsed
            data_type = {2: 0x16, 4: 0x20, 16: 0x21}[width]
            patterns.append(OrPatternConfig(0, data_type, payload + prefix))
    if signature.name_pattern is not None:
        total += 1
        if signature.name_mode == "exact":
            encoded = signature.name_pattern.encode("utf-8")
            patterns.extend((OrPatternConfig(0, 0x08, encoded), OrPatternConfig(0, 0x09, encoded)))
    if signature.exact_identifiers:
        total += 1
    return tuple(dict.fromkeys(patterns)), total


def watch_rule_filter_coverage(signature: Signature) -> RuleFilterCoverage:
    if not signature.enabled:
        return RuleFilterCoverage("disabled", ())
    patterns, total = _predicate_patterns(signature)
    if not patterns:
        return RuleFilterCoverage("browser_only", ())
    # Patterns can expand from one service criterion to complete/incomplete AD
    # variants. Count compatible predicates separately for all/any semantics.
    compatible = 0
    if signature.manufacturer_id is not None and signature.manufacturer_pattern is not None:
        mask = signature.manufacturer_mask
        compatible += int(mask is None or all(byte == 0xFF for byte in mask))
    compatible += int(bool(signature.manufacturer_ids))
    # service_uuids is a single OR predicate in match_signature. It is fully
    # covered only when every alternative has a corresponding scan filter.
    compatible += int(bool(signature.service_uuids) and all(
        _uuid_ad_bytes(value) is not None for value in signature.service_uuids
    ))
    compatible += sum(_uuid_ad_bytes(value) is not None for value in signature.service_data)
    compatible += int(signature.name_pattern is not None and signature.name_mode == "exact")
    if signature.match_mode == "all" or compatible == total:
        status = "full"
    elif compatible:
        status = "partial"
    else:
        status = "browser_only"
    return RuleFilterCoverage(status, tuple(dict.fromkeys(patterns)))


def derived_watch_filters(signatures: Sequence[Signature]) -> tuple[OrPatternConfig, ...]:
    patterns: list[OrPatternConfig] = []
    seen: set[tuple[int, int, bytes]] = set()
    for signature in signatures:
        if signature.watchlist is None or not signature.enabled:
            continue
        for pattern in watch_rule_filter_coverage(signature).patterns:
            key = (pattern.start_position, pattern.ad_data_type, pattern.pattern)
            if key not in seen:
                seen.add(key)
                patterns.append(pattern)
    return tuple(patterns)
