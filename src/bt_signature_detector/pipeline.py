from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
import re
from typing import Sequence

from .builtin_rules import BuiltInRule
from .detection_scoring import CrossProtocolScorer, RuleHit
from .models import Advertisement, Confidence, DetectionEvent, Signature
from .signatures import match_signature
from .state import DetectionFilter
from .wifi_scanner import WifiObservation, match_wifi_rules

logger = logging.getLogger(__name__)


def _normalized_mac(value: str) -> str:
    compact = re.sub(r"[:-]", "", value).upper()
    return compact if re.fullmatch(r"[0-9A-F]{12}", compact) else ""


def match_ble_rules(rules: Sequence[BuiltInRule], advertisement: Advertisement) -> tuple[BuiltInRule, ...]:
    """Match BLE names and globally administered OUI prefixes in an advertisement."""
    address = _normalized_mac(advertisement.identifier)
    global_address = bool(address) and not (int(address[:2], 16) & 0x02)
    name = advertisement.name or ""
    matched = []
    for rule in rules:
        if rule.protocol != "ble":
            continue
        if rule.match_type == "mac_prefix" and global_address:
            if address.startswith(rule.pattern.replace(":", "").replace("-", "").upper()):
                matched.append(rule)
        elif rule.match_type == "name_regex" and re.search(rule.pattern, name):
            matched.append(rule)
    return tuple(matched)


class DetectionPipeline:
    def __init__(self, signatures: Sequence[Signature], *, store=None,
                 cooldown_seconds: int = 300, absence_seconds: int = 120,
                 global_min_rssi: int | None = None, dispatcher=None, scan_cache=None,
                 device_cache=None, builtin_rules: Sequence[BuiltInRule] = (),
                 builtin_scorer: CrossProtocolScorer | None = None) -> None:
        self.signatures = tuple(signatures)
        self.store = store
        self.dispatcher = dispatcher
        self.scan_cache = scan_cache
        self.device_cache = device_cache
        self.builtin_rules = tuple(builtin_rules)
        self.builtin_scorer = builtin_scorer
        self._builtin_last_alert: dict[tuple[str, str], datetime] = {}
        self._builtin_cooldown = timedelta(seconds=cooldown_seconds)
        self.filter = DetectionFilter(cooldown_seconds=cooldown_seconds,
            absence_seconds=absence_seconds, global_min_rssi=global_min_rssi)
        self.advertisements_processed = 0
        self.store_errors = 0

    def process(self, advertisement: Advertisement) -> list[DetectionEvent]:
        self.advertisements_processed += 1
        if self.scan_cache is not None:
            try: self.scan_cache.add(advertisement)
            except OSError:
                logger.warning("runtime scan cache is unavailable", exc_info=True)
        if self.device_cache is not None:
            try: self.device_cache.add(advertisement)
            except OSError:
                logger.warning("runtime device cache is unavailable", exc_info=True)
        matches = [signature for signature in self.signatures if match_signature(signature, advertisement)]
        events = self.filter.observe(advertisement, matches)
        if self.builtin_rules and self.builtin_scorer is not None:
            for rule in match_ble_rules(self.builtin_rules, advertisement):
                scored = self.builtin_scorer.observe(RuleHit(
                    rule=rule, protocol="ble", observed_identifier=advertisement.identifier,
                    observed_name=advertisement.name, observed_ssid=None,
                    observed_at=advertisement.timestamp))
                if not scored.qualifies:
                    continue
                key = (rule.rule_id, advertisement.identifier.casefold())
                previous = self._builtin_last_alert.get(key)
                if previous is not None and advertisement.timestamp - previous < self._builtin_cooldown:
                    continue
                self._builtin_last_alert[key] = advertisement.timestamp
                events.append(DetectionEvent(
                    signature_id=f"builtin:{rule.rule_id}", signature_name=rule.vendor,
                    confidence=Confidence.POSSIBLE, observed_identifier=advertisement.identifier,
                    first_seen=advertisement.timestamp, last_seen=advertisement.timestamp,
                    strongest_rssi=advertisement.rssi, observation_count=1,
                    alert_enabled=True, protocol="ble", vendor=rule.vendor,
                    base_score=scored.base_score, correlation_bonus=scored.correlation_bonus,
                    effective_score=scored.effective_score,
                    source_note="; ".join(value for value in (rule.source, rule.notes) if value),
                    observed_name=advertisement.name))
        for event in events:
            logger.info("detection signature=%s confidence=%s", event.signature_id, event.confidence.value)
            if self.store is not None:
                try:
                    self.store.record(event)
                except Exception:
                    self.store_errors += 1
                    logger.exception("unable to store detection; observation continues")
            if self.dispatcher is not None:
                self.dispatcher.submit(event)
        return events

    def process_wifi_observation(self, observation: WifiObservation) -> list[DetectionEvent]:
        """Store qualifying Wi-Fi hits; raw observations stay in the volatile cache."""
        if self.builtin_scorer is None:
            return []
        events: list[DetectionEvent] = []
        for rule in match_wifi_rules(self.builtin_rules, observation):
            scored = self.builtin_scorer.observe(RuleHit(
                rule=rule, protocol="wifi", observed_identifier=observation.bssid,
                observed_name=None, observed_ssid=observation.ssid,
                observed_at=observation.observed_at))
            if not scored.qualifies:
                continue
            key = (rule.rule_id, observation.bssid.casefold())
            previous = self._builtin_last_alert.get(key)
            if previous is not None and observation.observed_at - previous < self._builtin_cooldown:
                continue
            self._builtin_last_alert[key] = observation.observed_at
            events.append(DetectionEvent(
                signature_id=f"builtin:{rule.rule_id}", signature_name=rule.vendor,
                confidence=Confidence.POSSIBLE, observed_identifier=observation.bssid,
                first_seen=observation.observed_at, last_seen=observation.observed_at,
                strongest_rssi=observation.signal, observation_count=1,
                alert_enabled=True, protocol="wifi", vendor=rule.vendor,
                base_score=scored.base_score, correlation_bonus=scored.correlation_bonus,
                effective_score=scored.effective_score,
                source_note="; ".join(value for value in (rule.source, rule.notes) if value),
                observed_ssid=observation.ssid))
        for event in events:
            logger.info("built-in Wi-Fi detection vendor=%s score=%s", event.vendor, event.effective_score)
            self._record_event(event)
        return events

    def _record_event(self, event: DetectionEvent) -> None:
        if self.store is not None:
            try:
                self.store.record(event)
            except Exception:
                self.store_errors += 1
                logger.exception("unable to store detection; observation continues")
        if self.dispatcher is not None:
            self.dispatcher.submit(event)
