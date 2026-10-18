from __future__ import annotations

import logging
from typing import Sequence

from .models import Advertisement, DetectionEvent, Signature
from .signatures import match_signature
from .state import DetectionFilter

logger = logging.getLogger(__name__)


class DetectionPipeline:
    def __init__(self, signatures: Sequence[Signature], *, store=None,
                 cooldown_seconds: int = 300, absence_seconds: int = 120,
                 global_min_rssi: int | None = None, dispatcher=None) -> None:
        self.signatures = tuple(signatures)
        self.store = store
        self.dispatcher = dispatcher
        self.filter = DetectionFilter(cooldown_seconds=cooldown_seconds,
            absence_seconds=absence_seconds, global_min_rssi=global_min_rssi)
        self.advertisements_processed = 0
        self.store_errors = 0

    def process(self, advertisement: Advertisement) -> list[DetectionEvent]:
        self.advertisements_processed += 1
        matches = [signature for signature in self.signatures if match_signature(signature, advertisement)]
        events = self.filter.observe(advertisement, matches)
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
