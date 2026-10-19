from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from bt_signature_detector.models import Advertisement, Confidence, Signature


class AdvertisementModelTests(unittest.TestCase):
    def test_signature_watch_fields_keep_legacy_defaults_and_trailing_construction(self) -> None:
        signature = Signature("id", "name", Confidence.POSSIBLE)
        self.assertIsNone(signature.watchlist)
        self.assertTrue(signature.enabled)

    def test_optional_advertisement_fields_remain_absent(self) -> None:
        observed = Advertisement(identifier="AA:BB", rssi=-70)
        self.assertIsNone(observed.name)
        self.assertEqual(observed.manufacturer_data, {})
        self.assertEqual(observed.service_uuids, ())
        self.assertEqual(observed.service_data, {})
        self.assertIsNone(observed.address_type)
        self.assertIsNotNone(observed.timestamp)
        self.assertEqual(observed.timestamp.tzinfo, timezone.utc)

    def test_advertisement_is_immutable_and_keeps_supplied_timestamp(self) -> None:
        timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
        observed = Advertisement(identifier="AA:BB", rssi=-55, timestamp=timestamp)
        self.assertEqual(observed.timestamp, timestamp)
        with self.assertRaises(FrozenInstanceError):
            observed.rssi = -20  # type: ignore[misc]

    def test_confidence_values_are_closed_classification_set(self) -> None:
        self.assertEqual({item.value for item in Confidence}, {"confirmed", "possible", "unknown"})

    def test_timestamps_normalize_to_utc(self) -> None:
        timestamp = datetime(2026, 1, 1, 2, tzinfo=timezone(timedelta(hours=2)))
        observed = Advertisement(identifier="AA:BB", timestamp=timestamp)
        self.assertEqual(observed.timestamp, datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_optional_address_type_is_preserved_when_platform_provides_it(self) -> None:
        observed = Advertisement(identifier="AA:BB", address_type="random")
        self.assertEqual(observed.address_type, "random")


if __name__ == "__main__":
    unittest.main()
