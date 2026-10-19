import unittest

from bt_signature_detector.config import OrPatternConfig
from bt_signature_detector.models import Confidence, Signature
from bt_signature_detector.watch_filters import derived_watch_filters, watch_rule_filter_coverage


class WatchFilterTests(unittest.TestCase):
    def test_manufacturer_company_id_is_little_endian_before_prefix(self):
        rule = Signature("m", "Manufacturer", Confidence.UNKNOWN, manufacturer_id=0x1234,
                         manufacturer_pattern=bytes.fromhex("aabb"), watchlist="List")
        coverage = watch_rule_filter_coverage(rule)
        self.assertEqual(coverage.patterns, (OrPatternConfig(0, 0xFF, bytes.fromhex("3412aabb")),))
        self.assertEqual(coverage.status, "full")

    def test_service_uuid_and_service_data_prefix_patterns(self):
        service = Signature("s", "Service", Confidence.UNKNOWN,
                            service_uuids=("0000180d-0000-1000-8000-00805f9b34fb",), watchlist="List")
        data = Signature("d", "Data", Confidence.UNKNOWN,
                         service_data={"0000180f-0000-1000-8000-00805f9b34fb": b"\xaa"}, watchlist="List")
        self.assertEqual(watch_rule_filter_coverage(service).patterns,
                         (OrPatternConfig(0, 0x02, bytes.fromhex("0d18")),
                          OrPatternConfig(0, 0x03, bytes.fromhex("0d18"))))
        self.assertEqual(watch_rule_filter_coverage(data).patterns,
                         (OrPatternConfig(0, 0x16, bytes.fromhex("0f18aa")),))

    def test_exact_name_prefix_is_filterable_but_contains_and_address_are_not(self):
        exact = Signature("n", "Name", Confidence.UNKNOWN, name_pattern="Beacon", watchlist="List")
        contains = Signature("c", "Contains", Confidence.UNKNOWN, name_pattern="Beacon", name_mode="contains", watchlist="List")
        address = Signature("a", "Address", Confidence.UNKNOWN, exact_identifiers=("aa",), watchlist="List")
        self.assertEqual(watch_rule_filter_coverage(exact).patterns,
                         (OrPatternConfig(0, 0x08, b"Beacon"),
                          OrPatternConfig(0, 0x09, b"Beacon")))
        self.assertEqual(watch_rule_filter_coverage(contains).status, "browser_only")
        self.assertEqual(watch_rule_filter_coverage(address).status, "browser_only")

    def test_all_any_disabled_and_unlisted_coverage(self):
        compatible = dict(manufacturer_id=76, manufacturer_pattern=b"\x01", watchlist="List")
        all_rule = Signature("all", "All", Confidence.UNKNOWN, **compatible,
                             name_pattern="Beacon", name_mode="contains")
        any_rule = Signature("any", "Any", Confidence.UNKNOWN, match_mode="any", **compatible,
                             name_pattern="Beacon", name_mode="contains")
        disabled = Signature("off", "Off", Confidence.UNKNOWN, enabled=False, **compatible)
        unlisted = Signature("base", "Base", Confidence.UNKNOWN, **{k:v for k,v in compatible.items() if k!="watchlist"})
        self.assertEqual(watch_rule_filter_coverage(all_rule).status, "full")
        self.assertEqual(watch_rule_filter_coverage(any_rule).status, "partial")
        self.assertEqual(watch_rule_filter_coverage(disabled).status, "disabled")
        self.assertEqual(derived_watch_filters((unlisted, disabled)), ())

    def test_any_service_uuid_group_counts_as_one_compatible_predicate(self):
        rule = Signature("uuids", "Several UUIDs", Confidence.UNKNOWN,
                         service_uuids=("0000180d-0000-1000-8000-00805f9b34fb",
                                        "0000180f-0000-1000-8000-00805f9b34fb"),
                         match_mode="any", watchlist="List")
        self.assertEqual(watch_rule_filter_coverage(rule).status, "full")

    def test_derived_patterns_are_deduplicated(self):
        rule = Signature("m", "Manufacturer", Confidence.UNKNOWN, manufacturer_id=76,
                         manufacturer_pattern=b"\x01", watchlist="List")
        self.assertEqual(derived_watch_filters((rule, rule)), (OrPatternConfig(0, 0xFF, b"L\x00\x01"),))

    def test_company_id_only_rule_derives_manufacturer_filter(self):
        rule = Signature("company", "Company", Confidence.UNKNOWN,
                         manufacturer_ids=(0x004C,), watchlist="List")
        self.assertEqual(watch_rule_filter_coverage(rule).status, "full")
        self.assertEqual(derived_watch_filters((rule,)),
                         (OrPatternConfig(0, 0xFF, bytes.fromhex("4c00")),))


if __name__ == "__main__":
    unittest.main()
