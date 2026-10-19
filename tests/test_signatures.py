import tempfile
import unittest
from pathlib import Path

import yaml

from bt_signature_detector.models import Advertisement
from bt_signature_detector.signatures import load_signatures, match_signature


class SignatureTests(unittest.TestCase):
    def write_signatures(self, text):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "signatures.yaml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_masked_manufacturer_bytes(self):
        signature = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: masked
    label: Masked bytes
    manufacturer_data:
      "76": {pattern: "aabb", mask: "ff00"}
'''))[0]
        self.assertTrue(match_signature(signature, Advertisement("aa", manufacturer_data={76: bytes.fromhex("aa11")})))
        self.assertFalse(match_signature(signature, Advertisement("aa", manufacturer_data={76: bytes.fromhex("ab11")})))

    def test_and_or_composition_uuid_and_name_predicates(self):
        signature = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: any
    label: Any
    match_mode: any
    service_uuids: ["180d"]
    name_contains: beacon
    observed_identifiers: ["aa:bb"]
'''))[0]
        self.assertTrue(match_signature(signature, Advertisement("AA:BB", name="Nearby BEACON")))
        self.assertFalse(match_signature(signature, Advertisement("CC:DD", name="Other device")))
        all_signature = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: all
    label: All
    match_mode: all
    service_uuids: ["180d"]
    name_exact: Beacon
    observed_identifiers: ["aa:bb"]
'''))[0]
        self.assertTrue(match_signature(all_signature, Advertisement("AA:BB", name="Beacon", service_uuids=("0000180d-0000-1000-8000-00805f9b34fb",))))
        self.assertFalse(match_signature(all_signature, Advertisement("aa:bb", name="beacon", service_uuids=("180d",))))

    def test_missing_optional_fields_do_not_raise(self):
        signature = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: missing
    label: Missing fields
    service_uuids: ["180d"]
    name_contains: beacon
    manufacturer_data:
      "76": "aabb"
'''))[0]
        self.assertFalse(match_signature(signature, Advertisement("id")))

    def test_rssi_is_not_used_as_signature_identity(self):
        signature = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: rssi
    label: RSSI is a filter only
    match_mode: any
    service_uuids: ["180d"]
    min_rssi: -90
'''))[0]
        self.assertFalse(match_signature(signature, Advertisement("id", rssi=-40)))

    def test_invalid_or_empty_predicates_rejected(self):
        for body in (
            "  - id: empty\n    label: Empty\n",
            "  - id: bad\n    label: Bad\n    manufacturer_data: {\"1\": {pattern: 'aa', mask: 'ffff'}}\n",
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                load_signatures(self.write_signatures("schema_version: 1\nsignatures:\n" + body))

    def test_invalid_hex_and_uuid_predicates_are_rejected(self):
        for body in (
            'manufacturer_data: {"76": "gg"}',
            'service_uuids: ["not-a-uuid"]',
            'service_data: {"bad": "aabb"}',
        ):
            text = "schema_version: 1\nsignatures:\n  - id: invalid\n    label: Invalid\n    " + body.replace("\n", "\n    ") + "\n"
            with self.subTest(body=body), self.assertRaises(ValueError):
                load_signatures(self.write_signatures(text))

    def test_watchlist_fields_are_optional_and_validated(self):
        signatures = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: legacy
    label: Legacy
    service_uuids: ["180d"]
  - id: enabled
    label: Enabled
    watchlist: Roadside
    enabled: true
    service_uuids: ["180f"]
  - id: disabled
    label: Disabled
    watchlist: Roadside
    enabled: false
    service_uuids: ["1810"]
'''))
        self.assertIsNone(signatures[0].watchlist)
        self.assertTrue(signatures[0].enabled)
        self.assertEqual(signatures[1].watchlist, "Roadside")
        self.assertTrue(signatures[1].enabled)
        self.assertFalse(signatures[2].enabled)

    def test_watchlist_names_are_trimmed_and_unique_case_insensitively(self):
        signatures = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: one
    label: One
    watchlist: "  Roadside  "
    service_uuids: ["180d"]
  - id: two
    label: Two
    watchlist: roadside
    service_uuids: ["180f"]
'''))
        self.assertEqual([item.watchlist for item in signatures], ["Roadside", "Roadside"])
        with self.assertRaisesRegex(ValueError, "watchlist"):
            load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: bad
    label: Bad
    watchlist: "   "
    service_uuids: ["180d"]
'''))
        with self.assertRaisesRegex(ValueError, "unique"):
            load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: one
    label: One
    watchlist: Roadside
    service_uuids: ["180d"]
  - id: one
    label: Two
    service_uuids: ["180f"]
'''))

    def test_watchlist_limits_boolean_type_and_unknown_keys_are_rejected(self):
        for body in (
            'watchlist: "' + ("x" * 81) + '"\n    service_uuids: ["180d"]',
            'watchlist: 12\n    service_uuids: ["180d"]',
            'watchlist: Roadside\n    enabled: yes-no\n    service_uuids: ["180d"]',
            'watchlist: Roadside\n    enabled: "false"\n    service_uuids: ["180d"]',
            'watchlist: Roadside\n    mystery: true\n    service_uuids: ["180d"]',
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                load_signatures(self.write_signatures("schema_version: 1\nsignatures:\n  - id: bad\n    label: Bad\n    " + body.replace("\n", "\n    ") + "\n"))

    def test_signature_criteria_have_bounded_fields_and_collections(self):
        oversized = [
            {"id": "x" * 129, "label": "Label", "service_uuids": ["180d"]},
            {"id": "x", "label": "L" * 121, "service_uuids": ["180d"]},
            {"id": "x", "label": "Label", "name_exact": "é" * 125},
            {"id": "x", "label": "Label", "observed_identifiers": ["a" * 129]},
            {"id": "x", "label": "Label", "observed_identifiers": [f"{i:02x}" for i in range(33)]},
            {"id": "x", "label": "Label", "service_uuids": ["180d"] * 33},
            {"id": "x", "label": "Label", "service_data": {f"0000{i:04x}": "aa" for i in range(33)}},
            {"id": "x", "label": "Label", "manufacturer_data": {"76": "aa" * 63}},
            {"id": "x", "label": "Label", "service_data": {"180d": "aa" * 63}},
            {"id": "x", "label": "Label", "service_uuids": ["180d"], "evidence": "x" * 2001},
        ]
        for row in oversized:
            with self.subTest(fields=list(row)):
                document = yaml.safe_dump({"schema_version": 1, "signatures": [row]})
                with self.assertRaises(ValueError):
                    load_signatures(self.write_signatures(document))

    def test_watch_rules_match_name_regex_mac_prefix_and_manufacturer_id(self):
        signatures = load_signatures(self.write_signatures('''schema_version: 1
signatures:
  - id: regex
    label: Name regex
    name_regex: '^Axon-[0-9]{4}$'
  - id: address
    label: Address prefix
    identifier_prefixes: ["AA:BB:CC"]
  - id: company
    label: Company ID
    manufacturer_ids: [76]
'''))
        self.assertTrue(match_signature(signatures[0], Advertisement("10:20:30:40:50:60", name="Axon-1234")))
        self.assertFalse(match_signature(signatures[0], Advertisement("10:20:30:40:50:60", name="Axon-123")))
        self.assertTrue(match_signature(signatures[1], Advertisement("aa:bb:cc:01:02:03")))
        self.assertFalse(match_signature(signatures[1], Advertisement("aa:bb:cd:01:02:03")))
        self.assertTrue(match_signature(signatures[2], Advertisement("10:20:30:40:50:60", manufacturer_data={76: b""})))
        self.assertFalse(match_signature(signatures[2], Advertisement("10:20:30:40:50:60", manufacturer_data={77: b""})))

    def test_invalid_regex_and_mac_prefix_are_rejected(self):
        for row in (
            {"id": "regex", "label": "Bad regex", "name_regex": "[unterminated"},
            {"id": "regex", "label": "Backtracking regex", "name_regex": "^(a+)+$"},
            {"id": "regex", "label": "Ambiguous repeated regex", "name_regex": "^(a|aa)+$"},
            {"id": "address", "label": "Bad prefix", "identifier_prefixes": ["AA:BB:C"]},
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                try:
                    load_signatures(self.write_signatures(yaml.safe_dump({"schema_version": 1, "signatures": [row]})))
                except ValueError as error:
                    self.assertRegex(str(error), "regex|identifier_prefixes")
                    raise


if __name__ == "__main__":
    unittest.main()
