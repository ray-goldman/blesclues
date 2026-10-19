import json
import tempfile
import unittest
from pathlib import Path

from bt_signature_detector.company_ids import CompanyIdentifierRegistry, parse_company_registry, write_company_snapshot


class CompanyIdentifierTests(unittest.TestCase):
    def test_parses_valid_registry_records(self):
        result = parse_company_registry('''company_identifiers:
  - value: 0x004C
    name: Apple, Inc.
  - value: 0x0006
    name: Microsoft
''')
        self.assertEqual(result, {0x004C: "Apple, Inc.", 0x0006: "Microsoft"})

    def test_rejects_duplicate_out_of_range_and_empty_records(self):
        for source in (
            'company_identifiers: [{value: 1, name: One}, {value: 1, name: Duplicate}]',
            'company_identifiers: [{value: 65536, name: Too high}]',
            'company_identifiers: [{value: 1, name: " "}]',
            'company_identifiers: [{value: "1", name: String ID}]',
            'wrong_root: []',
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_company_registry(source)

    def test_snapshot_loader_rejects_malformed_json_and_unknown_lookup_is_none(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "registry.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                CompanyIdentifierRegistry.from_json(path)
            path.write_text(json.dumps({"source_url": "source", "retrieved_at": "now", "companies": {"0x004C": "Apple"}}), encoding="utf-8")
            registry = CompanyIdentifierRegistry.from_json(path)
            self.assertEqual(registry.lookup(0x004C), "Apple")
            self.assertIsNone(registry.lookup(0xFFFF))

    def test_packaged_registry_is_available_without_network(self):
        registry = CompanyIdentifierRegistry.from_package()
        self.assertIsInstance(registry.lookup(0x004C), str)

    def test_snapshot_writer_is_sorted_and_uses_four_digit_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "registry.json"
            write_company_snapshot({0x004C: "Apple", 0x0006: "Microsoft"}, path, retrieved_at="2026-10-18T00:00:00Z")
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(list(value["companies"]), ["0x0006", "0x004C"])


if __name__ == "__main__":
    unittest.main()
