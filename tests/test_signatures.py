import tempfile
import unittest
from pathlib import Path

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

    def test_invalid_or_empty_predicates_rejected(self):
        for body in (
            "  - id: empty\n    label: Empty\n",
            "  - id: bad\n    label: Bad\n    manufacturer_data: {\"1\": {pattern: 'aa', mask: 'ffff'}}\n",
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                load_signatures(self.write_signatures("schema_version: 1\nsignatures:\n" + body))


if __name__ == "__main__":
    unittest.main()
