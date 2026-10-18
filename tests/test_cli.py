import tempfile
import unittest
from pathlib import Path

from bt_signature_detector.cli import main


class CliTests(unittest.TestCase):
    def test_validate_config_and_list_signatures(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(main(["validate-config", "--config", str(root / "config" / "detector.example.yaml")]), 0)
        self.assertEqual(main(["list-signatures", "--config", str(root / "config" / "detector.example.yaml"),
                               "--signatures", str(root / "config" / "signatures.example.yaml")]), 0)

    def test_dry_run_emits_synthetic_detection(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config.yaml"
            cfg.write_text((root / "config" / "detector.example.yaml").read_text(encoding="utf-8").replace(
                "/var/lib/bt-signature-detector/events.sqlite3", str(Path(directory) / "events.sqlite3")), encoding="utf-8")
            self.assertEqual(main(["scan", "--dry-run", "--config", str(cfg)]), 0)

    def test_sms_test_alert_requires_explicit_confirmation(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config.yaml"
            text = (root / "config" / "detector.example.yaml").read_text(encoding="utf-8")
            text = text.replace("  sms:\n    enabled: false", "  sms:\n    enabled: true\n    destination: '+15555550123'")
            cfg.write_text(text, encoding="utf-8")
            self.assertEqual(main(["test-alert", "--config", str(cfg)]), 2)


if __name__ == "__main__": unittest.main()
