import unittest
from pathlib import Path


class DocumentationTests(unittest.TestCase):
    def test_install_and_safety_guides_include_required_operator_notes(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        install = (root / "docs" / "raspberry-pi-install.md").read_text(encoding="utf-8")
        trouble = (root / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
        carplay = (root / "docs" / "carplay-testing.md").read_text(encoding="utf-8")
        updates = (root / "docs" / "software-updates.md").read_text(encoding="utf-8")
        self.assertIn("easypassword", readme)
        self.assertIn("at least three matching observations by default", install)
        self.assertIn("or_patterns", install)
        self.assertIn("without changing to active scanning", install)
        self.assertIn("--purge", install)
        self.assertIn("--confirm-sms", trouble)
        self.assertIn("not guaranteed", carplay)
        self.assertIn("A2P", carplay)
        self.assertIn("Ed25519", updates)
        self.assertIn("local signed bundle upload", updates)
        self.assertIn("health check fails", updates)
        self.assertIn("outside source control and the Pi", updates)


if __name__ == "__main__": unittest.main()
