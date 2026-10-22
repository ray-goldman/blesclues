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
        self.assertIn("**Devices**", readme)
        self.assertIn("Pause updates", readme)
        self.assertIn("the radios keep running", install)
        self.assertIn("Pause updates", install)
        self.assertIn("scanner-status.json", trouble)
        self.assertIn("Detector-Admin", readme)
        self.assertIn("Ethernet", readme)
        self.assertIn("40 points", install)
        self.assertIn("20-point bonus", install)
        self.assertIn("60 seconds", install)
        self.assertIn("Switching modes stops the current service", install)
        self.assertIn("not written to the SD card", install)
        self.assertIn("Resume updates", trouble)
        self.assertIn("at least three matching observations by default", install)
        self.assertIn("or_patterns", install)
        self.assertIn("configured passive", install)
        self.assertIn("--purge", install)
        self.assertIn("--confirm-sms", trouble)
        self.assertIn("cannot guarantee", carplay)
        self.assertIn("A2P", carplay)
        self.assertIn("Ed25519", updates)
        self.assertIn("local bundle upload", updates)
        self.assertIn("health check fails", updates)
        self.assertIn("out of source control and off the Pi", updates)

    def test_watchlist_and_company_registry_documentation(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        install = (root / "docs" / "raspberry-pi-install.md").read_text(encoding="utf-8")
        trouble = (root / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
        for label in ("Live Feed", "Watch Lists", "No derived filter", "Partial", "Full"):
            self.assertIn(label, readme + install)
        self.assertIn("Bluetooth SIG Assigned Numbers", readme + install)
        self.assertIn("They do not confirm", readme + install)
        self.assertIn("derived", install.lower())
        self.assertIn("signatures.yaml", install)
        self.assertIn("SQLite", readme)
        self.assertIn("no device history is saved", install)
        self.assertIn("Bluetooth SIG", trouble)


if __name__ == "__main__": unittest.main()
