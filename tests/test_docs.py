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
        self.assertIn("Devices page", readme)
        self.assertIn("active scan requests", readme)
        self.assertIn("does not connect to or pair", readme)
        self.assertIn("ends on reboot", install)
        self.assertIn("Stop and restore filters", install)
        self.assertIn("scanner-status.json", trouble)
        self.assertIn("hidden Wi-Fi network", readme)
        self.assertIn("wired Ethernet", readme)
        self.assertIn("40 points", install)
        self.assertIn("20-point bonus", install)
        self.assertIn("60 seconds", install)
        self.assertIn("stops the hotspot", install)
        self.assertIn("not written to the SD card", install)
        self.assertIn("helper's sanitized stderr", trouble)
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

    def test_watchlist_and_company_registry_documentation(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        install = (root / "docs" / "raspberry-pi-install.md").read_text(encoding="utf-8")
        trouble = (root / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
        for label in ("Live Feed", "Watch Lists", "Browser scan only", "Partial", "Full"):
            self.assertIn(label, readme + install)
        self.assertIn("Bluetooth SIG Assigned Numbers", readme + install)
        self.assertIn("does not prove", readme + install)
        self.assertIn("derived", install.lower())
        self.assertIn("existing signature file", install)
        self.assertIn("SQLite", readme)
        self.assertIn("not a saved device inventory", readme + install)
        self.assertIn("Bluetooth SIG", trouble)


if __name__ == "__main__": unittest.main()
