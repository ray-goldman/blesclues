import unittest
from pathlib import Path


class InstallScriptTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]

    def test_service_waits_for_bluetooth_without_waiting_for_network(self):
        unit = (self.root / "systemd" / "bt-signature-detector.service").read_text()
        web_unit = (self.root / "systemd" / "bt-signature-detector-web.service").read_text()
        self.assertIn("After=bluetooth.service", unit)
        self.assertNotIn("network-online.target", unit)
        self.assertNotIn("RuntimeDirectoryGroup", unit + web_unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("StandardOutput=journal", unit)

    def test_install_preserves_config_and_uninstall_requires_explicit_purge(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        uninstall = (self.root / "scripts" / "uninstall.sh").read_text()
        self.assertIn("if [[ ! -e", install)
        self.assertIn("--purge", uninstall)
        self.assertIn("if [[ \"$PURGE\" -eq 1 ]]", uninstall)
        self.assertIn("/var/lib/bt-signature-detector", uninstall)
        self.assertIn("dnsmasq-ap.conf", install)
        self.assertIn("if [[ ! -e /etc/bt-signature-detector/dnsmasq-ap.conf ]]", install)
        self.assertIn("802-11-wireless-security.pmf 1", install)

    def test_linux_deployment_text_is_kept_as_lf_in_archives(self):
        attributes = (self.root / ".gitattributes").read_text()
        self.assertIn("* text=auto eol=lf", attributes)
        deployment_text = [
            *self.root.joinpath("scripts").glob("*.sh"),
            *self.root.joinpath("systemd").glob("*.service"),
            *self.root.joinpath("systemd").glob("*.sudoers"),
        ]
        for path in deployment_text:
            self.assertNotIn(b"\r", path.read_bytes(), path.name)


if __name__ == "__main__": unittest.main()
