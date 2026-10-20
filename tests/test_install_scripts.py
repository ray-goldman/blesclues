import unittest
from pathlib import Path
import importlib.util
import sys
import tempfile
from unittest.mock import patch

import yaml


class InstallScriptTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]

    def test_service_waits_for_bluetooth_without_waiting_for_network(self):
        unit = (self.root / "systemd" / "bt-signature-detector.service").read_text()
        web_unit = (self.root / "systemd" / "bt-signature-detector-web.service").read_text()
        self.assertIn("After=bluetooth.service", unit)
        self.assertNotIn("network-online.target", unit)
        self.assertIn("After=NetworkManager.service bt-signature-detector-wifi-mode.service network-online.target", web_unit)
        self.assertNotIn("RuntimeDirectoryGroup", unit + web_unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("StandardOutput=journal", unit)
        self.assertIn("LogRateLimitIntervalSec=30s", unit + web_unit)
        self.assertIn("LogRateLimitBurst=100", unit + web_unit)

    def test_updater_sandbox_can_write_only_its_managed_system_paths(self):
        unit = (self.root / "systemd" / "bt-signature-detector-updater@.service").read_text()
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadWritePaths=/opt/bt-signature-detector /var/lib/bt-signature-detector /etc/systemd/system /etc/sudoers.d /usr/local/sbin", unit)

    def test_install_preserves_config_and_uninstall_requires_explicit_purge(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        uninstall = (self.root / "scripts" / "uninstall.sh").read_text()
        self.assertIn("if [[ ! -e", install)
        self.assertIn("--purge", uninstall)
        self.assertIn("if [[ \"$PURGE\" -eq 1 ]]", uninstall)
        self.assertIn("/var/lib/bt-signature-detector", uninstall)
        self.assertIn("nmcli connection delete BLE-Detector", install)
        self.assertIn("802-11-wireless.hidden yes", install)
        self.assertIn("nmcli connection add type wifi", install)
        self.assertNotIn("systemctl enable --now bt-signature-detector-dhcp.service", install)

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

    def test_dhcp_lease_file_is_writable_under_systemd_sandbox(self):
        unit = (self.root / "systemd" / "bt-signature-detector-dhcp.service").read_text()
        self.assertIn("RuntimeDirectory=bt-signature-detector-dhcp", unit)
        self.assertIn("ReadWritePaths=/run/bt-signature-detector-dhcp", unit)
        self.assertIn("--dhcp-leasefile=/run/bt-signature-detector-dhcp/dnsmasq.leases", unit)

    def test_installer_enables_a_bluetooth_power_unit_before_scanning(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        scanner = (self.root / "systemd" / "bt-signature-detector.service").read_text()
        power = (self.root / "systemd" / "bt-signature-detector-bluetooth.service").read_text()
        self.assertIn("rfkill", install)
        self.assertIn("bt-signature-detector-bluetooth.service", install)
        self.assertRegex(scanner, r"(?m)^Requires=.*bt-signature-detector-bluetooth\.service")
        self.assertIn("rfkill unblock bluetooth", power)
        self.assertIn("bluetoothctl power on", power)

    def test_optional_wifi_scanner_is_installed_but_not_enabled_by_default(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        uninstall = (self.root / "scripts" / "uninstall.sh").read_text()
        unit = (self.root / "systemd" / "bt-signature-detector-wifi.service").read_text()
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6", unit)
        self.assertIn("bt-signature-detector-wifi.service", install)
        self.assertNotIn("systemctl enable --now bt-signature-detector-wifi.service", install)
        self.assertIn("bt-signature-detector-wifi.service", uninstall)
        self.assertIn("Conflicts=bt-signature-detector-ap.service", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN", unit)
        self.assertIn("detector wifi-scan", unit)

    def test_wifi_mode_helper_uses_fixed_sudo_commands_and_reconciles_at_boot(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        uninstall = (self.root / "scripts" / "uninstall.sh").read_text()
        sudoers = (self.root / "systemd" / "bt-signature-detector-wifi-mode.sudoers").read_text()
        helper = (self.root / "scripts" / "wifi_mode_helper.sh").read_text()
        service = (self.root / "systemd" / "bt-signature-detector-wifi-mode.service").read_text()
        self.assertIn("wifi_mode_helper.sh", install)
        self.assertIn("bt-signature-detector-wifi-mode.sudoers", install)
        self.assertIn("enable --now bt-signature-detector-wifi-mode.service", install)
        self.assertIn("bt-signature-detector-wifi-mode", uninstall)
        self.assertIn("/usr/local/sbin/bt-detector-wifi-mode", uninstall)
        self.assertIn("scan-start", sudoers)
        self.assertIn("ap-stop", sudoers)
        self.assertNotIn("*", sudoers)
        self.assertIn("bt-signature-detector-ap.service", helper)
        self.assertIn("wifi_mode_helper reconcile", service)

    def test_installer_enables_bluez_experimental_api_for_passive_scanning(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        override = (self.root / "systemd" / "bluetooth.service.d" / "10-bt-signature-detector.conf").read_text()
        uninstall = (self.root / "scripts" / "uninstall.sh").read_text()
        self.assertIn("bluetooth.service.d", install)
        self.assertIn("bluetooth.service", install)
        self.assertIn("systemctl restart bt-signature-detector-bluetooth.service", install)
        self.assertIn("systemctl restart bt-signature-detector.service", install)
        self.assertIn("--experimental", override)
        self.assertIn("10-bt-signature-detector.conf", uninstall)

    def test_installer_restarts_web_interface_after_updating_it(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        self.assertIn("systemctl restart bt-signature-detector-web.service", install)

    def test_installer_deploys_and_removes_temporary_browser_helper(self):
        install = (self.root / "scripts" / "install.sh").read_text()
        uninstall = (self.root / "scripts" / "uninstall.sh").read_text()
        sudoers = (self.root / "systemd" / "bt-signature-detector-device-browser.sudoers").read_text()
        self.assertIn("device_browser_helper.sh", install)
        self.assertIn("bt-signature-detector-device-browser.sudoers", install)
        self.assertIn("/usr/local/sbin/bt-detector-device-browser start", sudoers)
        self.assertIn("/usr/local/sbin/bt-detector-device-browser stop", sudoers)
        self.assertIn("/usr/local/sbin/bt-detector-device-browser", uninstall)
        self.assertIn("bt-signature-detector-device-browser", uninstall)

    def test_web_service_has_separate_writable_volatile_device_browser_state(self):
        web_unit = (self.root / "systemd" / "bt-signature-detector-web.service").read_text()
        browser = (self.root / "src" / "bt_signature_detector" / "device_browser.py").read_text()
        cli = (self.root / "src" / "bt_signature_detector" / "cli.py").read_text()
        marker = "/run/bt-signature-detector-web/device-browser.json"
        self.assertIn("ReadOnlyPaths=/run/bt-signature-detector", web_unit)
        self.assertIn("RuntimeDirectory=bt-signature-detector bt-signature-detector-web", web_unit)
        self.assertIn("ReadWritePaths=/var/lib/bt-signature-detector /etc/bt-signature-detector /run/bt-signature-detector-web", web_unit)
        self.assertIn(marker, browser)
        self.assertIn(marker, cli)

    def test_hidden_ap_migration_disables_legacy_and_preserves_new_settings(self):
        spec = importlib.util.spec_from_file_location("migrate_hidden_ap_config", self.root / "scripts" / "migrate_hidden_ap_config.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "detector.yaml"
            project_config = yaml.safe_load((self.root / "config" / "detector.example.yaml").read_text())
            project_config["access_point"].update({"enabled": True, "ssid": "BLE-Detector", "profile_name": "BLE-Detector"})
            config.write_text(yaml.safe_dump(project_config), encoding="utf-8")
            with patch.object(sys, "argv", [str(self.root / "scripts" / "migrate_hidden_ap_config.py"), str(config), "US"]):
                self.assertEqual(module.main(), 0)
            migrated = yaml.safe_load(config.read_text(encoding="utf-8"))["access_point"]
            self.assertFalse(migrated["enabled"])
            self.assertTrue(migrated["hidden"])
            self.assertEqual(migrated["ssid"], "Detector-Admin")
            migrated["enabled"] = True
            migrated["passphrase"] = "custom-password"
            root = yaml.safe_load(config.read_text(encoding="utf-8"))
            root["access_point"].update(migrated)
            config.write_text(yaml.safe_dump(root), encoding="utf-8")
            with patch.object(sys, "argv", [str(self.root / "scripts" / "migrate_hidden_ap_config.py"), str(config), "US"]):
                self.assertEqual(module.main(), 0)
            migrated = yaml.safe_load(config.read_text(encoding="utf-8"))["access_point"]
            self.assertTrue(migrated["enabled"])
            self.assertEqual(migrated["passphrase"], "custom-password")

if __name__ == "__main__": unittest.main()
