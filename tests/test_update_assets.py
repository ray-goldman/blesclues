import tempfile
import unittest
import os
from pathlib import Path

from bt_signature_detector.update_assets import SystemdAssetInstaller


class SystemdAssetInstallerTests(unittest.TestCase):
    def test_installs_fixed_allowlisted_units_helpers_and_sudoers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "share" / "bt-signature-detector"
            systemd = root / "etc" / "systemd" / "system"
            sbin = root / "usr" / "local" / "sbin"
            for relative in SystemdAssetInstaller.ASSETS:
                source_path = source / relative
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_text("asset: " + relative, encoding="utf-8")
            calls = []
            installer = SystemdAssetInstaller(source, systemd_dir=systemd, sbin_dir=sbin,
                                               runner=lambda command, **kwargs: calls.append(command))
            snapshot = installer.install()
            self.assertEqual((systemd / "bt-signature-detector-wifi.service").read_text(),
                             "asset: systemd/bt-signature-detector-wifi.service")
            self.assertEqual((sbin / "bt-detector-wifi-mode").read_text(),
                             "asset: scripts/wifi_mode_helper.sh")
            sudoers = root / "etc" / "sudoers.d" / "bt-signature-detector-wifi-mode"
            self.assertTrue(sudoers.exists())
            if os.name != "nt":
                self.assertEqual((sudoers.stat().st_mode & 0o777), 0o440)
            self.assertTrue(any(command[0] == "visudo" for command in calls))
            snapshot.rollback()
            self.assertFalse((systemd / "bt-signature-detector-wifi.service").exists())
            self.assertFalse((sbin / "bt-detector-wifi-mode").exists())

    def test_rollback_restores_existing_asset_bytes_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "share"
            targets = root / "etc" / "systemd"
            for relative in SystemdAssetInstaller.ASSETS:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("new", encoding="utf-8")
            existing = targets / "bt-signature-detector.service"
            existing.parent.mkdir(parents=True)
            existing.write_text("old", encoding="utf-8")
            existing.chmod(0o600)
            installer = SystemdAssetInstaller(source, systemd_dir=targets,
                sbin_dir=root / "sbin", runner=lambda *args, **kwargs: None)
            snapshot = installer.install()
            snapshot.rollback()
            self.assertEqual(existing.read_text(), "old")
            if os.name != "nt":
                self.assertEqual(existing.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__": unittest.main()
