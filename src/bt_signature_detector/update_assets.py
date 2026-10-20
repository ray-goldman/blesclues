"""Install signed-wheel systemd assets with a reversible filesystem snapshot."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Callable


@dataclass(slots=True)
class SystemdAssetSnapshot:
    states: list[tuple[Path, bytes | None, int | None]]

    def rollback(self) -> None:
        for target, content, mode in reversed(self.states):
            if content is None:
                try:
                    os.chmod(target, 0o600)
                    target.unlink()
                except FileNotFoundError:
                    pass
                continue
            _atomic_write(target, content, mode or 0o644)


def _atomic_write(target: Path, content: bytes, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, target)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


class SystemdAssetInstaller:
    ASSETS = (
        "systemd/bt-signature-detector.service",
        "systemd/bt-signature-detector-bluetooth.service",
        "systemd/bt-signature-detector-dhcp.service",
        "systemd/bt-signature-detector-ap.service",
        "systemd/bt-signature-detector-wifi.service",
        "systemd/bt-signature-detector-wifi-mode.service",
        "systemd/bt-signature-detector-web.service",
        "systemd/bt-signature-detector-updater@.service",
        "systemd/bluetooth.service.d/10-bt-signature-detector.conf",
        "systemd/bt-signature-detector-ap-helper.sudoers",
        "systemd/bt-signature-detector-device-browser.sudoers",
        "systemd/bt-signature-detector-wifi-mode.sudoers",
        "scripts/apply_update_helper.sh",
        "scripts/restart_detector_helper.sh",
        "scripts/device_browser_helper.sh",
        "scripts/wifi_mode_helper.sh",
    )
    SCRIPT_NAMES = {
        "scripts/apply_update_helper.sh": "bt-detector-apply-update",
        "scripts/restart_detector_helper.sh": "bt-detector-restart-scanner",
        "scripts/device_browser_helper.sh": "bt-detector-device-browser",
        "scripts/wifi_mode_helper.sh": "bt-detector-wifi-mode",
    }

    def __init__(self, source_root: Path, *, systemd_dir: Path = Path("/etc/systemd/system"),
                 sbin_dir: Path = Path("/usr/local/sbin"), runner: Callable = subprocess.run) -> None:
        self.source_root = Path(source_root)
        self.systemd_dir = Path(systemd_dir)
        self.sbin_dir = Path(sbin_dir)
        self.runner = runner

    def _target(self, relative: str) -> tuple[Path, int]:
        source = Path(relative)
        if relative in self.SCRIPT_NAMES:
            return self.sbin_dir / self.SCRIPT_NAMES[relative], 0o755
        if source.suffix == ".sudoers":
            return self.systemd_dir.parent.parent / "sudoers.d" / source.name.removesuffix(".sudoers"), 0o440
        if relative.startswith("systemd/bluetooth.service.d/"):
            return self.systemd_dir / "bluetooth.service.d" / source.name, 0o644
        return self.systemd_dir / source.name, 0o644

    def _validate_sudoers(self, relative: str, content: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="bt-sudoers-check-") as directory:
            candidate = Path(directory) / Path(relative).name.removesuffix(".sudoers")
            candidate.write_bytes(content)
            candidate.chmod(0o440)
            self.runner(["visudo", "-cf", str(candidate)], check=True, capture_output=True, text=True)

    def install(self) -> SystemdAssetSnapshot:
        snapshot = SystemdAssetSnapshot([])
        try:
            assets = []
            for relative in self.ASSETS:
                source = self.source_root / relative
                if source.is_symlink() or not source.is_file():
                    raise ValueError(f"signed update is missing required system asset: {relative}")
                content = source.read_bytes()
                if len(content) > 1_000_000:
                    raise ValueError(f"signed update system asset is oversized: {relative}")
                target, mode = self._target(relative)
                if relative.endswith(".sudoers"):
                    self._validate_sudoers(relative, content)
                assets.append((target, content, mode))
            for target, content, mode in assets:
                if target.is_symlink():
                    raise ValueError(f"refusing to replace symlink system asset: {target}")
                old_content = target.read_bytes() if target.is_file() else None
                old_mode = target.stat().st_mode & 0o777 if old_content is not None else None
                snapshot.states.append((target, old_content, old_mode))
                _atomic_write(target, content, mode)
            return snapshot
        except Exception:
            snapshot.rollback()
            raise
