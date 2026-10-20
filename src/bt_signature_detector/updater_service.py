from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .updates import ReleaseManifest, VerifiedRelease, UpdateVerifier, verify_bundle


@dataclass(frozen=True, slots=True)
class UpdateResult:
    success: bool
    message: str
    rolled_back: bool = False
    version: str | None = None


class UpdateCoordinator:
    """Root-side version-slot installer. It accepts already verified releases only."""
    def __init__(self, root: Path = Path("/opt/bt-signature-detector"), *,
                 state_dir: Path = Path("/var/lib/bt-signature-detector"),
                 runner: Callable = subprocess.run, health_check: Callable[[], bool] | None = None,
                 get_active: Callable[[], Path | None] | None = None,
                 switch_active: Callable[[Path | None], None] | None = None) -> None:
        self.root = Path(root)
        self.state_dir = Path(state_dir)
        self.staged_dir = self.root / "staged"
        self.releases_dir = self.root / "releases"
        self.active = self.root / "active"
        self.runner = runner
        self.health_check = health_check or self._service_healthy
        self._get_active = get_active or self._read_active
        self._switch_active = switch_active or self._write_active

    def _read_active(self) -> Path | None:
        if not self.active.is_symlink(): return None
        target = Path(os.readlink(self.active))
        return target if target.is_absolute() else (self.active.parent / target).resolve()

    def _write_active(self, target: Path | None) -> None:
        temporary = self.root / ".active-next"
        try: temporary.unlink()
        except FileNotFoundError: pass
        if target is None:
            try: self.active.unlink()
            except FileNotFoundError: pass
            return
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(temporary, self.active)

    def _service_healthy(self) -> bool:
        for _ in range(6):
            scanner = self.runner(["systemctl", "is-active", "--quiet", "bt-signature-detector.service"],
                                  capture_output=True, check=False, text=True)
            web = self.runner(["systemctl", "is-active", "--quiet", "bt-signature-detector-web.service"],
                              capture_output=True, check=False, text=True)
            if scanner.returncode == 0 and web.returncode == 0: return True
            time.sleep(2)
        return False

    def _wifi_unit_state(self) -> dict[str, tuple[str, str]]:
        units = ("bt-signature-detector-wifi-mode.service", "bt-signature-detector-ap.service",
                 "bt-signature-detector-wifi.service", "bt-signature-detector-dhcp.service")
        state = {}
        for unit in units:
            active = self.runner(["systemctl", "is-active", unit], capture_output=True, check=False, text=True)
            enabled = self.runner(["systemctl", "is-enabled", unit], capture_output=True, check=False, text=True)
            state[unit] = ((active.stdout or "unknown").strip(), (enabled.stdout or "unknown").strip())
        return state

    def _restore_wifi_unit_state(self, state: dict[str, tuple[str, str]]) -> None:
        for unit in state:
            self.runner(["systemctl", "stop", unit], check=False, capture_output=True, text=True)
        for unit, (_active, enabled) in state.items():
            if enabled == "enabled":
                self.runner(["systemctl", "enable", unit], check=False, capture_output=True, text=True)
            else:
                self.runner(["systemctl", "disable", unit], check=False, capture_output=True, text=True)
        # Let the old reconciler run first when it existed, then restore any
        # previously active one-shot/client units from the captured state.
        for unit in state:
            if state[unit][0] == "active":
                self.runner(["systemctl", "start", unit], check=False, capture_output=True, text=True)

    def _install_release_assets(self, slot: Path):
        from .update_assets import SystemdAssetInstaller
        source = slot / "share" / "bt-signature-detector"
        if not source.is_dir():
            return None
        prior_state = self._wifi_unit_state()
        snapshot = SystemdAssetInstaller(source, runner=self.runner).install()
        try:
            self.runner(["systemctl", "daemon-reload"], check=True, capture_output=True, text=True)
            self.runner(["systemctl", "disable", "--now", "bt-signature-detector-ap.service",
                         "bt-signature-detector-dhcp.service", "bt-signature-detector-wifi.service"],
                        check=False, capture_output=True, text=True)
            self.runner(["systemctl", "enable", "bt-signature-detector-wifi-mode.service"],
                        check=True, capture_output=True, text=True)
            self.runner(["systemctl", "restart", "bt-signature-detector-wifi-mode.service"],
                        check=True, capture_output=True, text=True)
            self.runner(["systemctl", "restart", "bt-signature-detector-web.service"],
                        check=True, capture_output=True, text=True)
            return (snapshot, prior_state)
        except Exception:
            snapshot.rollback()
            self.runner(["systemctl", "daemon-reload"], check=False, capture_output=True, text=True)
            self._restore_wifi_unit_state(prior_state)
            raise

    def _rollback_release_assets(self, snapshot) -> None:
        if snapshot is None:
            return
        files_snapshot, prior_state = snapshot
        files_snapshot.rollback()
        self.runner(["systemctl", "daemon-reload"], check=False, capture_output=True, text=True)
        self._restore_wifi_unit_state(prior_state)
        self.runner(["systemctl", "restart", "bt-signature-detector.service"], check=False, capture_output=True, text=True)
        self.runner(["systemctl", "restart", "bt-signature-detector-web.service"], check=False, capture_output=True, text=True)

    def stage(self, verified: VerifiedRelease) -> "StagedUpdate":
        from .updates import StagedUpdate
        self.staged_dir.mkdir(parents=True, exist_ok=True)
        staged_id = __import__("uuid").uuid4().hex
        target = self.staged_dir / staged_id
        target.mkdir(mode=0o700)
        manifest = verified.manifest
        wheel_version = manifest.version.replace("-", "_")
        wheel_name = f"bt_signature_detector-{wheel_version}-py3-none-any.whl"
        (target / wheel_name).write_bytes(verified.artifact_bytes)
        (target / "manifest.json").write_text(json.dumps({
            "version": manifest.version, "artifact_url": manifest.artifact_url,
            "sha256": manifest.sha256, "size_bytes": manifest.size_bytes,
            "release_notes": manifest.release_notes}, sort_keys=True), encoding="utf-8")
        return StagedUpdate(staged_id, target, manifest)

    def apply(self, staged_id: str) -> UpdateResult:
        if not re.fullmatch(r"[0-9a-f]{32}", staged_id): raise ValueError("invalid staged update id")
        stage = (self.staged_dir / staged_id).resolve()
        if stage.parent != self.staged_dir.resolve(): raise ValueError("staged update was not found")
        try:
            data = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
            manifest = ReleaseManifest(**data)
            wheel_version = manifest.version.replace("-", "_")
            wheel_path = stage / f"bt_signature_detector-{wheel_version}-py3-none-any.whl"
            artifact = wheel_path.read_bytes()
        except (OSError, ValueError, TypeError) as exc:
            raise ValueError("staged update metadata is invalid") from exc
        if len(artifact) != manifest.size_bytes:
            raise ValueError("staged artifact size mismatch")
        import hashlib
        if hashlib.sha256(artifact).hexdigest() != manifest.sha256:
            raise ValueError("staged artifact hash mismatch")
        old = self._get_active()
        self.releases_dir.mkdir(parents=True, exist_ok=True)
        slot_name = f"{manifest.version}-{staged_id[:8]}"
        slot = self.releases_dir / slot_name
        if slot.exists(): raise ValueError("release slot already exists")
        asset_snapshot = None
        try:
            if old is not None and old.is_dir(): shutil.copytree(old, slot, symlinks=True)
            else: slot.mkdir(parents=True)
            python = slot / "bin" / "python"
            if not python.exists():
                self.runner([sys.executable, "-m", "venv", str(slot)], check=True, capture_output=True, text=True)
                python = slot / "bin" / "python"
            self.runner([str(python), "-m", "pip", "install", "--no-deps", "--force-reinstall", str(wheel_path)],
                        check=True, capture_output=True, text=True)
            self._switch_active(slot)
            asset_snapshot = self._install_release_assets(slot)
            self.runner(["systemctl", "restart", "bt-signature-detector.service"], check=True, capture_output=True, text=True)
            if not self.health_check():
                self._switch_active(old)
                self._rollback_release_assets(asset_snapshot)
                if asset_snapshot is None:
                    self.runner(["systemctl", "restart", "bt-signature-detector.service"], check=False, capture_output=True, text=True)
                return UpdateResult(False, "health check failed; restored the previous release", True, manifest.version)
            shutil.rmtree(stage)
            return UpdateResult(True, "release applied and health check passed", False, manifest.version)
        except Exception as exc:
            if self._get_active() == slot:
                self._switch_active(old)
                self._rollback_release_assets(asset_snapshot)
                self.runner(["systemctl", "restart", "bt-signature-detector.service"], check=False, capture_output=True, text=True)
                if asset_snapshot is None:
                    self.runner(["systemctl", "restart", "bt-signature-detector-web.service"], check=False, capture_output=True, text=True)
            if slot.exists(): shutil.rmtree(slot, ignore_errors=True)
            return UpdateResult(False, f"update failed: {exc}", old is not None, manifest.version)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    data = path.read_bytes()
    try:
        key = serialization.load_pem_public_key(data)
        if isinstance(key, Ed25519PublicKey): return key
    except ValueError: pass
    try: return Ed25519PublicKey.from_public_bytes(data)
    except ValueError as exc: raise ValueError("update trust key is not a valid Ed25519 public key") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Restricted signed update coordinator")
    sub = parser.add_subparsers(dest="action", required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--id", required=True)
    args = parser.parse_args(argv)
    if os.name == "posix" and os.geteuid() != 0:
        print("update coordinator must run as root", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[0-9a-f]{32}", args.id):
        print("invalid staged update id", file=sys.stderr)
        return 2
    bundle_path = Path("/var/lib/bt-signature-detector/web/updates") / f"{args.id}.zip"
    try:
        if bundle_path.is_symlink(): raise ValueError("staged bundle must not be a symbolic link")
        verifier = UpdateVerifier(_load_public_key(Path("/etc/bt-signature-detector-trust/update.pub")))
        verified = verifier.verify_bundle(bundle_path)
        coordinator = UpdateCoordinator()
        staged = coordinator.stage(verified)
        result = coordinator.apply(staged.staged_id)
        print(json.dumps({"success": result.success, "message": result.message,
                          "rolled_back": result.rolled_back, "version": result.version}))
        if result.success:
            try: bundle_path.unlink()
            except OSError: pass
        return 0 if result.success else 1
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__": raise SystemExit(main())
