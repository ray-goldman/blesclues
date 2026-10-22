from __future__ import annotations

from pathlib import Path
import subprocess
import threading
import re

from .updates import HttpTransport, UpdateVerifier, check_release, stage_download, stage_upload
from .updater_service import _load_public_key


def _version_key(value: str):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?", value)
    if not match:
        return None
    major, minor, patch, prerelease, number = match.groups()
    rank = {"a": 0, "b": 1, "rc": 2, None: 3}[prerelease]
    return int(major), int(minor), int(patch), rank, int(number or 0)


def _is_newer(candidate: str, installed: str) -> bool:
    candidate_key = _version_key(candidate)
    installed_key = _version_key(installed)
    if candidate_key is None or installed_key is None:
        return candidate != installed
    return candidate_key > installed_key


class WebUpdateManager:
    """Unprivileged release checker/stager. Applying delegates to the fixed root helper."""
    def __init__(self, *, manifest_url: str | None, public_key_file: Path,
                 staging_dir: Path, max_bytes: int = 20_000_000,
                 timeout: float = 10.0, transport=None, apply_runner=subprocess.run) -> None:
        self.manifest_url = manifest_url
        self.public_key_file = Path(public_key_file)
        self.staging_dir = Path(staging_dir)
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.transport = transport or HttpTransport()
        self.apply_runner = apply_runner
        self._lock = threading.Lock()
        self._latest = None
        self._staged: dict[str, dict] = {}
        self._last_check = "Not checked"
        from . import __version__
        self.installed_version = __version__
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._recover_staged()

    def _verifier(self) -> UpdateVerifier:
        return UpdateVerifier(_load_public_key(self.public_key_file), self.max_bytes)

    def _recover_staged(self) -> None:
        try: verifier = self._verifier()
        except (OSError, ValueError): return
        paths = sorted(self.staging_dir.glob("*.zip"), key=lambda path: path.stat().st_mtime, reverse=True)
        recovered_versions = set()
        for path in paths:
            if not re.fullmatch(r"[0-9a-f]{32}\.zip", path.name): continue
            try:
                release = verifier.verify_bundle(path)
                version = release.manifest.version
                if not _is_newer(version, self.installed_version):
                    path.unlink(missing_ok=True)
                    continue
                if version in recovered_versions:
                    path.unlink(missing_ok=True)
                    continue
                recovered_versions.add(version)
                staged_id = path.stem
                self._staged[staged_id] = {"id": staged_id, "version": version,
                    "release_notes": release.manifest.release_notes, "source": "staged"}
            except (OSError, ValueError):
                continue

    def _remember_staged(self, staged, source: str) -> dict:
        if not _is_newer(staged.manifest.version, self.installed_version):
            staged.path.unlink(missing_ok=True)
            state = "already installed" if staged.manifest.version == self.installed_version else "older than the installed version"
            raise ValueError(f"Version {staged.manifest.version} is {state}")
        result = {"id": staged.staged_id, "version": staged.manifest.version,
                  "release_notes": staged.manifest.release_notes, "source": source}
        with self._lock:
            for staged_id, existing in list(self._staged.items()):
                if existing["version"] == result["version"]:
                    self._staged.pop(staged_id)
                    (self.staging_dir / f"{staged_id}.zip").unlink(missing_ok=True)
            self._staged[staged.staged_id] = result
        return result

    def check(self) -> dict:
        if not self.manifest_url: raise ValueError("No HTTPS release manifest URL is configured")
        try:
            release = check_release(self.manifest_url, self.transport, self._verifier(), self.timeout)
        except Exception as exc:
            with self._lock: self._last_check = f"Check failed: {exc}"
            raise
        version = release.manifest.version
        available = _is_newer(version, self.installed_version)
        with self._lock:
            self._latest = release if available else None
            if available:
                self._last_check = "Release available"
            elif version == self.installed_version:
                self._last_check = "Installed version is current"
            else:
                self._last_check = "Installed version is newer"
        return {"version": version, "release_notes": release.manifest.release_notes,
                "update_available": available, "already_installed": version == self.installed_version}

    def upload(self, stream) -> dict:
        staged = stage_upload(stream, self.staging_dir, self._verifier())
        return self._remember_staged(staged, "upload")

    def stage_download(self) -> dict:
        with self._lock:
            release = self._latest
            last_check = self._last_check
        if release is None:
            if last_check == "Installed version is current":
                raise ValueError("The installed version is already current")
            if last_check == "Installed version is newer":
                raise ValueError("No newer release is available")
            raise ValueError("Check for a release before staging a download")
        staged = stage_download(release, self.transport, self.staging_dir, self._verifier(), self.timeout)
        return self._remember_staged(staged, "download")

    def status(self) -> dict:
        with self._lock:
            return {"installed_version": self.installed_version, "last_check": self._last_check,
                "available": ({"version": self._latest.manifest.version,
                    "release_notes": self._latest.manifest.release_notes} if self._latest else None),
                "staged": list(self._staged.values())}

    def apply(self, staged_id: str) -> dict:
        if staged_id not in self._staged or not (self.staging_dir / f"{staged_id}.zip").is_file():
            raise ValueError("Unknown or expired staged update")
        command = ["sudo", "-n", "/usr/local/sbin/bt-detector-apply-update"]
        result = self.apply_runner(command, input=staged_id + "\n", check=False, capture_output=True, text=True, timeout=300)
        try:
            import json
            response = json.loads(result.stdout or result.stderr)
        except (ValueError, AttributeError):
            response = {"success": result.returncode == 0, "message": result.stderr or "Update helper completed"}
        if response.get("success"):
            with self._lock: self._staged.pop(staged_id, None)
        return response
