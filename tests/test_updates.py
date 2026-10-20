import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from bt_signature_detector.updates import ReleaseManifest, verify_bundle, verify_manifest, VerifiedRelease
from bt_signature_detector.updater_service import UpdateCoordinator


class UpdateVerificationTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.artifact = b"wheel bytes"
        self.manifest = {"version":"1.2.3", "artifact_url":"https://releases.example.invalid/1.2.3.whl",
            "sha256":hashlib.sha256(self.artifact).hexdigest(), "size_bytes":len(self.artifact), "release_notes":"Test release"}
        self.canonical = json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode()
        self.signature = self.private.sign(self.canonical)

    def bundle(self, path, artifact=None, manifest=None, signature=None, extra=()):
        manifest = manifest or self.canonical
        signature = signature or self.signature
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", manifest)
            archive.writestr("manifest.sig", signature)
            archive.writestr("artifact.whl", self.artifact if artifact is None else artifact)
            for name, data in extra: archive.writestr(name, data)

    def test_valid_signed_manifest_and_bundle(self):
        parsed = verify_manifest(self.canonical, self.signature, self.public)
        self.assertEqual(parsed.version, "1.2.3")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.zip"
            self.bundle(path)
            release = verify_bundle(path, parsed, self.public, 1024)
            self.assertEqual(release.manifest.version, "1.2.3")
            self.assertEqual(release.artifact_bytes, self.artifact)

    def test_invalid_signature_and_noncanonical_metadata_rejected(self):
        with self.assertRaises(ValueError): verify_manifest(self.canonical, b"bad", self.public)
        bad = json.dumps({**self.manifest, "version":"latest"}, indent=2).encode()
        with self.assertRaises(ValueError): verify_manifest(bad, self.private.sign(bad), self.public)

    def test_hash_mismatch_rejects_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.zip"
            self.bundle(path, artifact=b"tampered")
            with self.assertRaises(ValueError): verify_bundle(path, None, self.public, 1024)

    def test_oversize_and_unsafe_archive_paths_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.zip"
            self.bundle(path, extra=(("../outside", b"bad"),))
            with self.assertRaises(ValueError): verify_bundle(path, None, self.public, 1024)
            self.bundle(path)
            with self.assertRaises(ValueError): verify_bundle(path, None, self.public, 4)

    def test_health_failure_rolls_back_active_slot_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            state = Path(directory) / "state"
            state.mkdir()
            (state / "events.sqlite3").write_bytes(b"history")
            old = root / "venv-old"
            old.mkdir(parents=True)
            (old / "runtime.txt").write_text("old", encoding="utf-8")
            active = {"path": old}
            staged_dir = root / "staged"
            staged_dir.mkdir()
            verified = VerifiedRelease(
                ReleaseManifest("1.2.3", self.manifest["artifact_url"], self.manifest["sha256"], len(self.artifact), "Test release"), self.artifact)
            calls = []
            coordinator = UpdateCoordinator(root, state_dir=state, runner=lambda args, **kwargs: calls.append(args),
                health_check=lambda: False, get_active=lambda: active["path"], switch_active=lambda target: active.update(path=target))
            staged = coordinator.stage(verified)
            result = coordinator.apply(staged.staged_id)
            self.assertFalse(result.success)
            self.assertTrue(result.rolled_back)
            self.assertEqual(active["path"], old)
            self.assertEqual((state / "events.sqlite3").read_bytes(), b"history")

    def test_success_switches_active_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            old = root / "venv-old"
            old.mkdir(parents=True)
            (old / "runtime.txt").write_text("old", encoding="utf-8")
            active = {"path": old}
            verified = VerifiedRelease(
                ReleaseManifest("1.2.3", self.manifest["artifact_url"], self.manifest["sha256"], len(self.artifact), "Test release"), self.artifact)
            coordinator = UpdateCoordinator(root, runner=lambda *args, **kwargs: None,
                health_check=lambda: True, get_active=lambda: active["path"], switch_active=lambda target: active.update(path=target))
            staged = coordinator.stage(verified)
            result = coordinator.apply(staged.staged_id)
            self.assertTrue(result.success)
            self.assertTrue(active["path"].name.startswith("1.2.3-"))
            self.assertTrue((active["path"] / "runtime.txt").exists())

    def test_pip_receives_a_wheel_filename_not_the_bundle_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            old = root / "venv-old"
            old.mkdir(parents=True)
            active = {"path": old}
            calls = []
            verified = VerifiedRelease(
                ReleaseManifest("1.2.3", self.manifest["artifact_url"], self.manifest["sha256"], len(self.artifact), "Test release"),
                self.artifact,
            )
            coordinator = UpdateCoordinator(root, runner=lambda args, **kwargs: calls.append(args),
                health_check=lambda: True, get_active=lambda: active["path"],
                switch_active=lambda target: active.update(path=target))
            staged = coordinator.stage(verified)

            result = coordinator.apply(staged.staged_id)

            self.assertTrue(result.success)
            install_command = next(args for args in calls if "pip" in args)
            self.assertEqual(Path(install_command[-1]).name, "bt_signature_detector-1.2.3-py3-none-any.whl")

    def test_asset_install_failure_restores_old_web_service_after_slot_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            old = root / "venv-old"
            old.mkdir(parents=True)
            active = {"path": old}
            staged_dir = root / "staged"
            staged_dir.mkdir()
            verified = VerifiedRelease(
                ReleaseManifest("1.2.3", self.manifest["artifact_url"], self.manifest["sha256"], len(self.artifact), "Test release"), self.artifact)
            calls = []
            coordinator = UpdateCoordinator(root, runner=lambda args, **kwargs: calls.append(args),
                health_check=lambda: True, get_active=lambda: active["path"],
                switch_active=lambda target: active.update(path=target))
            coordinator._install_release_assets = lambda _slot: (_ for _ in ()).throw(RuntimeError("unit restart failed"))
            staged = coordinator.stage(verified)
            result = coordinator.apply(staged.staged_id)
            self.assertFalse(result.success)
            self.assertEqual(active["path"], old)
            self.assertIn(["systemctl", "restart", "bt-signature-detector-web.service"], calls)


if __name__ == "__main__": unittest.main()
