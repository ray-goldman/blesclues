import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from subprocess import CompletedProcess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bt_signature_detector import __version__
from bt_signature_detector.updates import canonical_manifest
from bt_signature_detector.web_updates import WebUpdateManager, _is_newer


class WebUpdateTests(unittest.TestCase):
    def test_release_version_comparison_ignores_matching_and_older_builds(self):
        self.assertFalse(_is_newer("0.1.0b5", "0.1.0b5"))
        self.assertFalse(_is_newer("0.1.0b4", "0.1.0b5"))
        self.assertTrue(_is_newer("0.1.0b6", "0.1.0b5"))
        self.assertTrue(_is_newer("0.1.0", "0.1.0rc1"))


    def test_check_does_not_offer_the_installed_release_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = Ed25519PrivateKey.generate()
            public_path = root / "update.pub"
            public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            artifact = b"signed wheel"
            manifest = canonical_manifest({"version":__version__, "artifact_url":"https://feed.example.invalid/bundle.zip",
                "sha256":hashlib.sha256(artifact).hexdigest(), "size_bytes":len(artifact),
                "release_notes":"Beta 6"})
            signature = key.sign(manifest)

            class FeedTransport:
                def get(self, url, timeout, max_bytes):
                    return manifest if url.endswith("stable.json") else signature

            manager = WebUpdateManager(manifest_url="https://feed.example.invalid/stable.json",
                public_key_file=public_path, staging_dir=root / "updates", max_bytes=1024,
                transport=FeedTransport())

            result = manager.check()

            self.assertTrue(result["already_installed"])
            self.assertEqual(manager.status()["last_check"], "Installed version is current")
            self.assertIsNone(manager.status()["available"])
            with self.assertRaisesRegex(ValueError, "already current"):
                manager.stage_download()

            staged_id = "a" * 32
            staged_path = manager.staging_dir / f"{staged_id}.zip"
            with zipfile.ZipFile(staged_path, "w") as archive:
                archive.writestr("manifest.json", manifest)
                archive.writestr("manifest.sig", signature)
                archive.writestr("artifact.whl", artifact)
            restarted = WebUpdateManager(manifest_url=None, public_key_file=public_path,
                staging_dir=manager.staging_dir, max_bytes=1024, transport=FeedTransport())
            self.assertEqual(restarted.status()["staged"], [])
            self.assertFalse(staged_path.exists())
    def test_updates_page_exposes_apply_progress_and_restart_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            from bt_signature_detector.web import WebServices, create_app
            app = create_app(WebServices(root / "password.hash", root / "session.key"))
            client = app.test_client()
            client.post("/setup", data={"password": "a-good-password"})

            page = client.get("/updates")
            self.assertIn(b'id="apply-progress"', page.data)
            self.assertIn(b'aria-live="polite"', page.data)
            self.assertIn(b"Do not apply again while the Pi is restarting", page.data)
            script = client.get("/static/updates.js")
            self.assertIn(b"applyInProgress", script.data)
            self.assertIn(b"waitForInstalledVersion", script.data)
            self.assertIn(b"Pi is restarting", script.data)
            self.assertNotIn(b"staged.innerHTML", script.data)
            self.assertIn(b"is already installed", script.data)
            self.assertIn(b"update_available", script.data)
            script.close()

    def test_signed_upload_persists_as_staged_and_apply_is_id_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = Ed25519PrivateKey.generate()
            public_path = root / "update.pub"
            public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            artifact = b"signed wheel"
            manifest = canonical_manifest({"version":"1.2.3", "artifact_url":"https://feed.example.invalid/bundle.zip",
                "sha256":hashlib.sha256(artifact).hexdigest(), "size_bytes":len(artifact), "release_notes":"Release notes"})
            bundle = io.BytesIO()
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("manifest.json", manifest)
                archive.writestr("manifest.sig", key.sign(manifest))
                archive.writestr("artifact.whl", artifact)
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                return CompletedProcess(command, 0, '{"success":true}', "")
            staging = root / "updates"
            manager = WebUpdateManager(manifest_url=None, public_key_file=public_path,
                staging_dir=staging, max_bytes=1024, apply_runner=run)
            staged = manager.upload(io.BytesIO(bundle.getvalue()))
            self.assertEqual(staged["version"], "1.2.3")
            duplicate = manager.upload(io.BytesIO(bundle.getvalue()))
            self.assertEqual(duplicate["version"], "1.2.3")
            self.assertNotEqual(duplicate["id"], staged["id"])
            self.assertEqual(len(manager.status()["staged"]), 1)
            self.assertFalse((staging / f"{staged['id']}.zip").exists())
            duplicate_id = "a" * 32
            (staging / f"{duplicate_id}.zip").write_bytes((staging / f"{duplicate['id']}.zip").read_bytes())
            again = WebUpdateManager(manifest_url=None, public_key_file=public_path,
                staging_dir=staging, max_bytes=1024, apply_runner=run)
            self.assertEqual(len(again.status()["staged"]), 1)
            remaining_id = again.status()["staged"][0]["id"]
            self.assertEqual(len(list(staging.glob("*.zip"))), 1)
            self.assertTrue(again.apply(remaining_id)["success"])
            self.assertEqual(commands[0], ["sudo", "-n", "/usr/local/sbin/bt-detector-apply-update"])


if __name__ == "__main__": unittest.main()
