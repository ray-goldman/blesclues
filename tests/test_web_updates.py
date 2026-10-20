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
from bt_signature_detector.updates import canonical_manifest
from bt_signature_detector.web_updates import WebUpdateManager


class WebUpdateTests(unittest.TestCase):
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
