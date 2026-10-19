import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bt_signature_detector.updates import UpdateVerifier, check_release, stage_download, stage_upload, canonical_manifest, verify_manifest


class FakeTransport:
    def __init__(self, resources): self.resources = resources
    def get(self, url, timeout, max_bytes):
        data = self.resources[url]
        if len(data) > max_bytes: raise ValueError("response too large")
        return data


class UpdateSourceTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.verifier = UpdateVerifier(self.private.public_key(), 10000)
        self.artifact = b"whl bytes"
        self.manifest_data = {"version":"2.0.1", "artifact_url":"https://updates.example.invalid/release.zip",
            "sha256":hashlib.sha256(self.artifact).hexdigest(), "size_bytes":len(self.artifact), "release_notes":"Notes"}
        self.manifest = canonical_manifest(self.manifest_data)
        self.signature = self.private.sign(self.manifest)
        self.bundle = io.BytesIO()
        with zipfile.ZipFile(self.bundle, "w") as archive:
            archive.writestr("manifest.json", self.manifest)
            archive.writestr("manifest.sig", self.signature)
            archive.writestr("artifact.whl", self.artifact)
        self.bundle_data = self.bundle.getvalue()

    def test_signed_https_feed_and_download_staging(self):
        manifest_url = "https://updates.example.invalid/stable.json"
        release = check_release(manifest_url, FakeTransport({manifest_url:self.manifest, manifest_url + ".sig":self.signature}), self.verifier)
        with tempfile.TemporaryDirectory() as directory:
            staged = stage_download(release, FakeTransport({release.manifest.artifact_url:self.bundle_data}), Path(directory), self.verifier)
            self.assertTrue(staged.path.exists())
            self.assertEqual(staged.manifest.version, "2.0.1")

    def test_rejects_non_https_manifest_and_artifact_urls(self):
        with self.assertRaises(ValueError): check_release("http://bad", FakeTransport({}), self.verifier)
        data = {**self.manifest_data, "artifact_url":"http://bad"}
        with self.assertRaises(ValueError): self.verifier.verify_manifest(canonical_manifest(data), self.private.sign(canonical_manifest(data)))

    def test_response_too_large_and_failed_upload_leaves_no_partial_file(self):
        url = "https://updates.example.invalid/stable.json"
        with self.assertRaises(ValueError): check_release(url, FakeTransport({url:b"x"*10001}), self.verifier)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): stage_upload(io.BytesIO(b"not a zip"), Path(directory), self.verifier)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_uploaded_bundle_uses_same_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            result = stage_upload(io.BytesIO(self.bundle_data), Path(directory), self.verifier)
            self.assertEqual(result.manifest.version, "2.0.1")

    def test_alpha_build_version_is_valid_in_signed_manifest(self):
        data = {**self.manifest_data, "version": "0.1.0a1"}
        raw = canonical_manifest(data)
        release = verify_manifest(raw, self.private.sign(raw), self.private.public_key())
        self.assertEqual(release.version, "0.1.0a1")


if __name__ == "__main__": unittest.main()
