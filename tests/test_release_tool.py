import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from bt_signature_detector.updates import verify_bundle
from scripts.package_release import package_release


class ReleaseToolTests(unittest.TestCase):
    def test_release_package_is_signed_with_external_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "bt_signature_detector-1.2.3-py3-none-any.whl"
            wheel.write_bytes(b"wheel")
            key = Ed25519PrivateKey.generate()
            key_path = root / "private.pem"
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            bundle = root / "release.zip"
            package_release(wheel, "Release notes", "1.2.3", key_path, bundle)
            result = verify_bundle(bundle, None, key.public_key(), 1024)
            self.assertEqual(result.manifest.version, "1.2.3")
            self.assertEqual(result.artifact_bytes, b"wheel")
            self.assertNotIn("private.pem", [entry.filename for entry in __import__("zipfile").ZipFile(bundle).infolist()])


if __name__ == "__main__": unittest.main()
