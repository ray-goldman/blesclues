#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import zipfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bt_signature_detector.updates import canonical_manifest


def package_release(wheel: Path, release_notes: str, version: str, private_key_path: Path,
                    output: Path, artifact_url: str | None = None) -> Path:
    wheel, private_key_path, output = Path(wheel), Path(private_key_path), Path(output)
    if wheel.suffix != ".whl" or not wheel.is_file(): raise ValueError("release artifact must be an existing wheel")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|[-+][A-Za-z0-9.-]+)?", version): raise ValueError("invalid release version")
    if len(release_notes) > 20_000: raise ValueError("release notes are too long")
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey): raise ValueError("release key must be Ed25519")
    artifact = wheel.read_bytes()
    manifest = {"version": version, "artifact_url": artifact_url or f"https://example.invalid/releases/{wheel.name}",
        "sha256": hashlib.sha256(artifact).hexdigest(), "size_bytes": len(artifact), "release_notes": release_notes}
    raw = canonical_manifest(manifest)
    signature = key.sign(raw)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".release-", suffix=".zip", dir=output.parent)
    import os
    os.close(fd)
    try:
        with zipfile.ZipFile(temp_name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", raw)
            archive.writestr("manifest.sig", signature)
            archive.writestr("artifact.whl", artifact)
        os.replace(temp_name, output)
    except Exception:
        try: os.unlink(temp_name)
        except OSError: pass
        raise
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create an Ed25519 signed BLE detector release bundle")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--private-key", type=Path, required=True, help="external PEM Ed25519 private key")
    parser.add_argument("--artifact-url")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    package_release(args.wheel, args.notes.read_text(encoding="utf-8"), args.version, args.private_key, args.output, args.artifact_url)
    print(args.output)
    return 0


if __name__ == "__main__": raise SystemExit(main())
