from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import os
import uuid
import zipfile
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True, slots=True)
class ReleaseManifest:
    version: str
    artifact_url: str
    sha256: str
    size_bytes: int
    release_notes: str


@dataclass(frozen=True, slots=True)
class VerifiedRelease:
    manifest: ReleaseManifest
    artifact_bytes: bytes
    artifact_name: str = "artifact.whl"


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    manifest: ReleaseManifest
    manifest_bytes: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class StagedUpdate:
    staged_id: str
    path: Path
    manifest: ReleaseManifest


class HttpTransport:
    def get(self, url: str, timeout: float, max_bytes: int) -> bytes:
        _require_https(url)
        request = Request(url, headers={"User-Agent": "bt-signature-detector-updater/1"})
        class HttpsRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                _require_https(newurl)
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        with build_opener(HttpsRedirect()).open(request, timeout=timeout) as response:
            chunks = response.read(max_bytes + 1)
        if len(chunks) > max_bytes: raise ValueError("update response exceeds configured size limit")
        return chunks


class UpdateVerifier:
    def __init__(self, public_key: Ed25519PublicKey, max_bytes: int = 20_000_000) -> None:
        self.public_key = public_key
        self.max_bytes = max_bytes

    def verify_manifest(self, data: bytes, signature: bytes) -> ReleaseManifest:
        return verify_manifest(data, signature, self.public_key)

    def verify_bundle(self, path: Path, expected: ReleaseManifest | None = None) -> VerifiedRelease:
        return verify_bundle(path, expected, self.public_key, self.max_bytes)


def _require_https(url: str) -> None:
    if not isinstance(url, str): raise ValueError("update URL must be a string")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("update URL must be a valid HTTPS URL")


def check_release(manifest_url: str, transport: HttpTransport, verifier: UpdateVerifier,
                  timeout: float = 10.0) -> ReleaseInfo:
    _require_https(manifest_url)
    data = transport.get(manifest_url, timeout, min(verifier.max_bytes, 1_000_000))
    signature = transport.get(manifest_url + ".sig", timeout, 1024)
    manifest = verifier.verify_manifest(data, signature)
    return ReleaseInfo(manifest, data, signature)


def _stage_bytes(raw: bytes, staging_dir: Path, verifier: UpdateVerifier,
                 expected: ReleaseManifest | None = None) -> StagedUpdate:
    if len(raw) > verifier.max_bytes: raise ValueError("release bundle exceeds configured size limit")
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".incoming-", suffix=".zip", dir=staging_dir)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        verified = verifier.verify_bundle(Path(temp_name), expected)
        staged_id = uuid.uuid4().hex
        final_path = staging_dir / f"{staged_id}.zip"
        os.replace(temp_name, final_path)
        return StagedUpdate(staged_id, final_path, verified.manifest)
    except Exception:
        try: os.unlink(temp_name)
        except OSError: pass
        raise


def stage_upload(stream, staging_dir: Path, verifier: UpdateVerifier) -> StagedUpdate:
    raw = stream.read(verifier.max_bytes + 1)
    if not isinstance(raw, bytes): raise ValueError("upload stream must provide bytes")
    return _stage_bytes(raw, staging_dir, verifier)


def stage_download(release: ReleaseInfo, transport: HttpTransport, staging_dir: Path,
                   verifier: UpdateVerifier, timeout: float = 10.0) -> StagedUpdate:
    _require_https(release.manifest.artifact_url)
    raw = transport.get(release.manifest.artifact_url, timeout, verifier.max_bytes)
    return _stage_bytes(raw, staging_dir, verifier, release.manifest)


def canonical_manifest(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def verify_manifest(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> ReleaseManifest:
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("manifest must be UTF-8 JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"version", "artifact_url", "sha256", "size_bytes", "release_notes"}:
        raise ValueError("manifest has missing or unsupported fields")
    canonical = canonical_manifest(parsed)
    if data != canonical:
        raise ValueError("manifest is not canonical JSON")
    try: public_key.verify(signature, canonical)
    except InvalidSignature as exc: raise ValueError("manifest signature is invalid") from exc
    version = parsed["version"]
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise ValueError("manifest version is invalid")
    url = parsed["artifact_url"]
    try: _require_https(url)
    except ValueError as exc: raise ValueError("artifact_url must use HTTPS") from exc
    digest = parsed["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
    size = parsed["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError("size_bytes must be a positive integer")
    notes = parsed["release_notes"]
    if not isinstance(notes, str) or len(notes) > 20_000:
        raise ValueError("release_notes must be a string no longer than 20000 characters")
    return ReleaseManifest(version, url, digest, size, notes)


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name and not name.startswith("/")


def verify_bundle(path: Path, expected: ReleaseManifest | None, public_key: Ed25519PublicKey,
                  max_bytes: int) -> VerifiedRelease:
    path = Path(path)
    size_on_disk = path.stat().st_size
    if size_on_disk > max_bytes: raise ValueError("bundle exceeds configured size limit")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != 3 or len(set(names)) != len(names) or set(names) != {"manifest.json", "manifest.sig", "artifact.whl"}:
                raise ValueError("bundle must contain exactly manifest.json, manifest.sig, and artifact.whl")
            if any(not _safe_member(info.filename) or info.is_dir() for info in infos):
                raise ValueError("bundle contains an unsafe archive path")
            for info in infos:
                if info.flag_bits & 1 or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                    raise ValueError("encrypted or linked archive entries are not allowed")
            if sum(info.file_size for info in infos) > max_bytes:
                raise ValueError("expanded bundle exceeds configured size limit")
            raw_manifest = archive.read("manifest.json")
            signature = archive.read("manifest.sig")
            artifact = archive.read("artifact.whl")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError(f"unable to read release bundle: {exc}") from exc
    manifest = verify_manifest(raw_manifest, signature, public_key)
    if expected is not None and manifest != expected:
        raise ValueError("bundle manifest does not match expected release")
    if len(artifact) != manifest.size_bytes:
        raise ValueError("artifact size does not match signed manifest")
    if hashlib.sha256(artifact).hexdigest() != manifest.sha256:
        raise ValueError("artifact SHA-256 does not match signed manifest")
    return VerifiedRelease(manifest, artifact)
