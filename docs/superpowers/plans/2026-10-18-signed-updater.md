# Signed Software Update Implementation Plan

> **For agentic workers:** Required sub-skill: use `superpowers:executing-plans` to implement this plan task by task. Do not begin implementation until the user approves the plan and selects an execution method.

**Goal:** Let an authenticated UI user check HTTPS releases or upload a signed bundle, then explicitly stage/install a verified build with automatic rollback if it fails health checks.

**Architecture:** One verifier accepts the same signed release format from HTTPS or local upload. A narrowly scoped updater service installs into an inactive version slot, switches atomically, checks service health, and restores the previous slot on failure; state/config/database remain outside release slots.

**Tech Stack:** Python, `cryptography` Ed25519, HTTPS, Flask upload endpoint, systemd updater service, `unittest`.

**Spec:** [2026-10-18-raspberry-pi-ble-signature-detector-design.md](../specs/2026-10-18-raspberry-pi-ble-signature-detector-design.md)

## Global Constraints

- HTTPS manifests and uploaded release bundles must verify with the root-owned Ed25519 public key.
- Hash, version, archive paths, metadata, and file size are validated before installation.
- Updates are manual-only: user checks, stages, and explicitly confirms apply.
- Never execute arbitrary uploaded scripts or expose update trust-key changes through the web UI.
- Preserve config, secrets, SQLite data, and previous known-good release; rollback on failed health check.

## Review Focus

- A valid signature cannot compensate for a bad artifact digest: `test_updates.py::test_hash_mismatch_rejects_bundle`.
- Forged signatures, malformed manifests, and oversized/path-traversal uploads must be rejected before staging: `test_updates.py::test_rejects_invalid_signature_and_archive_paths`.
- Non-HTTPS manifest/artifact URLs must be rejected: `test_update_sources.py::test_rejects_non_https_manifest_and_artifact_urls`.
- A failed post-switch health check must restore the previous release: `test_updates.py::test_health_failure_rolls_back_active_slot`.
- Failed update attempts must preserve config/database bytes: `test_updates.py::test_rollback_preserves_state_directory`.

---

### Task 1: Signed manifest and bundle verifier

**Files:**
- Create: `src/bt_signature_detector/updates.py`
- Create: `scripts/package_release.py`
- Create: `tests/test_updates.py`
- Create: `tests/test_release_tool.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes root-owned Ed25519 public-key path and release metadata.
- Produces `ReleaseManifest(version: str, artifact_url: str, sha256: str, size_bytes: int, release_notes: str)`, `verify_manifest(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> ReleaseManifest`, and `verify_bundle(path: Path, expected: ReleaseManifest | None, public_key: Ed25519PublicKey, max_bytes: int) -> VerifiedRelease`.
- Uses UTF-8 JSON with sorted keys and compact separators for canonical manifest bytes, SHA-256 artifact digest, version metadata, maximum artifact size, and safe archive path/type validation.
- Release tooling accepts a wheel, release notes, version, and external private-key path, then emits a signed manifest/bundle without copying the key into the repository or artifact.

- [ ] **Step 1: Write failing tests** for valid manifest/bundle, invalid signature, bad hash, unsupported version, malformed metadata, oversize artifact, zip/tar path traversal, and release-tool output/signature verification.
- [ ] **Step 2: Run** `python -m unittest tests.test_updates -v`; confirm tests fail at missing verifier functions.
- [ ] **Step 3: Implement Ed25519 verification, safe artifact validation, and external-key release packaging** without extracting or executing content during verification.
- [ ] **Step 4: Run** `python -m unittest tests.test_updates tests.test_release_tool -v`; confirm verifier and release-tool cases pass.
- [ ] **Step 5: Commit** with `feat: verify and package signed detector releases`.

### Task 2: Release check, upload intake, and staging

**Files:**
- Modify: `src/bt_signature_detector/updates.py`
- Create: `tests/test_update_sources.py`
- Modify: `src/bt_signature_detector/config.py`
- Modify: `config/detector.example.yaml`

**Interfaces:**
- Produces `check_release(manifest_url: str, transport: HttpTransport, verifier: UpdateVerifier) -> ReleaseInfo`, `stage_upload(stream, staging_dir: Path, verifier) -> StagedUpdate`, and `stage_download(release: ReleaseInfo, transport, staging_dir, verifier) -> StagedUpdate`.
- HTTPS timeout, maximum content length, and HTTPS-only URL validation are explicit; uploads share identical signature/hash checks.

- [ ] **Step 1: Write failing tests** for offline checks, non-HTTPS URLs, HTTPS errors, max response size, signed feed success, uploaded bundle verification, and no partial staged files on failure.
- [ ] **Step 2: Run** `python -m unittest tests.test_update_sources -v`; confirm source handling fails.
- [ ] **Step 3: Implement bounded HTTPS and local upload intake** with injected transports and atomic staging.
- [ ] **Step 4: Run** `python -m unittest tests.test_updates tests.test_update_sources -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: stage verified detector updates`.

### Task 3: Privileged updater, version slots, health checks, and rollback

**Files:**
- Create: `src/bt_signature_detector/updater_service.py`
- Create: `systemd/bt-signature-detector-updater.service`
- Modify: `systemd/bt-signature-detector.service`
- Modify: `tests/test_updates.py`
- Modify: `scripts/install.sh`
- Modify: `scripts/uninstall.sh`

**Interfaces:**
- Produces `UpdateCoordinator.stage(verified: VerifiedRelease) -> StagedUpdate` and `UpdateCoordinator.apply(staged_id: str) -> UpdateResult`.
- IPC accepts only status, stage, and apply requests for a validated staged artifact; it cannot run arbitrary commands or select arbitrary filesystem paths.
- Uses inactive versioned venv slots, atomic active-pointer switch, bounded health wait, rollback to prior pointer on failure, and persistent state outside slots.

- [ ] **Step 1: Write failing coordinator tests** for stage/apply lifecycle, active slot switch, health pass, rollback, state preservation, and rejection of arbitrary IPC paths/actions.
- [ ] **Step 2: Run** `python -m unittest tests.test_updates -v`; confirm coordinator tests fail.
- [ ] **Step 3: Implement isolated updater service and version-slot activation**; never write user config/database into an application slot.
- [ ] **Step 4: Run** `python -m unittest tests.test_updates -v`; confirm rollback and preservation pass.
- [ ] **Step 5: Commit** with `feat: apply detector updates with rollback`.

### Task 4: Authenticated update UI and release documentation

**Files:**
- Modify: `src/bt_signature_detector/web.py`
- Modify: `web/templates/index.html`
- Modify: `web/static/app.js`
- Create: `docs/software-updates.md`
- Modify: `tests/test_web.py`
- Modify: `tests/test_docs.py`

**Interfaces:**
- Adds authenticated endpoints for check, signed upload, staged status, and explicit apply confirmation; request handlers delegate to `UpdateCoordinator` and never perform privileged filesystem operations.
- UI displays installed/available versions, release notes, last check result, stage/apply state, and offline/no-uplink status.

- [ ] **Step 1: Write failing UI tests** for CSRF/auth on all update routes, check/upload/status/apply lifecycle, explicit apply confirmation, and rejection of unsigned uploads.
- [ ] **Step 2: Run** `python -m unittest tests.test_web tests.test_docs -v`; confirm update UI/docs tests fail.
- [ ] **Step 3: Implement UI integration and release guide** covering signing-key custody, manifest format, local upload, manual install, rollback, and offline behavior.
- [ ] **Step 4: Run** `python -m unittest discover -s tests -v`; confirm complete suite passes without network or Pi hardware.
- [ ] **Step 5: Commit** with `feat: manage signed updates through web UI`.
