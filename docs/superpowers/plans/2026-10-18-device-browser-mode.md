# Temporary Device Browser Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an authenticated Devices page that temporarily switches the existing BLE scanner to broad active scanning and restores its saved mode and filters on Stop or reboot.

**Architecture:** The scanner service remains the only adapter owner. A small privileged helper manages a volatile mode override in `/run` and restarts that service; the scanner reads the override at startup. Advertisement processing continues through the existing detection pipeline, while a bounded volatile inventory snapshot feeds the new page.

**Tech Stack:** Python 3, Bleak, Flask, vanilla JavaScript/CSS, systemd, shell installer, `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-18-device-browser-mode-design.md`

## Global Constraints

- Active scanning is allowed only in the explicitly started temporary browser mode; it does not connect to or pair with devices.
- Normal scanning uses the saved Bluetooth mode and BlueZ filters unchanged.
- The scanner systemd service remains the sole owner of the Bluetooth adapter.
- Browser mode is stored only in `/run`, so it ends on reboot and never changes the saved YAML configuration.
- Device inventory is bounded and volatile; no routine device inventory or advertisement payload is written to persistent storage or logs.
- Device mode-changing endpoints require the existing authenticated session and CSRF token.
- Observed BLE addresses are radio identifiers and must not be represented as verified product or owner identities.

## Review Focus

- **Interrupted mode transition:** restart failure must roll back the runtime override and report actual mode. Pin with injected systemctl failure tests in Task 1.
- **Saved configuration changes during browser mode:** Stop must load the newest saved values. Pin with a settings-change-then-stop integration test in Task 2.
- **Noisy/repeated advertisements and address rotation:** repeated identifiers update one row, rotated identifiers remain separate, and the inventory is bounded/expired. Pin in Task 3.
- **Unauthorized or forged mode request:** authentication and CSRF failures must not call the privileged helper. Pin in Task 4.
- **Adapter unavailable during mode change:** keep browser mode stoppable and expose scanner failure instead of claiming a successful scan. Pin in Task 4.

---

### Task 1: Add the privileged temporary mode controller

**Files:**
- Create: `src/bt_signature_detector/device_browser.py`
- Create: `scripts/device_browser_helper.sh`
- Create: `systemd/bt-signature-detector-device-browser.sudoers`
- Modify: `scripts/install.sh`
- Modify: `scripts/uninstall.sh`
- Modify: `tests/test_install_scripts.py`
- Create: `tests/test_device_browser.py`

**Interfaces:**
- `set_browser_mode(active: bool, *, state_file: Path, restart: Callable[[], None]) -> bool`: atomically set or remove the runtime override, restart the scanner, and restore the prior override if restart fails. Return whether browser mode is active.
- Root helper accepts exactly one argument: `start` or `stop`; it calls `set_browser_mode` with `/run/bt-signature-detector/device-browser.json` and restarts only `bt-signature-detector.service`.
- Web sudoers grants `bt-web` exactly the `start` and `stop` helper invocations; no wildcard command arguments.

- [x] **Step 1: Write failing tests** for successful start/stop, idempotency, atomic override contents, rejected arguments, and restart-failure rollback.
- [x] **Step 2: Run the focused tests** with `python -m unittest tests.test_device_browser -v`; confirm the controller is missing or failing.
- [x] **Step 3: Implement** the injected controller and fixed-argument helper. Use a temporary file plus `os.replace`; do not interpolate user input into a shell command.
- [x] **Step 4: Add installation and uninstall handling** for the helper and exact sudoers rules; extend installer tests to assert deployment and removal.
- [x] **Step 5: Run focused tests** with `python -m unittest tests.test_device_browser tests.test_install_scripts -v`.
- [x] **Step 6: Commit skipped** — kept this shared worktree uncommitted because unrelated pre-existing Pi/deployment edits overlap; see the execution ledger.

### Task 2: Make scanner startup honor the runtime override

**Files:**
- Create: `src/bt_signature_detector/scan_mode.py`
- Modify: `src/bt_signature_detector/cli.py`
- Modify: `src/bt_signature_detector/scanner.py`
- Modify: `tests/test_scanner.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- `effective_bluetooth_config(config: BluetoothConfig, *, override_file: Path) -> BluetoothConfig`: when the valid runtime marker says browser mode is active, return a copy with `scan_mode="active"` and empty `or_patterns`; otherwise return the configured object unchanged.
- `detector scan` resolves the runtime mode once at startup and gives the resolved config to `BleScanner`; the rest of CLI and pipeline construction is unchanged.

- [x] **Step 1: Write failing tests** for passive configured mode, active configured mode, active browser override with no BlueZ filters, malformed/missing override fallback, and detection pipeline continuity.
- [x] **Step 2: Run focused tests** with `python -m unittest tests.test_scanner tests.test_cli -v`; confirm override behavior is not implemented.
- [x] **Step 3: Implement** the resolver and wire it into scanner startup using `/run/bt-signature-detector/device-browser.json` on Linux. Keep non-Pi/local test execution independent of `/run` when an override path is injected.
- [x] **Step 4: Run focused tests** with `python -m unittest tests.test_scanner tests.test_cli -v`.
- [x] **Step 5: Commit skipped** — kept this shared worktree uncommitted because unrelated pre-existing Pi/deployment edits overlap; see the execution ledger.

### Task 3: Add a bounded volatile device inventory

**Files:**
- Modify: `src/bt_signature_detector/runtime_cache.py`
- Modify: `src/bt_signature_detector/pipeline.py`
- Modify: `src/bt_signature_detector/cli.py`
- Modify: `tests/test_runtime_cache.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Add `RuntimeDeviceCache(path: Path, *, limit: int = 100, absence_seconds: int = 120)` with `add(advertisement: Advertisement) -> None`, `recent() -> list[dict]`, and static `read(path: Path, limit: int = 100) -> list[dict]`.
- Each row contains observed identifier, optional name, latest RSSI, first-seen and last-seen timestamps, manufacturer data (hex, capped at 32 bytes per company), and service UUIDs. Deduplicate only by exact observed identifier.
- `DetectionPipeline` accepts optional `device_cache`; it forwards every processed advertisement while retaining existing matching/storage behavior.

- [x] **Step 1: Write failing tests** for exact-address deduplication, first/last-seen behavior, rotated address separation, count bound, absence expiry, volatile snapshot serialization, and pipeline forwarding without changing emitted events.
- [x] **Step 2: Run focused tests** with `python -m unittest tests.test_runtime_cache tests.test_pipeline -v`; confirm the inventory API is absent.
- [x] **Step 3: Implement** a separately bounded inventory with expiry and a one-second-or-slower snapshot flush to `/run`; pass `web.max_live_scans` and `detection.absence_seconds` from CLI.
- [x] **Step 4: Run focused tests** with `python -m unittest tests.test_runtime_cache tests.test_pipeline -v`.
- [x] **Step 5: Commit skipped** — kept this shared worktree uncommitted because unrelated pre-existing Pi/deployment edits overlap; see the execution ledger.

### Task 4: Add authenticated Devices page and mode APIs

**Files:**
- Modify: `src/bt_signature_detector/web.py`
- Create: `src/bt_signature_detector/web_templates/devices.html`
- Create: `src/bt_signature_detector/web_static/devices.js`
- Modify: `src/bt_signature_detector/web_static/style.css`
- Modify: `src/bt_signature_detector/web_templates/index.html`
- Modify: `src/bt_signature_detector/web_templates/settings.html`
- Modify: `src/bt_signature_detector/web_templates/updates.html`
- Modify: `tests/test_web.py`
- Create: `tests/test_web_devices.py`

**Interfaces:**
- Extend `WebServices` with optional `devices: Callable[[], list[dict]]`, `browser_mode: Callable[[], bool]`, and `set_browser_mode: Callable[[bool], bool]`.
- Add authenticated `GET /api/devices/status`, `GET /api/devices`, `POST /api/devices/start`, and `POST /api/devices/stop`.
- `GET /api/status` includes configured mode, effective mode, and browser-active state.
- `POST` routes use the existing `login_required` and CSRF mechanisms and invoke helper callbacks with literal booleans only.

- [x] **Step 1: Write failing tests** for authenticated/CSRF-protected start/stop, unauthenticated access, helper failure status, bounded inventory response, configured versus effective status, and adapter unavailable reporting without disabling Stop.
- [x] **Step 2: Run focused tests** with `python -m unittest tests.test_web_devices tests.test_web -v`; confirm routes and page are missing.
- [x] **Step 3: Implement** routes and Flask service wiring. Invoke sudo with an argv list and fixed helper path; read mode state from the runtime marker and inventory from `/run/bt-signature-detector/devices.json`.
- [x] **Step 4: Build the Devices page** with distinct stopped/scanning/error states, Start/Stop controls, escaped text rendering, and a responsive live device table; add navigation links on all authenticated pages.
- [x] **Step 5: Run focused tests** with `python -m unittest tests.test_web_devices tests.test_web -v` and check JavaScript syntax with `node --check src/bt_signature_detector/web_static/devices.js`.
- [x] **Step 6: Commit skipped** — kept this shared worktree uncommitted because unrelated pre-existing Pi/deployment edits overlap; see the execution ledger.

### Task 5: Document operation and verify full integration

**Files:**
- Modify: `README.md`
- Modify: `docs/raspberry-pi-install.md`
- Modify: `docs/troubleshooting.md`
- Modify: `tests/test_docs.py`
- Modify: `tests/test_install_scripts.py`

**Interfaces:**
- Document Devices as temporary active BLE discovery, with scan requests allowed, no connection/pairing, no persistent device history, and Stop/reboot restoration behavior.
- Document that configured BlueZ filters remain the normal mode and are managed under Settings; the browser does not edit them.

- [x] **Step 1: Write failing documentation assertions** for temporary-mode semantics, privacy/storage limits, and install/uninstall coverage.
- [x] **Step 2: Run focused tests** with `python -m unittest tests.test_docs tests.test_install_scripts -v`.
- [x] **Step 3: Update documentation** and make required installer adjustments discovered during integration.
- [x] **Step 4: Run the full suite** with `python -m unittest discover -v`, `node --check src/bt_signature_detector/web_static/devices.js`, and `git diff --check`.
- [x] **Step 5: Deploy to the Pi** with the built wheel and fixed helper, verify active mode reports healthy and lists advertisers, then Stop and confirm the saved passive mode/filter return. The marker lives in `/run`, so reboot clears it; no Pi reboot is needed for this check.
- [x] **Step 6: Commit skipped** — kept this shared worktree uncommitted because unrelated pre-existing Pi/deployment edits overlap; see the execution ledger.

## Self-review

- **Spec coverage:** Scanner ownership, active unfiltered mode, saved configuration preservation, Stop/reboot restoration, continued detection processing, bounded volatile inventory, authenticated APIs, CSRF, failure rollback, UI states, no pairing/connection, and documentation each have an owning task.
- **Step scan:** Tasks name the exact API, CLI, inventory, and helper interfaces and list focused checks before implementation; no task relies on an unspecified mode value or state path.
- **Type consistency:** The controller writes the path consumed by `effective_bluetooth_config`; the CLI writes observations to the cache whose reader is injected into `WebServices`; web callbacks accept a boolean and helper arguments remain literal `start`/`stop`.
- **Review focus:** Restart failure is Task 1; changed saved config is Task 2; repeated/rotating/expired devices are Task 3; authorization/CSRF and adapter failures are Task 4.
- **Proportion:** Five tasks follow the separable mode-controller, scanner, inventory, UI/API, and operations boundaries described in the spec.
