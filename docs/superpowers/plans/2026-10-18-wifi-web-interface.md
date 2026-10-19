# Wi-Fi Access Point and Web Interface Implementation Plan

> **Approved design revision (2026-10-18):** Replace the old broadcast `BLE-Detector` network with a hidden optional `Detector-Admin` AP, disabled by default, with initial password `easypassword`. It has no internet forwarding. Admin UI access remains password-protected and available on both Ethernet and AP. The UI is refreshed to a clean operations console. Routine scans remain in memory; service journal output is rate-limited for SD-card durability. Notes below are historical where they conflict with this revision.

> **For agentic workers:** Required sub-skill: use `superpowers:executing-plans` to implement this plan task by task. Do not begin implementation until the user approves the plan and selects an execution method.

**Goal:** Provide an authenticated local UI for scanner status, live/recent output, safe configuration edits, an optional hidden AP, and software updates over Ethernet or the AP.

**Architecture:** A Flask/Waitress UI binds to Ethernet and the local AP address, requires a separately created UI password, and allows only whitelisted detector/update changes. The hidden AP is off by default and can be controlled in Settings. Live observations remain bounded in memory.

**Tech Stack:** NetworkManager, Python Flask and Waitress, same-origin HTML/JS/CSS, `unittest`.

**Spec:** [2026-10-18-raspberry-pi-ble-signature-detector-design.md](../specs/2026-10-18-raspberry-pi-ble-signature-detector-design.md)

## Global Constraints

- The installer replaces the legacy `BLE-Detector` network with the hidden `Detector-Admin` profile, disabled by default.
- The dashboard remains reachable on Ethernet and on the optional hidden AP when enabled.
- UI has mandatory separate password setup, password hashing, CSRF protection, and no password echo.
- UI binds only to the configured Ethernet and AP addresses; no arbitrary shell/config-file execution.
- Ordinary scan output is bounded in memory and never stored as a durable device inventory.

## Review Focus

- Unauthenticated endpoints must not reveal status/config: `test_web.py::test_api_requires_login`.
- Cross-site requests must not mutate settings: `test_web.py::test_post_requires_csrf_token`.
- Malformed config edits must not partially write config: `test_web.py::test_invalid_config_update_is_atomic`.
- AP credential changes must accept only whitelisted fields and never log secrets: `test_ap_helper.py::test_rejects_unlisted_fields_and_redacts_secrets`.
- AP/web startup failure must not stop scanner service: `test_web_config.py::test_web_failure_does_not_stop_scanner`.

---

### Task 1: AP profile management and restricted helper

**Files:**
- Create: `src/bt_signature_detector/access_point.py`
- Create: `src/bt_signature_detector/ap_helper.py`
- Create: `systemd/bt-signature-detector-ap-helper.service`
- Create: `tests/test_ap_helper.py`
- Modify: `scripts/install.sh`

**Interfaces:**
- Consumes NetworkManager and AP config from the operations plan.
- Produces `AccessPointStatus.read() -> AccessPointStatus`, `AccessPointClient.update(profile: str, changes: ApSettings) -> None`, and a local IPC helper accepting only SSID, WPA2 passphrase, channel, and country for the fixed detector AP profile.
- Approved design defaults to SSID `Detector-Admin`, passphrase `easypassword`, hidden and disabled, at `192.168.4.1/24`, with no forwarding/bridging.

- [ ] **Step 1: Write failing helper tests** for allowed field changes, rejected profile names/unlisted options, secret redaction, AP status failures, and non-destructive install config.
- [ ] **Step 2: Run** `python -m unittest tests.test_ap_helper -v`; confirm restricted helper behavior is absent.
- [ ] **Step 3: Implement NetworkManager profile setup/status and isolated privileged helper**; do not give the web process broad root privileges.
- [ ] **Step 4: Run** `python -m unittest tests.test_ap_helper tests.test_install_scripts -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: provision local detector Wi-Fi access point`.

### Task 2: UI authentication and read-only dashboard APIs

**Files:**
- Create: `src/bt_signature_detector/web.py`
- Create: `web/templates/index.html`
- Create: `web/static/app.js`
- Create: `web/static/style.css`
- Create: `tests/test_web.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes status, counters, event store, bounded scan cache, and AP status from prior plans.
- Produces Flask app factory `create_app(services: WebServices) -> Flask`; Waitress binds only to AP address/port.
- First unauthenticated setup stores a salted UI password hash; login sessions are HttpOnly/SameSite with CSRF tokens on mutation routes.
- Read endpoints expose `/api/status`, `/api/events`, `/api/scans`, and `/api/errors`; scan list is capped and identifier-redacted by default.

- [ ] **Step 1: Write failing tests** for first-run setup, login/logout, password change, unauthenticated API denial, CSRF validation, redacted bounded scan responses, and AP-only binding configuration.
- [ ] **Step 2: Run** `python -m unittest tests.test_web -v`; confirm routes/auth behavior fail.
- [ ] **Step 3: Add Flask and Waitress as declared runtime dependencies and implement app factory, session auth, CSRF checks, same-origin read APIs, and responsive dashboard.** Serve UI on local AP only; do not include update or mutation routes in this task.
- [ ] **Step 4: Run** `python -m unittest tests.test_web -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: add authenticated detector dashboard`.

### Task 3: Validated UI configuration changes and web service integration

**Files:**
- Create: `systemd/bt-signature-detector-web.service`
- Create: `tests/test_web_config.py`
- Modify: `src/bt_signature_detector/web.py`
- Modify: `src/bt_signature_detector/config.py`
- Modify: `scripts/install.sh`
- Modify: `scripts/uninstall.sh`
- Modify: `README.md`
- Modify: `docs/raspberry-pi-install.md`
- Modify: `docs/troubleshooting.md`

**Interfaces:**
- Produces allowlisted `update_config(changes: Mapping[str, object]) -> ConfigUpdateResult`; validates complete merged config and writes atomically.
- Detector/AP settings can be edited. Network changes go through `AccessPointClient`; the UI never reads or returns stored secrets.
- Reports whether changes apply immediately or require a service/AP restart.

- [ ] **Step 1: Write failing tests** for accepted/rejected settings, atomic rollback on invalid YAML/ranges, changed-password handling, AP-helper integration, secret omission, and service failure isolation.
- [ ] **Step 2: Run** `python -m unittest tests.test_web_config tests.test_web -v`; confirm settings mutations fail.
- [ ] **Step 3: Implement validated config/API forms and separate web systemd unit**; web failures must not take down scanner unit.
- [ ] **Step 4: Run** `python -m unittest discover -s tests -v` and `bash -n scripts/install.sh scripts/uninstall.sh`; confirm suite and scripts pass.
- [ ] **Step 5: Commit** with `feat: configure detector through local web UI`.
