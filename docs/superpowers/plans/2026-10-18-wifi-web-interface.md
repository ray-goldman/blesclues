# Wi-Fi Access Point and Web Interface Implementation Plan

> **For agentic workers:** Required sub-skill: use `superpowers:executing-plans` to implement this plan task by task. Do not begin implementation until the user approves the plan and selects an execution method.

**Goal:** Provide a Pi-hosted Wi-Fi network and authenticated local UI for scanner status, live/recent output, and safe configuration edits.

**Architecture:** NetworkManager owns a local-only AP. A Flask/Waitress UI binds only to its interface, requires a separately created UI password, and calls a narrow AP helper for whitelisted network changes. Live observations remain bounded in memory.

**Tech Stack:** NetworkManager/nmcli, Python Flask and Waitress, same-origin HTML/JS/CSS, `unittest`.

**Spec:** [2026-10-18-raspberry-pi-ble-signature-detector-design.md](../specs/2026-10-18-raspberry-pi-ble-signature-detector-design.md)

## Global Constraints

- AP defaults: SSID `BLE-Detector`, WPA2 passphrase `easypassword`, interface address `192.168.4.1`.
- AP is local-only and does not require internet; regulatory country is configured before start.
- UI has mandatory separate password setup, password hashing, CSRF protection, and no password echo.
- UI binds only to AP interface; no arbitrary shell/config-file execution.
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
- Defaults to SSID `BLE-Detector`, passphrase `easypassword`, local address `192.168.4.1/24`, and no forwarding/bridging.

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
