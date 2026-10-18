# Raspberry Pi Operations Implementation Plan

> **For agentic workers:** Required sub-skill: use `superpowers:executing-plans` to implement this plan task by task. Do not begin implementation until the user approves the plan and selects an execution method.

**Goal:** Package the detector as a maintainable headless Raspberry Pi OS service with install/uninstall scripts and operator documentation.

**Architecture:** Systemd owns service lifecycle and journald logging. An unprivileged scanner service waits for Bluetooth but not internet; the installer provisions dependencies and a persistent state/config layout without overwriting user data.

**Tech Stack:** Raspberry Pi OS Bookworm+, systemd, NetworkManager, Python venv, Bash, Markdown.

**Spec:** [2026-10-18-raspberry-pi-ble-signature-detector-design.md](../specs/2026-10-18-raspberry-pi-ble-signature-detector-design.md)

## Global Constraints

- Target Raspberry Pi 3 Model B and Raspberry Pi OS Lite Bookworm or later.
- Scanner starts without `network-online.target` and waits for `bluetooth.service`.
- Run scanner/UI unprivileged; send stdout/stderr to journald; support clean shutdown.
- Preserve user config, event data, and NetworkManager AP profile on uninstall by default.
- Document passive BlueZ `or_patterns`, hardware/network limits, and CarPlay/Siri caveats.

## Review Focus

- Install/uninstall reruns must not overwrite config or delete state: add shell integration checks using temporary roots.
- Missing NetworkManager/Bluetooth must produce useful status rather than block boot: assert unit dependency targets.
- Invalid locale/country or unsupported OS must fail before changing networking: test preflight checks.
- Unprivileged account permissions must cover Bluetooth D-Bus access without broad writable paths: inspect install permission tests.
- CarPlay must not be promised for ntfy; SMS instructions must mention provider registration requirements: doc assertions/review.

---

### Task 1: systemd service units and install/uninstall scripts

**Files:**
- Create: `systemd/bt-signature-detector.service`
- Create: `scripts/install.sh`
- Create: `scripts/uninstall.sh`
- Create: `tests/test_install_scripts.py`

**Interfaces:**
- Consumes the installable `detector` entry point from the core plan.
- Produces an unprivileged `bt-detector` scanner unit with `After=bluetooth.service`, restart policy, journald output, and no `network-online.target` dependency.
- Install script creates venv, service/state directories, service user, config copies only when absent, and enables service. Uninstall preserves config/database/AP profile unless explicit purge option is supplied.

- [ ] **Step 1: Write failing script/unit tests** for install idempotence, no config overwrite, state preservation, explicit purge, no network-online dependency, and Bluetooth wait/restart settings.
- [ ] **Step 2: Run** `python -m unittest tests.test_install_scripts -v`; confirm unit/script fixtures fail.
- [ ] **Step 3: Implement systemd unit and guarded install/uninstall scripts** with OS/tool preflight and clear failure messages.
- [ ] **Step 4: Run** `python -m unittest tests.test_install_scripts -v` and `bash -n scripts/install.sh scripts/uninstall.sh`; confirm both pass.
- [ ] **Step 5: Commit** with `feat: package detector as a systemd service`.

### Task 2: Raspberry Pi setup and operational guides

**Files:**
- Create: `README.md`
- Create: `docs/raspberry-pi-install.md`
- Create: `docs/troubleshooting.md`
- Create: `docs/carplay-testing.md`
- Create: `tests/test_docs.py`
- Modify: `config/detector.example.yaml`

**Interfaces:**
- Documents commands from the core plan and service lifecycle from Task 1.
- Documents adapter selection, country/regulatory setup, BlueZ passive filter requirements, log/status/recent commands, secrets storage, SD-card retention, Twilio/A2P registration, audio testing, and CarPlay/Siri end-to-end test limitations.

- [ ] **Step 1: Write documentation checklist tests** that assert required command examples, default thresholds, security caveats, and CarPlay limitations are present.
- [ ] **Step 2: Run** `python -m unittest tests.test_docs -v`; confirm missing guide coverage fails.
- [ ] **Step 3: Write concise operator guides** using commands implemented by earlier plans; keep actual device validation explicitly labeled as a hardware step.
- [ ] **Step 4: Run** `python -m unittest tests.test_docs -v` and `git diff --check`; confirm both pass.
- [ ] **Step 5: Commit** with `docs: add Raspberry Pi setup and troubleshooting guides`.
