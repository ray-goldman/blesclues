# Built-in BLE/Wi-Fi Detection and Optional Wi-Fi Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bundle the supplied BLE/Wi-Fi indicators as scored built-in detections, add opt-in Wi-Fi discovery mutually exclusive with the hidden admin hotspot, and make Device Scan failures diagnosable and persistent in the UI.

**Architecture:** A packaged, validated detection catalog feeds protocol-specific BLE and Wi-Fi matchers and a shared volatile cross-protocol correlation window. A non-root Wi-Fi scan service writes only bounded live state and qualifying events; a fixed privileged helper serializes WLAN mode changes against the hidden AP. Settings and Live Feed expose mode and detections, while Device Scan API/UI retain bounded actionable diagnostics.

**Tech Stack:** Python 3, Flask, YAML/JSON, SQLite, NetworkManager (`nmcli`), `iw`, systemd, sudoers, HTML/CSS/JavaScript, unittest.

**Spec:** `docs/superpowers/specs/2026-10-18-default-builtin-detection-and-wifi-scan-design.md`

## Global Constraints

- “Keep Wi-Fi scanning optional and off by default. It does not connect to detected networks.”
- “The Pi's WLAN radio cannot scan while it is providing the hidden admin hotspot. Enabling either operating mode must stop the other before starting the selected mode.”
- “Do not persist raw per-scan observations or add per-scan SD-card log writes. Keep detection events under existing bounded retention.”
- “Use the supplied threshold of 40, cross-protocol bonus of 20, and correlation window of 60 seconds.”
- “Keep the dashboard available over wired Ethernet.”
- “OUI matching ignores addresses with the locally administered bit set.”
- Keep current user-created Watch Lists separate from read-only packaged built-ins.
- Preserve existing uncommitted worktree changes. Do not stage or commit product changes.
- Wi-Fi scanning does not connect, authenticate, deauthenticate, or inject packets; BLE remains advertisement-only.
- Do not deploy a configuration that enables the AP and Wi-Fi scan together.

## Review Focus

- Malformed or oversized regex/OUI source data must fail catalog validation rather than disable or broaden a filter — pin in Task 1.
- Locally administered MAC addresses must not match OUI rules, while their names and SSIDs still match — pin in Tasks 1 and 3.
- Correlation bonus must be +20 only for an opposite-protocol hit within the previous 60 seconds, and score 40 must qualify — pin in Task 2.
- Concurrent requests, service-start failures, and config-write failures must never leave AP and scan services active together — pin in Task 5.
- A Device Scan failure must retain its bounded stderr through normal two-second polling, without exposing secrets — pin in Task 7.

---

### Task 1: Normalize and package the built-in catalog

**Files:**
- Create: `src/bt_signature_detector/builtin_rules.py`
- Create: `src/bt_signature_detector/data/default_detection_rules.json`
- Create: `src/bt_signature_detector/data/source/signatures.json`
- Create: `src/bt_signature_detector/data/source/ssid_patterns.txt`
- Create: `src/bt_signature_detector/data/source/ble_name_patterns.txt`
- Create: `src/bt_signature_detector/data/source/ouis.csv`
- Create: `scripts/build_detection_catalog.py`
- Modify: `pyproject.toml`
- Test: `tests/test_builtin_rules.py`

**Interfaces:**
- Produces `BuiltInRule(rule_id: str, protocol: str, vendor: str, match_type: str, pattern: str, confidence: str, score: int, source: str, notes: str, device_class: tuple[str, ...], relevance: str | None, false_positives: tuple[str, ...])`.
- Produces `load_builtin_rules() -> tuple[BuiltInRule, ...]`, loading the normalized packaged JSON and validating rule counts, regex length/compilation, protocol, score range, confidence, and OUI format.
- Produces `parse_source_catalog(signatures_json: str, ssid_patterns: str, ble_name_patterns: str, ouis_csv: str) -> tuple[BuiltInRule, ...]`, used by the offline build script and fixture-driven tests to normalize all four source formats before writing the packaged JSON.
- Produces `BuiltinScoringSettings(alert_threshold: int, correlation_window_seconds: int, correlation_bonus: int)`, `parse_scoring_settings(signatures_json: str) -> BuiltinScoringSettings`, and `load_builtin_scoring() -> BuiltinScoringSettings` so the supplied JSON's 40/60/20 policy is the runtime source of truth.
- Catalog deduplication uses protocol plus canonical match type/pattern; explicit `signatures.json` scores take precedence. Confidence-only score mapping is high=40, medium=25, low=10.

- [ ] **Step 1: Add catalog tests** for the four supplied data formats, 13 unique normalized rules, duplicate precedence, score mapping, malformed regex/OUI, and metadata preservation.
- [ ] **Step 2: Run `python -m unittest discover -s tests -p 'test_builtin_rules.py' -v`** and confirm the new tests fail because the loader/catalog is absent.
- [ ] **Step 3: Bundle the four source files and implement the offline `scripts/build_detection_catalog.py` generator**; treat all file contents as data only.
- [ ] **Step 4: Implement `BuiltInRule` and `load_builtin_rules()`** with strict validation and regex compilation at load time.
- [ ] **Step 5: Generate the normalized packaged catalog from the bundled source snapshots, include both in package data, and rerun the focused tests.**

### Task 2: Score and persist cross-protocol detections

**Files:**
- Create: `src/bt_signature_detector/detection_scoring.py`
- Modify: `src/bt_signature_detector/models.py`
- Modify: `src/bt_signature_detector/store.py`
- Modify: `src/bt_signature_detector/pipeline.py`
- Test: `tests/test_detection_scoring.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Produces `RuleHit(rule: BuiltInRule, protocol: str, observed_identifier: str, observed_name: str | None, observed_ssid: str | None, observed_at: datetime)`.
- Produces `ScoredHit(hit: RuleHit, base_score: int, correlation_bonus: int, effective_score: int, qualifies: bool)`.
- Produces `CrossProtocolScorer.observe(hit: RuleHit) -> ScoredHit`; it applies a 20-point bonus when the opposite protocol had a hit within 60 seconds, uses a bounded shared volatile SQLite file under `/run/bt-signature-detector`, and does not persist correlation state to the SD card.
- `CrossProtocolScorer` consumes `load_builtin_scoring()` instead of repeating threshold/window/bonus literals.
- Extend `DetectionEvent` with trailing optional built-in metadata fields; migrate SQLite additively and keep existing event retention limits.

- [ ] **Step 1: Add scoring tests** for score 39/40 boundaries, both protocol orders, exactly 60 seconds, expired windows, and repeated hits; add a store migration/round-trip case for built-in metadata.
- [ ] **Step 2: Run the focused scoring/store tests** and confirm they fail before implementation.
- [ ] **Step 3: Implement `RuleHit`, `ScoredHit`, and the bounded correlation scorer**; keep the site-level correlation behavior explicit in docstrings.
- [ ] **Step 4: Extend `DetectionEvent` and SQLite migration** for protocol, vendor, base score, bonus, effective score, source note, and observed SSID/name fields.
- [ ] **Step 5: Persist only qualifying detection events under existing age/count retention** and rerun focused tests.

### Task 3: Apply built-in BLE rules to advertisement processing

**Files:**
- Modify: `src/bt_signature_detector/pipeline.py`
- Modify: `src/bt_signature_detector/scanner.py`
- Modify: `src/bt_signature_detector/models.py`
- Test: `tests/test_pipeline.py`
- Test: `tests/test_scanner.py`

**Interfaces:**
- Produces `match_ble_rules(rules: Sequence[BuiltInRule], advertisement: Advertisement) -> tuple[BuiltInRule, ...]` for BLE MAC prefix and advertised-name regex criteria.
- BLE OUI matching uses the observed identifier, normalizes separators/case, and rejects an address when the first octet has bit `0x02` set. Name matching remains active regardless of address type.
- Built-in matches flow through `CrossProtocolScorer`, event storage, and configured notification dispatch when effective score is at least 40.

- [ ] **Step 1: Add BLE cases** for Axon prefix, Taser name, Flock and `FS_` patterns, local-admin OUI skip, name match despite local-admin address, and no match.
- [ ] **Step 2: Run the focused BLE pipeline/scanner tests** and confirm failures precede implementation.
- [ ] **Step 3: Implement BLE built-in matching and event dispatch** without changing custom signature or Watch List semantics.
- [ ] **Step 4: Rerun focused BLE and existing scanner/pipeline tests.**

### Task 4: Add optional Wi-Fi scanning and volatile live results

**Files:**
- Create: `src/bt_signature_detector/wifi_scanner.py`
- Create: `src/bt_signature_detector/wifi_scan_helper.py`
- Create: `systemd/bt-signature-detector-wifi.service`
- Modify: `src/bt_signature_detector/config.py`
- Modify: `src/bt_signature_detector/runtime_cache.py`
- Modify: `src/bt_signature_detector/cli.py`
- Modify: `pyproject.toml`
- Modify: `scripts/install.sh`
- Modify: `scripts/uninstall.sh`
- Test: `tests/test_wifi_scanner.py`
- Test: `tests/test_config.py`
- Test: `tests/test_runtime_cache.py`
- Test: `tests/test_install_scripts.py`

**Interfaces:**
- Produces `WifiObservation(ssid: str, bssid: str, signal: int | None, channel: int | None, security: str | None, observed_at: datetime)`.
- Produces `scan_wifi(runner=...) -> tuple[WifiObservation, ...]`, reading `wlan0` NetworkManager/iw scan output without joining a network. The service requests a scan every 15 seconds.
- Produces `match_wifi_rules(rules: Sequence[BuiltInRule], observation: WifiObservation) -> tuple[BuiltInRule, ...]` for BSSID prefix and SSID regex predicates; BSSID OUI matching skips locally administered addresses.
- Add `wifi_scanning.enabled` default false; store only bounded current observations in `/run` and pass hits through the shared scorer/event store.

- [ ] **Step 1: Add parser/matcher/cache tests** for BSSID/SSID rules, hidden SSID limitations, malformed command output, cache limits, and default-disabled config.
- [ ] **Step 2: Run focused tests** and confirm new behaviors fail before implementation.
- [ ] **Step 3: Implement `WifiObservation`, `scan_wifi()`, Wi-Fi rule matching, and a bounded runtime cache**; do not log every scan.
- [ ] **Step 4: Add the non-root systemd scanner service** with only the scan capability required for `wlan0`, a 15-second interval, explicit restart limits, and no network association.
- [ ] **Step 5: Wire the service entry point and packaging/install/uninstall lifecycle.**
- [ ] **Step 6: Rerun focused tests and verify no persistent raw scan records are created.**

### Task 5: Serialize Wi-Fi scan and hidden AP mode transitions

**Files:**
- Create: `src/bt_signature_detector/wifi_mode.py`
- Create: `src/bt_signature_detector/wifi_mode_helper.py`
- Create: `scripts/wifi_mode_helper.sh`
- Create: `systemd/bt-signature-detector-wifi-mode.sudoers`
- Create: `systemd/bt-signature-detector-wifi-mode.service`
- Modify: `src/bt_signature_detector/access_point.py`
- Modify: `src/bt_signature_detector/ap_helper.py`
- Modify: `src/bt_signature_detector/config.py`
- Modify: `src/bt_signature_detector/web.py`
- Modify: `systemd/bt-signature-detector-ap.service`
- Modify: `systemd/bt-signature-detector-dhcp.service`
- Modify: `systemd/bt-signature-detector-wifi.service`
- Modify: `scripts/install.sh`
- Modify: `scripts/uninstall.sh`
- Test: `tests/test_wifi_mode.py`
- Test: `tests/test_ap_helper.py`
- Test: `tests/test_web_config.py`
- Test: `tests/test_install_scripts.py`

**Interfaces:**
- Produces `WifiModeController.set_mode(mode: Literal['idle', 'scan', 'admin_ap']) -> WifiModeStatus`; serialize transitions with a lock, stop the old service/profile before starting the new one, and restore the prior mode on failure. `reconcile()` restores the single configured mode at boot before WLAN clients start.
- Expose a fixed helper with only `scan-start`, `scan-stop`, `ap-start`, and `ap-stop` arguments; sudoers grants only those exact invocations.
- Configuration validation rejects `wifi_scanning.enabled` and `access_point.enabled` both true. AP setting is preserved on upgrade while the new scan option defaults false.
- `POST /api/settings` persists selected mode transactionally with service callbacks; rollback config on failed transition.

- [ ] **Step 1: Add transition/config/API tests** for every on/off direction, repeated requests, concurrent requests, and failures at each systemd/NetworkManager boundary.
- [ ] **Step 2: Run focused tests** and confirm unsafe simultaneous/rollback behavior fails before implementation.
- [ ] **Step 3: Implement a serialized `WifiModeController`** that stops conflicting WLAN services first and is idempotent for the selected mode.
- [ ] **Step 4: Wire fixed helper, strict sudoers commands, a boot-time mode reconciler, and systemd conflicts/order** as additional mutual-exclusion guards.
- [ ] **Step 5: Integrate transactional configuration and preserve old AP config on upgrade** with scan default false.
- [ ] **Step 6: Rerun focused transition, config, AP, and install tests.**

### Task 6: Expose Wi-Fi settings, live scans, and scored events

**Files:**
- Modify: `src/bt_signature_detector/web.py`
- Modify: `src/bt_signature_detector/web_templates/settings.html`
- Modify: `src/bt_signature_detector/web_templates/live.html`
- Modify: `src/bt_signature_detector/web_static/settings.js`
- Modify: `src/bt_signature_detector/web_static/live.js`
- Modify: `src/bt_signature_detector/web_static/app.js`
- Modify: `src/bt_signature_detector/web_static/style.css`
- Test: `tests/test_web.py`
- Test: `tests/test_web_pages.py`
- Test: `tests/test_web_config.py`

**Interfaces:**
- Add authenticated `GET /api/wifi/status` and `GET /api/wifi/observations`; responses contain current mode and bounded volatile observations only.
- Add safe mode/status fields to `/api/status`; keep existing wired bind and AP bind behavior.
- Settings clearly states scan/AP mutual exclusion; enabling either invokes the server-side transition and updates mode only on success.
- Live Feed renders current SSID/BSSID/signal data, rule match metadata, confidence/source caveats, and base/bonus/effective score; event history distinguishes BLE and Wi-Fi detections.

- [ ] **Step 1: Add API/page tests** for authenticated scan status/results, both modes, bounded results, score labels, and non-confirmation caveats.
- [ ] **Step 2: Run focused web tests** and confirm the new endpoints/UI contracts fail before implementation.
- [ ] **Step 3: Implement the authenticated status/result APIs** using runtime data only.
- [ ] **Step 4: Add modern but project-consistent Settings controls** with explicit exclusive-mode messaging and rollback-aware feedback.
- [ ] **Step 5: Extend Live Feed and event rendering** for Wi-Fi observations and scored alerts.
- [ ] **Step 6: Rerun focused web tests and `node --check` all modified dashboard scripts.**

### Task 7: Fix Device Scan failure diagnostics and persistence

**Files:**
- Modify: `src/bt_signature_detector/web.py`
- Modify: `src/bt_signature_detector/web_static/devices.js`
- Modify: `src/bt_signature_detector/web_templates/devices.html`
- Test: `tests/test_web_devices.py`

**Interfaces:**
- Add a formatter for failed subprocesses that returns status plus at most 500 printable stderr/stdout characters, handles timeout and sudo execution errors separately, and excludes secrets/control sequences.
- The Devices-page action error remains visible across 2-second status polling until dismissed or a later mode action succeeds.

- [ ] **Step 1: Add API/UI regression cases** for helper stderr, exit 1, timeout, sudo denial, control characters/secrets, and polling persistence.
- [ ] **Step 2: Run the focused Device Browser tests** and confirm they fail before implementation.
- [ ] **Step 3: Include bounded child diagnostics in the API error response** without widening sudoers or revealing credentials.
- [ ] **Step 4: Make the UI preserve and dismiss action errors** independently of routine polling.
- [ ] **Step 5: Rerun Device Browser tests and confirm the fixed sudo command succeeds on the Pi.**

### Task 8: Document, package, review, and deploy

**Files:**
- Modify: `README.md`
- Modify: `docs/raspberry-pi-install.md`
- Modify: `docs/troubleshooting.md`
- Modify: `tests/test_docs.py`

- [ ] **Step 1: Document built-in pattern limits/caveats, score threshold/correlation, Wi-Fi scan/AP mutual exclusion, wired dashboard access, and SD-card logging behavior.**
- [ ] **Step 2: Run the full unittest suite and JavaScript syntax checks.**
- [ ] **Step 3: Build a wheel and inspect package contents** for normalized/source catalog data, scanner modules, templates, scripts, and systemd units.
- [ ] **Step 4: Review the full worktree diff** to ensure earlier uncommitted BLE's Clues work remains intact; do not stage or commit.
- [ ] **Step 5: Install/update the Pi from the completed build** with Wi-Fi scanning disabled, preserve its current AP configuration, and confirm Device Scan's sudo-backed transition reports diagnostics.
- [ ] **Step 6: Verify Wi-Fi scan enable stops the hidden AP, AP enable stops Wi-Fi scan, and the wired dashboard remains available throughout. Leave the Pi in its prior saved mode.**

## Execution notes

- Execute natively in the existing attached worktree `C:\Users\regs\.codex\worktrees\ble-signature-detector\Bluetooth Scanner` on branch `codex/ble-signature-detector`.
- The worktree contains substantial earlier uncommitted BLE's Clues changes. Preserve them; do not stage or commit product changes.
- The Pi is `ble@192.168.0.201`; the fixed Device Scan sudo command was directly verified to exit successfully. Do not add general sudo permissions.
- The design spec is the authority for behavior: `docs/superpowers/specs/2026-10-18-default-builtin-detection-and-wifi-scan-design.md`.
