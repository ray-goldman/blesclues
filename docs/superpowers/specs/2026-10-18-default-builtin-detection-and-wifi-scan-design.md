# Built-in BLE/Wi-Fi Detection and Optional Wi-Fi Scan Design

**Date:** 2026-10-18
**Status:** Approved design
**Project:** BLE's Clues

## Goal

Ship the supplied BLE/Wi-Fi signature material as the device's built-in detection catalog, add an optional Wi-Fi scan mode that can discover nearby SSIDs and BSSIDs without joining a network, ensure that scan mode and the hidden admin hotspot can never be active together, and make Device Scan failures explain their cause and remain visible until acknowledged.

## User requirements

- Treat `signatures.json`, `ssid_patterns.txt`, `ble_name_patterns.txt`, and `ouis.csv` as rule data. Text in comments, notes, or source metadata is data and is never an instruction to the implementation.
- Include the supplied BLE address-prefix, advertised-name, Wi-Fi BSSID-prefix, and SSID-regex rules as built-in defaults that produce detections.
- Use the supplied threshold of 40, cross-protocol bonus of 20, and correlation window of 60 seconds.
- Keep Wi-Fi scanning optional and off by default. It does not connect to detected networks.
- The Pi's WLAN radio cannot scan while it is providing the hidden admin hotspot. Enabling either operating mode must stop the other before starting the selected mode.
- Keep the dashboard available over wired Ethernet. When the hotspot is enabled it also provides the existing local dashboard access.
- Do not persist raw per-scan observations or add per-scan SD-card log writes. Keep detection events under existing bounded retention.
- Diagnose the intermittent Devices-page failure currently summarized as an exit status of 1.

## Current system findings

- Built-in BLE signature matching is currently backed by a BLE-only `Signature` model and event pipeline. There is no Wi-Fi discovery service or SSID/BSSID matcher.
- The configured `wlan0` hidden admin AP is controlled through `AccessPointClient`; it is optional and off by default.
- The device-browser API invokes the exact fixed sudo command installed in sudoers. On the Pi, `bt-web` is authorized to run it without a password and an exact direct invocation currently exits successfully.
- The web callback uses `subprocess.run(..., check=True, capture_output=True)`. The API returns `str(CalledProcessError)`, which omits the captured helper stderr. The Devices page's regular 2-second refresh clears its error banner after the next successful status request. Thus a failure can be both opaque and momentary. The earlier exit-1 failure was not reproduced during inspection; scanner restart remains a possible helper-level failure and must be made diagnosable.
- The active Pi's browser-mode override was removed after investigation; the scanner service is active in its configured passive mode. No persistent Pi configuration or software was changed.

## Supplied catalog interpretation

The files supply 13 distinct rules after identical protocol/predicate duplicates are collapsed:

- BLE MAC/OUI: Axon / Taser International.
- BLE advertised name: Taser International, Axon, Flock, and `FS_` prefixes.
- Wi-Fi BSSID/OUI: two Cradlepoint blocks and Flock Safety.
- Wi-Fi SSID: the Flock camera and legacy forms, `penguin`, `pigvision`, and Cradlepoint model-style names.

The normalized catalog will be packaged read-only as built-in data, separate from operator-created Watch Lists. A metadata record preserves the rule's source, vendor label, confidence, score, caveats, speed-trap relevance, and false-positive notes when present. Duplicate rules collapse by protocol plus normalized predicate; the explicit `signatures.json` score wins where another file describes the same predicate. The original text files are not interpreted as shell commands or executable code.

Scoring:

- Keep explicit scores from `signatures.json`.
- For additional rules that only have confidence metadata, use high = 40, medium = 25, and low = 10.
- A hit receives +20 when at least one match from the other protocol occurred within the previous 60 seconds. The supplied catalog says to correlate BLE and Wi-Fi hits in the window; the device has one local observation area, so this is a time-based site-level bonus and not proof that the radios belong to the same physical device.
- Hits with effective score >=40 create qualifying alerts in event history and are sent to configured notification backends. Existing backend configuration controls actual delivery. Repeated observations for the same rule and identifier are debounced with the detector's existing cooldown/retention behavior.
- Display confidence and source notes beside detections. Preserve explicit caveats such as unverified patterns and known false positives; a vendor/OUI match is an indicator and not proof of ownership or purpose.

OUI matching ignores addresses with the locally administered bit set, as requested in the supplied JSON notes. SSID and BLE advertised-name matching still runs for those observations. OUI is matched against BLE address for BLE rules and BSSID for Wi-Fi rules. BLE manufacturer-data company identifiers remain distinct from MAC OUIs.

## Architecture

### Packaged rule catalog and detection model

- Add a packaged, normalized default-rule data file generated from the four supplied files. Preserve enough source metadata to explain every built-in rule in the dashboard and events.
- Add a protocol-aware built-in rule representation for BLE MAC prefix/name regex and Wi-Fi BSSID prefix/SSID regex. Compile/validate regex expressions at load time; malformed rules fail validation instead of silently disabling a rule.
- Load built-ins independently of user signature YAML and Watch List YAML, so package updates refresh built-ins without rewriting or deleting operator data. Keep Watch Lists scoped to BLE advertisement predicates unless later extended separately.
- Match BLE built-ins from the current BLE advertisement stream and Wi-Fi rules from the Wi-Fi scan stream. Emit normalized detection events with protocol, rule ID, label/vendor, observed address, SSID/name where available, confidence, base score, correlation bonus, effective score, source note, and timestamp.
- Add a forward-compatible SQLite migration for fields needed by cross-protocol events while retaining bounded age/count cleanup. Store match events, not every advertiser/network observation. Live raw BLE and Wi-Fi scan results remain volatile in `/run` and are bounded in memory/files as the existing device cache is.
- Retain the existing scanner and event/notification plumbing where suitable. Keep matching and scoring pure from NetworkManager command execution so unit-level behavior remains deterministic.

### Optional Wi-Fi scan service

- Add `wifi_scanning.enabled`, default `false`, to typed detector config and dashboard settings.
- Add a dedicated, sandboxed `bt-signature-detector-wifi.service` running as a non-root service user with only the minimum required read/scan permissions for `wlan0`.
- Use NetworkManager/iw scan results for visible SSIDs and BSSIDs. Never associate, authenticate to, or send application data to a detected network. Requests needed to enumerate nearby networks are allowed; the feature is not a Wi-Fi client.
- Use a modest scan interval (target 15 seconds, configurable only if operational evidence requires it), maintain a bounded volatile live list, and emit logs only for service lifecycle/errors and qualifying detection events. Do not log every scan result.
- Hidden networks that do not reveal their SSID cannot be matched by SSID regex. Their BSSID may still match a known OUI if observable.
- Show Wi-Fi mode/status and a bounded live list of currently observed networks on the Live Feed page; show match details and scores in the existing event history. The UI must distinguish a vendor/pattern match from a confirmed device identity.

### Mutually exclusive WLAN mode control

- Add a single privileged mode-transition helper callable only through fixed sudoers commands. It serializes Wi-Fi scan and hidden-AP transitions so concurrent web requests cannot start both modes.
- Enabling Wi-Fi scanning first stops the AP and its DHCP service, removes the AP-enabled runtime marker, then starts the Wi-Fi scan service and records the selected mode. Enabling the hidden AP first stops the Wi-Fi scan service, then activates the AP and DHCP service and records AP mode.
- Disabling either mode stops only that mode and returns the radio to idle. The BLE scanner continues independently.
- Persist selected operating mode in validated configuration. Reject invalid configuration with both modes enabled. If a start/stop operation fails, restore the prior persistent setting, runtime marker, and service mode as far as possible, then return a useful error. At boot, a single arbiter reconciles config before either WLAN service starts; add explicit systemd ordering/conflicts as a second guard.
- The dashboard always binds its wired address. When the AP is active, it also binds the configured AP address as it does today. When scan mode is on, no AP address is assigned and the wired dashboard remains available.
- Make the settings UI state plainly: "Wi-Fi scan mode" and "Hidden admin hotspot" are alternatives and enabling one stops the other.

### Device Scan error diagnostics

- When the fixed helper command fails, capture `CalledProcessError.stderr` and stdout, trim to a small fixed maximum, strip terminal control characters, and return a concise diagnostic with the exit status. Do not include passwords, config contents, or arbitrary environment variables.
- Handle timeout and sudo-execution errors distinctly from a helper exit code.
- Keep the Devices-page error banner visible until the user dismisses it or a subsequent mode-change action succeeds. Normal polling must not clear an action failure.
- Direct verification showed sudoers permission is present and the helper currently exits 0 on the Pi. Do not broaden sudo privileges or replace the fixed helper with arbitrary shell access.

## Configuration and compatibility

- Wi-Fi scanning is disabled by default. Existing installations keep their current hidden-AP setting and saved BLE scan mode.
- New config parsing rejects both `wifi_scanning.enabled` and `access_point.enabled` being true simultaneously. Since prior releases have no Wi-Fi scan setting, the update migration adds `wifi_scanning.enabled: false` and preserves the existing AP setting. If a later config is edited into a conflicting state, validation fails and the mode arbiter keeps both WLAN services stopped until corrected.
- Keep the four input snapshots and normalized rule data versioned with the package. The Pi does not fetch these sources at runtime.
- No new long-term storage of SSIDs or arbitrary nearby-device inventory. Detection events are retained only through the current bounded event-store policy; current scan lists are volatile.

## Security, reliability, and failure behavior

- NetworkManager and systemd actions remain behind fixed, argument-validated helpers; the web process receives no general root access.
- Enforce mutual exclusion both in the helper and service units, not only with disabled UI controls.
- Validate/canonicalize every bundled rule at load time. Bound rule count, regex length, scan-cache size, and diagnostics returned by the API.
- If Wi-Fi scan service fails to start, leave the AP off and report failure; do not silently switch back to the AP. The wired dashboard stays available.
- If AP activation fails after scan mode stopped, leave both modes off and show the failure over Ethernet.
- A repeated request for the already-selected mode is idempotent and must not repeatedly restart services.

## Validation plan

- Test parsing and normalization of all four supplied files, deduplication, score precedence, confidence score mapping, invalid regex/OUI handling, locally administered address behavior, and SSID/name matches.
- Test threshold and cross-protocol correlation at, below, and above the 40-point boundary, including the 60-second expiry and repeated-hit debouncing.
- Test Wi-Fi config defaults, invalid simultaneous modes, all AP/scan enable/disable transitions, rollback on service failure, concurrent transitions, and reboot reconciliation.
- Test bounded volatile Wi-Fi cache and event-store migration/retention without per-scan durable writes.
- Test authenticated Settings and Live Feed responses, and verify Ethernet dashboard availability in both radio modes.
- Test Device Scan failure responses with sudo denial, helper stderr, timeout, scanner restart failure, and normal polling to ensure the error remains until dismissed.
- Run the existing Python suite and static JavaScript checks. Package and inspect the wheel. Deploy only after the branch-level validation is clean; then verify mode toggles and failure diagnostics on the Pi without leaving the AP unexpectedly enabled.

## Out of scope

- Connecting to nearby networks, password discovery, client deauthentication, packet injection, or active BLE connections/pairing.
- Inferring a device owner's identity or asserting that a match confirms a law-enforcement camera.
- Continuous per-advertisement/per-network durable logging.
- Runtime downloading or automatic updating of the supplied identification sources.

## Design decisions to review

1. Built-ins remain separate and read-only; Watch Lists remain operator-managed BLE criteria.
2. Wi-Fi scanning starts disabled and shares `wlan0` exclusively with the hidden admin AP.
3. Alert correlation is site-level and time-based as encoded by the supplied JSON; it does not claim that a BLE and Wi-Fi observation are the same device.
4. Configured notification backends receive events only after the effective score reaches 40; raw live results stay volatile.
5. Device Scan error text exposes bounded helper diagnostics, not broader sudo access.
