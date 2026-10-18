# Raspberry Pi Bluetooth Signature Detector — Design

**Date:** 2026-10-18
**Status:** Draft for review

## Purpose and boundaries

Build a headless Python service for Raspberry Pi OS Lite that passively observes BLE advertisements, evaluates operator-supplied YAML signatures, filters repeat observations, records detection events in SQLite, and dispatches events to optional local audio, ntfy, or SMS backends. The service must start without a network connection, tolerate adapter and notification outages, and offer the same detection and notification pipeline in a hardware-free dry run.

The scanner only consumes advertisements. It never connects to, pairs with, authenticates against, exploits, or transmits packets to discovered devices. Signature examples use clearly synthetic values. The software does not claim a generic name, OUI, manufacturer ID, or service UUID identifies law-enforcement equipment. A `confirmed` label is a configured classification, not a conclusion independently verified by the software. Only `confirmed` signatures with alerts enabled produce notifications by default.

This is a passive signal matching tool, not an identity or attribution system. BLE identifiers may be randomized and advertisement data can be copied or changed. Observations with changed identifiers are not linked as one device.

## Scope and delivery sequence

The implementation is split into three independently reviewable increments:

1. **Detection core:** package structure, data models, YAML configuration and signature parsing, BLE scanner adapter, signature evaluation, stateful observation/cooldown filtering, SQLite detection-event storage and retention, CLI, structured logging, synthetic source and dry run, and unit tests.
2. **Notification backends:** common backend contract, offline local audio, ntfy over HTTP, optional Twilio SMS behind a provider abstraction, rate limits, failure isolation, test-alert command, and mocked delivery tests.
3. **Raspberry Pi operation:** systemd unit, install/uninstall scripts, dependency setup, Raspberry Pi 3 installation, Bluetooth/passive-scan troubleshooting, secure secret setup, limitations, and CarPlay/Siri test guide.

The interfaces are defined up front so each increment integrates without changing the scanner or detection rules when another backend is added.

## Proposed repository layout

```text
pyproject.toml
README.md
src/bt_signature_detector/
  __init__.py
  cli.py                 # argparse command routing and human-readable output
  config.py              # config loading, defaults, validation
  models.py              # Advertisement, Signature, Match, DetectionEvent
  scanner.py             # Bleak adapter and reconnect loop
  signatures.py          # YAML loading and deterministic rule evaluation
  state.py               # per-observation tracking, thresholds, cooldowns
  store.py               # SQLite schema, event writes, retention, recent query
  pipeline.py            # orchestration from observations to detection events
  notifications/
    __init__.py
    base.py              # notifier protocol and outcome model
    dispatcher.py        # bounded asynchronous fan-out and failure isolation
    audio.py             # local sound playback
    ntfy.py              # HTTP backend
    sms.py               # provider interface and Twilio implementation
config/
  detector.example.yaml
  signatures.example.yaml
systemd/bt-signature-detector.service
scripts/install.sh
scripts/uninstall.sh
tests/
  test_config.py
  test_signatures.py
  test_state.py
  test_store.py
  test_pipeline.py
  test_notifications.py
  test_cli.py
```

Use Python's `argparse`, `asyncio`, `sqlite3`, `logging`, and `unittest` from the standard library. Runtime dependencies are PyYAML and Bleak. Audio uses the Raspberry Pi OS `aplay` executable when enabled. Twilio support is an optional dependency, imported only when that provider is enabled. Avoid a web server, external database, Docker, or a required online service.

## Component contracts and data flow

### Models

`Advertisement` is an immutable observation with observed address/identifier, optional name, manufacturer data (`int -> bytes`), service UUIDs, service data, RSSI, and observed timestamp. Missing fields remain absent; the model does not invent values. First-seen and last-seen are state-derived, not properties of a single BLE packet.

`Signature` is an immutable parsed rule: ID, descriptive name, confidence (`confirmed`, `possible`, or `unknown`), optional manufacturer ID and masked data patterns, service UUID predicates, optional name and exact observed-identifier predicates, optional minimum RSSI, minimum observation count, condition-combination mode, evidence/reference text, and alert enabled flag.

`DetectionEvent` is the single logical output of filtering. It includes event ID, signature ID/name, configured confidence, first/last seen, strongest RSSI, observation count, and an observed identifier for local diagnostics. Remote notifiers omit the complete identifier by default.

### Scanner

The scanner exposes an async stream or callback of `Advertisement` values and owns no signature, persistence, or notification logic. It accepts an adapter selector and explicit scan options. Passive mode is requested when configured; if Bleak/BlueZ/hardware cannot honor it, the scanner logs and surfaces a clear error/status. It must never silently fall back to active scanning. Advertisement callbacks do minimal work and hand observations to the pipeline.

On adapter errors or disappearance, scanner startup is retried with capped exponential backoff. Cancellation and shutdown stop the scanner cleanly. Scan errors do not terminate the service permanently. Debug logging can include advertisement field details; normal logs avoid dumping complete identifiers or manufacturer payloads.

### Signature engine

YAML uses versioned top-level `schema_version` and a list of signatures. Per signature, `match_mode: all|any` applies to configured predicates; at least one predicate is required. An absent optional predicate is ignored, not treated as a failed match. Manufacturer patterns are hexadecimal byte strings with an optional equal-length mask; compare `(observed_byte & mask) == (pattern_byte & mask)`. UUIDs are normalized before comparison. Name matching supports explicit exact or substring mode. Exact identifiers are optional and compared only to the currently observed identifier.

RSSI and observation count are evaluated by the state/filter stage so every signature uses the same semantics. Invalid or ambiguous YAML fails validation with a path and useful error. Example rules contain synthetic byte values and synthetic identifiers only.

### Stateful filtering

State is keyed by signature ID and the exact currently observed identifier. It tracks first-seen, last-seen, count, and strongest RSSI. A candidate must satisfy the signature RSSI threshold (when set), the configured global threshold (when set), and at least `max(3, signature.min_observations)` matching observations before alert consideration. This preserves the project-wide three-observation floor.

The default repeat cooldown is 300 seconds. After an alertable event is emitted, another event for that signature/observed-identifier key is suppressed until the cooldown expires. Tracking is discarded after configurable absence duration. A changed or randomized identifier starts a separate key; the system does not infer continuity. Only confirmed and alert-enabled signatures dispatch by default; possible/unknown matches may be listed or logged without alerting.

### Persistence

SQLite stores detection events, not every advertisement or every nearby device. The store uses a schema version and transactions. Retention is configurable by event age and/or maximum event count; expired rows are pruned in batches to limit SD-card writes. A configurable persistence interval/batch avoids a write for every observation. `recent` reads only retained detection events. Database failure is logged and isolated so the scanning loop can continue; the current event may be lost during a storage failure and status counters report this.

### Pipeline and notifications

The pipeline accepts observations from either the Bleak scanner or synthetic source, evaluates signatures, updates state, persists one `DetectionEvent` for each emitted event, and submits that same event to the dispatcher. This makes scanner, rules, filter, and event semantics independent of notification backends.

Each backend implements an async `send(event)` operation and a `test()` operation. The dispatcher sends to enabled backends independently; exceptions and network timeouts from one backend never stop scanning or block other backends. A bounded queue prevents unbounded memory use during outages; queue saturation is logged and counted. Shutdown drains the queue for a short configurable grace period, then exits cleanly.

- **Audio:** offline `aplay` playback, configurable sound path/volume where supported, and disabled by default until configured. `test-alert` can invoke it locally.
- **ntfy:** HTTP POST with configurable server, topic, priority, timeout, and optional token/basic authentication loaded from environment or a permissions-restricted secrets file. Message contains configured signature name/confidence and signal summary, never a complete BLE identifier by default. Delivery errors are isolated and logged; no unbounded retry queue.
- **SMS:** disabled by default. A provider interface isolates Twilio-specific behavior. Credentials are read from environment or a permissions-restricted secrets file, never committed to the repository or placed in the example config. Destination is configurable. Messages are concise and include signature and confidence. Backend-level rate limits supplement detector cooldown. Documentation explains applicable US A2P registration and carrier requirements. SMS transport supports the iPhone Messages/Siri announcement workflow but does not guarantee CarPlay presentation.

Notification text is configurable. A synthetic example is: “Bluetooth detector: Example signature observed. Strong signal.”

## Configuration and CLI

A YAML config file provides adapter, scan mode, reconnect bounds, RSSI and observation thresholds, cooldown, absence reset, signature path, SQLite path/retention, log level/debug behavior, dispatcher queue and timeout, and backend settings. Defaults are safe: no notifications enabled, passive scan requested, minimum three observations, 300-second cooldown, no network dependency to start scanning. `validate-config` performs structural and cross-field validation without opening Bluetooth or sending messages.

Commands:

- `detector scan [--config PATH] [--debug] [--dry-run]`
- `detector test-alert [--config PATH]`
- `detector list-signatures [--config PATH]`
- `detector status [--config PATH]`
- `detector recent [--config PATH] [--limit N]`
- `detector validate-config [--config PATH]`

Dry run injects deterministic synthetic advertisements through the same rule, state, storage, and notification interfaces. It must not require a Bluetooth adapter and must visibly identify itself as simulation. Test alert sends a sample event only to enabled configured backends; for SMS it should require an explicit CLI confirmation flag to prevent accidental charges.

Status reports process/scanner state and counters (observations, matches, emitted events, cooldown suppressions, persistence failures, notification failures, reconnects) without dumping discovered-device inventories.

## Startup and operations

The systemd unit runs as a dedicated unprivileged account, starts after and waits for `bluetooth.service`, and does not require network-online. It restarts on unexpected failures, sends stdout/stderr to journald, and uses systemd's stop signal for graceful async shutdown. Installation creates a virtual environment, installs the package/dependencies, installs configuration examples without overwriting user config, creates service user/state directories, and enables the service. Bluetooth group/D-Bus access is checked and documented rather than assumed. Uninstall stops/disables the service and removes installed files only when explicitly requested by the script; it preserves configuration and event data by default.

## Testing and acceptance mapping

Use `unittest` and injected scanner/notifier interfaces so the default suite runs without BLE hardware, network, audio output, or Twilio credentials. Cover YAML validation; missing fields; masked manufacturer patterns; all/any rules; UUID/name matching; randomized identifiers remaining separate; global and per-signature RSSI thresholds; the three-observation floor; strongest RSSI and timestamps; cooldown suppression and expiry; absence reset; SQLite retention/recent query; exactly one logical event; dispatcher failure isolation and bounded queue behavior; SMS disabled/secret handling; adapter restart backoff with a fake scanner; dry-run full pipeline; and CLI validation.

The release is acceptable when a Pi 3 can start scanning through systemd without network, adapter outages recover, synthetic confirmed matches produce one event and one dispatch during cooldown, audio works offline when configured, ntfy/SMS failures do not stop scanning, and the hardware-free unit suite passes. Deployment-specific passive scanning availability must be verified on the target Pi/BlueZ stack and documented accurately.

## Security, privacy, and identification limitations

The package does not include real-world law-enforcement signature data. User-supplied signature definitions must carry provenance in their evidence field and be reviewed independently. Generic manufacturer or name evidence cannot establish equipment identity. Bluetooth address randomization prevents durable identity tracking; the program intentionally does not correlate rotating identifiers. Remote notifications exclude full observed identifiers by default. Credentials belong in environment variables or a restricted local secrets file. Discovery events are not retained as an indefinite inventory; only filtered detection events are stored under retention limits.
