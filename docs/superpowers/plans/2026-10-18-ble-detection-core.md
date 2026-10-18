# BLE Detection Core Implementation Plan

> **For agentic workers:** Required sub-skill: use `superpowers:executing-plans` to implement this plan task by task. Do not begin implementation until the user approves the plan and selects an execution method.

**Goal:** Build a hardware-independent, testable BLE observation pipeline with YAML signatures, filtering, SQLite events, a Bleak scanner, CLI, and dry run.

**Architecture:** Immutable models connect an injected scanner to a deterministic signature engine, stateful filter, event store, and pipeline. The CLI composes real or synthetic sources without coupling Bluetooth callbacks to persistence or alerts.

**Tech Stack:** Python 3, `argparse`, `asyncio`, `sqlite3`, `unittest`, PyYAML, Bleak.

**Spec:** [2026-10-18-raspberry-pi-ble-signature-detector-design.md](../specs/2026-10-18-raspberry-pi-ble-signature-detector-design.md)

## Global Constraints

- BLE discovery is advertisement-only; never connect, pair, authenticate, exploit, or transmit to discovered devices.
- Examples use synthetic signature values only; generic identifiers never establish equipment identity.
- Passive mode never silently falls back to active mode; BlueZ passive mode requires configured `or_patterns`.
- At least three matching observations are required; default cooldown is 300 seconds.
- Only filtered detections are stored; ordinary discoveries are never persisted.
- The suite runs without BLE hardware, network, audio, or external services.

## Review Focus

- Incomplete or malformed YAML must produce path-specific errors before scanner startup: `test_config.py::test_rejects_invalid_yaml_and_unknown_fields`.
- Missing advertisement fields must not crash signature matching: `test_signatures.py::test_missing_optional_fields_do_not_raise`.
- Rotating addresses must not be joined, and cooldown boundaries must be deterministic: `test_state.py::test_randomized_identifiers_have_separate_state` and `test_state.py::test_cooldown_expires_at_configured_boundary`.
- BlueZ/passive adapter failures must retry without mode changes: `test_scanner.py::test_passive_error_retries_without_switching_mode`.
- Database failure must not terminate observation processing: `test_pipeline.py::test_store_failure_is_counted_and_scanning_continues`.

---

### Task 1: Package skeleton, models, and configuration

**Files:**
- Create: `pyproject.toml`
- Create: `src/bt_signature_detector/__init__.py`
- Create: `tests/__init__.py`
- Create: `src/bt_signature_detector/models.py`
- Create: `src/bt_signature_detector/config.py`
- Create: `config/detector.example.yaml`
- Create: `config/signatures.example.yaml`
- Test: `tests/test_config.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces frozen dataclasses `Advertisement`, `Signature`, `Match`, and `DetectionEvent` with documented UTC timestamps and absent optional advertisement fields represented as `None`/empty mappings.
- Produces `load_app_config(path: Path) -> AppConfig` and `validate_config_data(data: Mapping[str, object]) -> AppConfig`.
- `AppConfig` has typed sections for scanner, detection, storage, logging, notifications, AP/UI, and updates; secret values are references to environment variables/files, never literal sample credentials.

- [ ] **Step 1: Write failing config/model tests** for valid defaults, required passive filters, malformed YAML, unknown keys, synthetic signature values, and absent advertisement fields.
- [ ] **Step 2: Run** `python -m unittest tests.test_config tests.test_models -v`; confirm tests fail on missing imports/interfaces.
- [ ] **Step 3: Implement the package metadata, immutable models, PyYAML config loader, path-aware validation, and synthetic example files.** Pin Python floor and runtime dependencies in `pyproject.toml`; expose the `detector` entry point.
- [ ] **Step 4: Run** `python -m unittest tests.test_config tests.test_models -v`; confirm all cases pass.
- [ ] **Step 5: Commit** with `feat: add detector models and configuration`.

### Task 2: YAML signature parsing and matching

**Files:**
- Create: `src/bt_signature_detector/signatures.py`
- Create: `tests/test_signatures.py`
- Modify: `tests/test_config.py`

**Interfaces:**
- Consumes: `Advertisement`, `Signature`, and `AppConfig` from Task 1.
- Produces `load_signatures(path: Path) -> tuple[Signature, ...]` and `match_signature(signature: Signature, advertisement: Advertisement) -> bool`.
- Manufacturer matching accepts an optional equal-length byte mask and compares `(observed & mask) == (pattern & mask)`.
- `match_mode` is `all` or `any`; missing optional advertisement fields evaluate as non-matches for that predicate and never raise.

- [ ] **Step 1: Write failing tests** for masked manufacturer bytes, AND/OR composition, normalized UUIDs, exact/substring names, exact observed identifiers, missing fields, and invalid/empty predicate definitions.
- [ ] **Step 2: Run** `python -m unittest tests.test_signatures -v`; confirm failures identify absent parsing/matching behavior.
- [ ] **Step 3: Implement signature loading and pure predicate evaluation** without RSSI or observation-count logic.
- [ ] **Step 4: Run** `python -m unittest tests.test_signatures tests.test_config -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: add configurable signature matching`.

### Task 3: Stateful filtering and SQLite event store

**Files:**
- Create: `src/bt_signature_detector/state.py`
- Create: `src/bt_signature_detector/store.py`
- Create: `tests/test_state.py`
- Create: `tests/test_store.py`

**Interfaces:**
- Consumes: `Advertisement`, `Signature`, `DetectionEvent`, and detection config.
- Produces `DetectionFilter.observe(advertisement: Advertisement, matches: Sequence[Signature]) -> list[DetectionEvent]` and `DetectionFilter.expire(now: datetime) -> int`.
- Filter state is keyed by `(signature_id, exact_observed_identifier)` and tracks first/last seen, count, strongest RSSI, and last alert time. Minimum observations is `max(3, signature.min_observations)`.
- Produces `EventStore.record(event: DetectionEvent) -> None`, `EventStore.recent(limit: int) -> list[DetectionEvent]`, and `EventStore.prune(now: datetime) -> int`; SQLite stores detections only and applies age/count retention in bounded batches.

- [ ] **Step 1: Write failing state/store tests** for RSSI threshold boundaries, observation count, timestamps/strongest RSSI, randomized identifiers, cooldown suppression/expiry, absence reset, one event per cooldown, persistence/recent ordering, schema initialization, and retention.
- [ ] **Step 2: Run** `python -m unittest tests.test_state tests.test_store -v`; confirm failures are behavioral.
- [ ] **Step 3: Implement deterministic filtering with an injected clock and transactional SQLite storage** using only standard-library SQLite.
- [ ] **Step 4: Run** `python -m unittest tests.test_state tests.test_store -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: filter and persist detection events`.

### Task 4: Bleak scanner, pipeline, CLI, and dry run

**Files:**
- Create: `src/bt_signature_detector/scanner.py`
- Create: `src/bt_signature_detector/pipeline.py`
- Create: `src/bt_signature_detector/cli.py`
- Create: `src/bt_signature_detector/synthetic.py`
- Create: `tests/test_scanner.py`
- Create: `tests/test_pipeline.py`
- Create: `tests/test_cli.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: signature engine, filter, store, and config from Tasks 1–3.
- Produces `BleScanner.run(on_advertisement: Callable[[Advertisement], Awaitable[None]], stop_event: asyncio.Event) -> None`; the scanner has no matching or persistence responsibilities.
- Produces `DetectionPipeline.process(advertisement: Advertisement) -> list[DetectionEvent]`.
- CLI commands: `scan`, `test-alert`, `list-signatures`, `status`, `recent`, `validate-config`; `scan --dry-run` uses the injected synthetic source.

- [ ] **Step 1: Write failing fake-scanner/pipeline/CLI tests** for advertisement normalization, passive `or_patterns`, no active fallback, capped reconnect delay, clean cancellation, scan counters, store failure isolation, dry-run detection flow, and CLI validation/list/recent output.
- [ ] **Step 2: Run** `python -m unittest tests.test_scanner tests.test_pipeline tests.test_cli -v`; confirm expected missing behavior.
- [ ] **Step 3: Implement the Bleak adapter, reconnect loop, orchestration, synthetic source, structured logging, counters, and argparse commands.** Keep scanning independent of network and downstream errors.
- [ ] **Step 4: Run** `python -m unittest discover -s tests -v`; confirm the detection-core suite passes without a BLE adapter.
- [ ] **Step 5: Commit** with `feat: add BLE scanner and dry-run CLI`.
