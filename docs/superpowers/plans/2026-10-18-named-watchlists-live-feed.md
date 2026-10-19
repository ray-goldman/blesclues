# Named Watch Lists and Dedicated Live Feed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add named BLE watch lists with passive filter coverage, move the volatile advertisement feed to its own page, and retain qualifying watch matches in the existing bounded history.

**Architecture:** Extend the current signature model and YAML file with optional watch-list grouping and enabled state. A focused repository handles validated atomic edits; a filter derivation module combines compatible enabled watch rules with manually configured BlueZ filters at scanner startup. Authenticated APIs serve a Watch Lists manager and creation flow from Devices, while Monitor and Live Feed show durable matches and volatile raw observations separately.

**Tech Stack:** Python 3.11+, PyYAML, Bleak/BlueZ, Flask, SQLite, vanilla JavaScript/CSS, `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-18-named-watchlists-live-feed-design.md`

## Global Constraints

- Active scanning remains limited to the explicitly started temporary Device Browser mode; saved watch rules do not change the configured scan mode.
- Derived BlueZ filters are combined with, but never written over, manually configured filters.
- The scanner service remains the only owner of the Bluetooth adapter.
- Raw advertisements and the device inventory remain bounded and volatile under `/run`; qualifying matches use existing SQLite retention and maximum-event limits.
- Watch rules use the existing minimum of three qualifying observations and cooldown; new watch rules have unknown confidence and notifications disabled.
- All watch-list pages and APIs require the existing authenticated session; mutations require CSRF protection.
- Exact BLE addresses are observed radio identifiers, may rotate, and must not be represented as verified product or owner identities.
- Keep the existing restrained blue dashboard styling and use content-led page layouts; do not introduce a generic gradient/card treatment.
- Use the Bluetooth SIG assigned company name as a lookup label only. Bundle a generated registry snapshot; Pi scanning must not make registry network requests or write registry data to the SD card.

## Review Focus

- **Malformed or adversarial rule data:** unknown YAML keys, oversized names, invalid hex, malformed UUIDs, and duplicate IDs must reject the mutation without changing the file. Pin in Tasks 1 and 3.
- **All/any passive coverage:** an `all` rule needs one compatible filter to have full coverage; an `any` rule with unsupported criteria is only partially covered. Pin in Task 2.
- **Empty manual filters:** allow them only when an enabled watch rule derives a compatible filter; otherwise preserve the existing passive configuration error. Pin in Task 2.
- **Failed scanner restart:** any persisted rule mutation that requires a reload must restore the prior signature file if the scanner restart fails. Pin in Task 3.
- **History after rule rename/deletion:** retained events must keep the watch-list name they had when emitted. Pin in Task 1.
- **Address exposure and unauthorized mutations:** Live Feed stays redacted and watch APIs reject unauthenticated or invalid-CSRF requests. Pin in Tasks 4 and 5.
- **Unknown or stale company identifiers:** show the numeric identifier with an unknown label if it is missing from the bundled SIG snapshot; never fail a scan because a registry entry is absent. Pin in Task 6.
- **Identifier confusion:** company IDs from manufacturer data must not be treated as BLE address OUIs or verified device-vendor identity. Pin in Task 6's label and API contract assertions.

---

### Task 1: Extend signatures and retained event records

**Files:**
- Modify: `src/bt_signature_detector/models.py`
- Modify: `src/bt_signature_detector/signatures.py`
- Modify: `src/bt_signature_detector/state.py`
- Modify: `src/bt_signature_detector/pipeline.py`
- Modify: `src/bt_signature_detector/store.py`
- Test: `tests/test_signatures.py`
- Test: `tests/test_models.py`
- Test: `tests/test_pipeline.py`
- Test: `tests/test_store.py`

**Interfaces:**
- `Signature` gains optional `watchlist: str | None = None` and `enabled: bool = True` fields at the end of the dataclass so existing positional construction remains valid.
- `DetectionEvent` gains optional `watchlist_name: str | None = None` at the end of the dataclass.
- `load_signatures(path: Path) -> tuple[Signature, ...]` accepts optional YAML `watchlist` and `enabled` keys, validates their types and bounded lengths, and preserves legacy schema-version-1 files.
- `DetectionFilter.observe(...)` skips disabled signatures and copies a signature's watch-list name onto emitted events.

- [x] **Step 1: Add parser and model tests** for a legacy signature with no watch-list fields, a named enabled rule, a disabled rule, malformed list names, non-boolean `enabled`, an unknown key, invalid hex/UUID, and duplicate IDs. Assert legacy defaults are `watchlist is None` and `enabled is True`; compare list names after trimming and case-folding for uniqueness.
- [x] **Step 2: Run the focused tests and confirm the new cases fail** with the existing parser/model behavior.
- [x] **Step 3: Extend the signature model and parser** with the two optional fields. Keep unknown-key rejection and enforce a non-empty trimmed list name no longer than 80 characters.
- [x] **Step 4: Add pipeline tests** asserting disabled rules emit no event and enabled watch rules put the list name on their event after the existing three-observation threshold.
- [x] **Step 5: Add SQLite migration tests** asserting the `watchlist_name` column is added to an existing detections table, old records deserialize with `None`, and newly recorded events retain the list name after reload.
- [x] **Step 6: Implement event propagation and migration** in `DetectionFilter`, `DetectionEvent`, and `EventStore`; existing event schemas remain readable and event retention behavior is unchanged.
- [x] **Step 7: Run `python -m unittest discover -s tests -p "test_signatures.py" -v`, `python -m unittest discover -s tests -p "test_pipeline.py" -v`, and `python -m unittest discover -s tests -p "test_store.py" -v`.**

### Task 2: Derive passive BlueZ filters from watch rules

**Files:**
- Create: `src/bt_signature_detector/watch_filters.py`
- Modify: `src/bt_signature_detector/scan_mode.py`
- Modify: `src/bt_signature_detector/cli.py`
- Modify: `src/bt_signature_detector/config.py`
- Test: `tests/test_watch_filters.py`
- Test: `tests/test_scanner.py`
- Test: `tests/test_config.py`

**Interfaces:**
- `RuleFilterCoverage` in `watch_filters.py` contains `status: str` (`"full"`, `"partial"`, `"browser_only"`, or `"disabled"`) and `patterns: tuple[OrPatternConfig, ...]`.
- `watch_rule_filter_coverage(signature: Signature) -> RuleFilterCoverage` reports coverage and compatible patterns for one rule.
- `derived_watch_filters(signatures: Sequence[Signature]) -> tuple[OrPatternConfig, ...]` returns the deduplicated filter union for enabled signatures that have a watch-list name.
- `effective_bluetooth_config(config: BluetoothConfig, *, override_file: Path, signatures: Sequence[Signature] = ()) -> BluetoothConfig` combines saved filters with derived filters in passive mode and continues to remove all filters for the temporary active browser override.
- `validate_config_data(data: Mapping[str, object], *, base_dir: Path | None = None) -> AppConfig` resolves the signature file against `base_dir` only when checking whether empty manual filters are permitted; `load_app_config` supplies the config file's parent directory, and the web Settings route supplies its config file's parent directory.

- [x] **Step 1: Add tests for manufacturer data** asserting a manufacturer company identifier is encoded little-endian before the selected payload prefix in AD type `0xFF`.
- [x] **Step 2: Add tests for advertised service UUID, service-data prefix, and exact name prefix mappings**, plus unsupported name-contains and address-only criteria.
- [x] **Step 3: Add coverage tests** asserting an `all` rule with one compatible and one unsupported predicate is `full`, an `any` rule with both is `partial`, a rule with no compatible predicates is `browser_only`, and a disabled rule is `disabled`.
- [x] **Step 4: Add deduplication and runtime tests** asserting derived patterns are unioned with manual patterns once, normal mode stays passive, and Device Browser mode stays active with no filters.
- [x] **Step 5: Implement `watch_filters.py`** using exact BLE AD type and byte-order mappings; derive a manufacturer pattern only when its mask is absent or all `FF`; never infer identity from company identifiers or payloads.
- [x] **Step 6: Wire signature loading into scanner setup** so the CLI passes loaded signatures when resolving the effective Bluetooth configuration.
- [x] **Step 7: Update passive config validation** to permit an empty manual `or_patterns` list only when the referenced signature file has an enabled watch rule with a derivable filter; otherwise preserve the current validation error. Add base-directory resolution to `load_app_config` and the existing `/api/settings` validation call.
- [x] **Step 8: Run `python -m unittest discover -s tests -p "test_watch_filters.py" -v`, `python -m unittest discover -s tests -p "test_scanner.py" -v`, and `python -m unittest discover -s tests -p "test_config.py" -v`.**

### Task 3: Add atomic watch-list repository operations

**Files:**
- Create: `src/bt_signature_detector/watchlists.py`
- Test: `tests/test_watchlists.py`

**Interfaces:**
- `WatchListStore(path: Path)` owns reads and mutations of the existing signature YAML file.
- `WatchListStore.list_signatures() -> tuple[Signature, ...]` returns the currently validated signatures.
- `WatchListStore.create_rule(rule_data: Mapping[str, object]) -> Signature` validates and persists a new uniquely identified rule.
- `WatchListStore.rename_list(old_name: str, new_name: str) -> None` updates all member rules atomically.
- `WatchListStore.set_enabled(signature_id: str, enabled: bool) -> None` changes only the selected user watch rule.
- `WatchListStore.delete_rule(signature_id: str) -> None` deletes one user watch rule.
- `WatchListStore.delete_list(name: str) -> None` deletes all member rules for one list.
- `WatchListStore.transaction(operation: Callable[[], T], *, restart: Callable[[], None]) -> T` holds the repository lock across the mutation and scanner restart, restoring the saved bytes and file mode on either failure.
- Mutations preserve ungrouped built-in signatures, use a process lock, validate the complete file before replacement, and atomically replace the file while preserving its mode.

- [x] **Step 1: Add store tests** for create, rename, enable/disable, rule deletion, list deletion, preservation of ungrouped built-ins, generated unique IDs, bounded labels/list names, and complete signature-file validation.
- [x] **Step 2: Add failure tests** asserting invalid input, duplicate normalized list names, and failed atomic replacement leave the original file byte-for-byte unchanged.
- [x] **Step 3: Run the new tests and confirm they fail** because `WatchListStore` is not implemented.
- [x] **Step 4: Implement `WatchListStore`** with safe YAML loading, deterministic serialization, full-file revalidation, `RLock` serialization, atomic replacement, and mode preservation.
- [x] **Step 5: Run `python -m unittest discover -s tests -p "test_watchlists.py" -v`.**

### Task 4: Add authenticated watch-list APIs and restart rollback

**Files:**
- Modify: `src/bt_signature_detector/web.py`
- Modify: `src/bt_signature_detector/cli.py`
- Test: `tests/test_web_watchlists.py`
- Test: `tests/test_web.py`

**Interfaces:**
- `WebServices` gains optional `watchlists: WatchListStore | None = None`.
- `GET /api/watchlists` returns `{"watchlists": [{"name": str, "rules": [{"id": str, "label": str, "enabled": bool, "match_mode": str, "criteria": object, "filter_coverage": str}]}]}`.
- `POST /api/watchlists/rules` accepts `label` (1–120 characters), `list_name` (1–80 trimmed characters), `match_mode`, and any selected existing predicate keys: `observed_identifiers`, `name_exact`, `name_contains`, `manufacturer_data`, `service_uuids`, or `service_data`; it creates an unknown-confidence rule with `min_observations=3` and `alert_enabled=false`.
- The supported API predicate keys retain the existing signature file shapes: identifier and UUID arrays, company-ID-to-hex manufacturer mapping, UUID-to-hex service-data mapping, and one exact or contains name predicate.
- `POST /api/watchlists/rename` accepts `old_name` and `new_name`.
- `POST /api/watchlists/rules/<signature_id>/enabled` accepts a boolean `enabled` value.
- `DELETE /api/watchlists/rules/<signature_id>` deletes one watch rule; `POST /api/watchlists/delete` accepts a list name and deletes that list.
- All routes return JSON errors for invalid data, require session authentication, and apply existing CSRF checks to mutations.

- [x] **Step 1: Add API tests** for list serialization and create/rename/enable/delete behavior, asserting new rules use unknown confidence, three minimum observations, and disabled notifications.
- [x] **Step 2: Add auth/CSRF tests** asserting every mutation is rejected before store/restart calls when unauthenticated or supplied an invalid CSRF token.
- [x] **Step 3: Add rollback tests** asserting create, rule changes, rename, and deletion restore the previous signature file when `restart_scanner` raises; return a clear error and keep the scanner's existing state authoritative. Include two concurrent mutations to verify the repository lock prevents lost updates across the write/restart transaction.
- [x] **Step 4: Run the focused API tests and confirm they fail** before adding routes.
- [x] **Step 5: Implement the API routes** with strict JSON shape/length checks, safe serialization, `WatchListStore` calls, and file rollback around scanner restart.
- [x] **Step 6: Wire the configured signature file and `WatchListStore` into `WebServices`** in the dashboard startup path.
- [x] **Step 7: Run `python -m unittest discover -s tests -p "test_web_watchlists.py" -v` and `python -m unittest discover -s tests -p "test_web.py" -v`.**

### Task 5: Separate the Live Feed page and build the Watch Lists interface

**Files:**
- Create: `src/bt_signature_detector/web_templates/live.html`
- Create: `src/bt_signature_detector/web_templates/watchlists.html`
- Create: `src/bt_signature_detector/web_static/live.js`
- Create: `src/bt_signature_detector/web_static/watchlists.js`
- Modify: `src/bt_signature_detector/web_templates/index.html`
- Modify: `src/bt_signature_detector/web_templates/devices.html`
- Modify: `src/bt_signature_detector/web_static/app.js`
- Modify: `src/bt_signature_detector/web_static/devices.js`
- Modify: `src/bt_signature_detector/web_static/style.css`
- Modify: `src/bt_signature_detector/web.py`
- Test: `tests/test_web_pages.py`
- Test: `tests/test_web_devices.py`

**Interfaces:**
- Add authenticated `GET /live` and `GET /watchlists` page routes with the existing CSRF token.
- Monitor renders recent matches with the saved watch-list name and removes the volatile advertisement panel and `/api/scans` polling.
- Live Feed renders the existing bounded `/api/scans` response, keeps address redaction, and polls at the current five-second Monitor cadence.
- Device rows provide a **Watch this** action that opens a rule form populated only with the selected observation's available fields.
- Watch-list manager groups and labels rules using the Task 4 API; rule coverage is rendered as Full, Partial, Browser scan only, or Disabled.
- Manufacturer data on Live Feed, Devices, and Watch Lists keeps its numeric company ID and payload visible; Task 6 adds the assigned company-name enrichment after the page structure is in place.

- [x] **Step 1: Add page/API contract tests** asserting the authenticated navigation exposes Monitor, Live Feed, Devices, Watch Lists, Settings, and Updates; unauthenticated page requests redirect to login.
- [x] **Step 2: Add a Live Feed API rendering test** asserting scan identifiers remain redacted and the page consumes the scan endpoint without exposing a raw identifier field in rendered content.
- [x] **Step 3: Add Devices page tests** asserting rows include a Watch this action and that the rule form only preselects available data (no RSSI identity predicate).
- [x] **Step 4: Add Watch Lists UI tests or JS contract checks** for empty state, named lists, full/partial/browser-only/disabled coverage labels, mutation errors, and CSRF headers.
- [x] **Step 5: Add the two authenticated page routes and templates**; move the volatile window markup and API polling to `live.html`/`live.js`, leaving Monitor focused on status and match events.
- [x] **Step 6: Implement the rule form and list manager** in the existing blue visual system, including list selection or new list entry, all/any control, address-rotation note, confirmation before list deletion, and visible save/restart failures.
- [x] **Step 7: Run page/API checks and review the six-page navigation and forms at desktop and narrow viewport widths.**

### Task 6: Bundle Bluetooth SIG company names

**Files:**
- Create: `src/bt_signature_detector/company_ids.py`
- Create: `src/bt_signature_detector/data/company_identifiers.json`
- Create: `scripts/update_company_identifiers.py`
- Modify: `pyproject.toml`
- Modify: `src/bt_signature_detector/web.py`
- Modify: `src/bt_signature_detector/web_static/live.js`
- Modify: `src/bt_signature_detector/web_static/devices.js`
- Modify: `src/bt_signature_detector/web_static/watchlists.js`
- Test: `tests/test_company_ids.py`
- Test: `tests/test_web_watchlists.py`
- Test: `tests/test_web_devices.py`

**Interfaces:**
- `CompanyIdentifierRegistry.from_package() -> CompanyIdentifierRegistry` loads the packaged compact JSON snapshot once at dashboard startup.
- `CompanyIdentifierRegistry.from_json(path: Path) -> CompanyIdentifierRegistry` validates a supplied registry snapshot for tests and release tooling.
- `CompanyIdentifierRegistry.lookup(company_id: int) -> str | None` returns the assigned company name or `None` for an unknown ID.
- The packaged JSON shape is `{"source_url": str, "retrieved_at": str, "companies": {"0xNNNN": str}}`, with IDs written as four-digit uppercase hexadecimal strings and records sorted by numeric ID.
- `parse_company_registry(source: str) -> dict[int, str]` parses the SIG YAML text without network access, so the release updater can be tested with a fixture.
- `scripts/update_company_identifiers.py` downloads the official raw YAML URL `https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml`, validates `company_identifiers` records, and writes sorted compact JSON to the package data path. It is a release-preparation tool only; the Pi never runs it during startup or scanning.
- `GET /api/devices`, `GET /api/scans`, and `GET /api/watchlists` enrich each manufacturer company ID with a `manufacturer_names` mapping. Unknown IDs are omitted from that mapping so the UI can display the numeric ID with “Unknown SIG company ID.”
- The UI labels a known entry “SIG company: {name} · ID 0xNNNN”; it describes the company assigned that manufacturer-data ID, not a verified device maker, owner, or MAC-address OUI.
- `WebServices.company_identifiers: CompanyIdentifierRegistry | None` supplies the in-memory registry to `create_app`; the dashboard startup path in `web.py` constructs it once from package data.

- [x] **Step 1: Add registry parser tests** for valid records, duplicate IDs, IDs outside `0..65535`, empty names, malformed JSON, and lookup of an unknown ID.
- [x] **Step 2: Add enrichment API tests** asserting known company names appear for device, scan, and manufacturer-data watch-rule fields, while unknown identifiers retain their numeric form and do not fail the response.
- [x] **Step 3: Run the focused registry and API tests and confirm they fail** before adding the registry loader.
- [x] **Step 4: Implement the registry loader** with strict schema validation and a single in-memory mapping; use no network access at runtime.
- [x] **Step 5: Implement `parse_company_registry(source: str) -> dict[int, str]` and the release generator** with fixture-driven parsing and atomic deterministic JSON output. Validate that source records have integer IDs in range and non-empty company names; do not add an update call to Pi services.
- [x] **Step 6: Generate and package the registry snapshot** and include the JSON data file in wheel package-data configuration.
- [x] **Step 7: Enrich the existing authenticated API responses** and update the three page scripts to render labels as “SIG company: {name} · ID 0xNNNN”; render unknown IDs as “Unknown SIG company ID · 0xNNNN.”
- [x] **Step 8: Run `python -m unittest discover -s tests -p "test_company_ids.py" -v`, `python -m unittest discover -s tests -p "test_web_watchlists.py" -v`, and `python -m unittest discover -s tests -p "test_web_devices.py" -v`.**

### Task 7: Integration regression and deployment notes

**Files:**
- Modify: `README.md`
- Modify: `docs/raspberry-pi-install.md`
- Modify: `docs/troubleshooting.md`
- Test: `tests/test_docs.py`

**Interfaces:**
- Document that watch rules match only advertisements received by the current scan mode, explain Full/Partial/Browser scan only coverage, and distinguish derived filters from manually configured BlueZ filters.
- Document that Live Feed data is volatile, watch rules persist in the existing signature file, and match events use bounded SQLite retention.
- Attribute the bundled company-name snapshot to the Bluetooth SIG Assigned Numbers YAML registry and explain that the SIG company label is not proof of a device's manufacturer or owner.

- [x] **Step 1: Update operator documentation** with the Live Feed, named watch-list workflow, address rotation limitation, passive filter coverage labels, restart behavior, and SD-card storage behavior.
- [x] **Step 2: Update documentation assertions** to cover the new navigation/workflow, SIG registry source/attribution, and avoid claiming ordinary advertisements or device inventories are durably stored.
- [x] **Step 3: Run the full suite with `python -m unittest discover -s tests -v`** and confirm existing browser mode, settings, updates, and signature behavior remain intact.
- [x] **Step 4: Build a wheel and inspect package contents** to confirm new templates and static assets are included; confirm the signature example remains valid under the extended schema.
- [x] **Step 5: Review the complete diff** for unintended edits to existing user changes. Do not stage or commit product changes from this worktree: it contains pre-existing uncommitted implementation changes from the earlier BLE's Clues work.
- [x] **Step 6: On the Pi, verify a manufacturer-prefix rule has full passive coverage and receives a match, an address-only rule is labeled Browser scan only, and Device Browser Stop restores passive filters without changing saved scan mode.**

## Execution notes

- Execute natively in the existing attached worktree, as previously selected for this project.
- Preserve all pre-existing worktree changes. The approved spec commit is isolated; product implementation must not stage unrelated pre-existing edits.
- After implementation, use a fresh code review before considering any integration or deployment to the Pi.
