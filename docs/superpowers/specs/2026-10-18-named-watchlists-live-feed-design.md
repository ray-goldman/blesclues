# Named Watch Lists and Dedicated Live Feed

**Status:** Draft for review  
**Date:** 2026-10-18  
**Product:** BLE's Clues

## Purpose

Give operators a way to turn an observed BLE device into a reusable watch rule, organize rules into named lists, and review later matches. Show the Bluetooth SIG assigned company name for manufacturer company identifiers when available. Move the raw, short-lived advertisement window off the Monitor page and onto its own page.

The design must preserve BLE's Clues' passive-by-default behavior and avoid writing ordinary advertisements or a device inventory to the SD card. A saved rule should work during normal scanning whenever its selected advertisement fields can be represented by a passive BlueZ filter.

## User experience

### Navigation and pages

- **Monitor** shows scanner status and recent signature/watch-rule matches. It no longer embeds the raw advertisement window.
- **Live Feed** (`/live`) shows the existing bounded, volatile advertisement window. It refreshes from the authenticated scan API, continues to redact device addresses, shows assigned SIG company names beside known manufacturer company IDs, and explains that observations are short-lived and not a saved device inventory.
- **Devices** remains the temporary broad device browser. Manufacturer data shows the assigned Bluetooth SIG company name beside its numeric company identifier when one is present in the bundled registry. Each observed-device row gains a **Watch this** action.
- **Watch Lists** (`/watchlists`) shows named lists, their rules, current rule state, and whether each rule has a compatible passive scan filter. Manufacturer-data criteria show the assigned company name beside the identifier. Operators can rename or delete a list, disable/enable a rule, and delete a rule.

All pages use the existing authenticated dashboard and CSRF protections. Navigation remains usable on narrow screens.

### Creating a watch rule

Selecting **Watch this** opens a form prefilled only with fields present in the selected observation. The operator chooses one or more criteria:

- Exact observed BLE address.
- Advertised name, as exact or contains.
- Manufacturer company identifier and payload prefix.
- Advertised service UUID.
- Service-data UUID and payload prefix.

RSSI is not offered as an identity criterion. The operator names the rule, selects an existing list or enters a new list name, and chooses whether selected criteria must all match or any one may match. “All” is the default. The form previews the selected criteria and marks an exact address as potentially unreliable because BLE addresses can rotate.

Rules created from the browser start with unknown confidence, at least three observations required, and notifications disabled. Saving validates the rule, writes it atomically, and restarts the existing scanner service so it loads the rule and any derived filters. A failed restart restores the previous signature file and reports the failure.

### Watch-list management

The Watch Lists page groups rules by their saved list name. Operators can rename lists, enable or disable individual rules, and delete rules or lists. Disabling a rule removes it from matching and passive filter derivation but retains the rule. Deleting a list deletes its rules after an explicit confirmation. The built-in signatures without a list remain visible in the Monitor match history but are not treated as user watch-list rules.

## Rule storage and matching

Use the existing signature YAML file and matcher as the single source of truth. Add an optional `watchlist` string to signature records; legacy records without it keep their current behavior. Watch-list grouping is derived from the rules, so a list exists while it contains one or more rules. A list name must be non-empty and normalized consistently for uniqueness.

The existing signature predicates remain the supported rule language. Rule changes are written with the same atomic replacement and validation approach used for dashboard settings. The web service validates the full resulting signature file before replacing it. Scanner restart is required to load changed rules; no polling or per-advertisement config reads are added.

The existing observation threshold and cooldown remain in effect. A rule must receive at least three qualifying advertisements before emitting a match event. Existing event retention and maximum-event limits remain in effect. Watch rules do not enable notifications by default. Match history identifies the watch-list name and rule name so the operator can tell which saved rule matched.

## Company identifier names

Use the Bluetooth SIG public company-identifiers YAML registry at `https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml` as the source for company names. Generate a compact, bundled lookup snapshot when preparing a software release and include it in the application package. The Pi performs no network request for this lookup at startup or while scanning, and does not write registry data to its SD card. A later application release can ship a refreshed snapshot. Attribute the snapshot to the Bluetooth SIG Assigned Numbers repository and retain its source URL in the generated metadata or adjacent documentation.

Show a company name only for a manufacturer-data company identifier present in the registry. Manufacturer-specific advertising data carries this two-byte company identifier; the mapping is not a lookup of the BLE address or a MAC-address OUI. Label it as the assigned SIG company name; an unknown value remains visible as its numeric company identifier with an “Unknown SIG company ID” label. The registry entry describes the company associated with the assigned identifier; it does not prove which company made, owns, or operates the observed device.

## Passive scan filter derivation

Normal passive scanning filters advertisements in BlueZ before they reach the signature matcher. To let compatible watch rules work during normal scanning, derive BlueZ `or_patterns` from enabled watch rules at scanner startup and combine them with the manually configured filters. Do not rewrite the operator's configured filter list when saving or deleting a rule. Do not derive filters from built-in signatures that are not assigned to a watch list.

Derive a filter for a watch rule only when an enabled criterion has an unambiguous representation in a BLE advertising-data field that BlueZ can match. Supported mappings should cover manufacturer data (company identifier plus payload prefix), advertised service UUIDs, service-data UUID plus payload prefix, and name prefixes when their rule semantics allow a safe prefix filter. Deduplicate derived patterns against configured and other derived patterns. Preserve software-level signature matching as the authority: BlueZ filtering only decides which advertisements reach the matcher.

Exact address rules and other criteria without a compatible advertising-data filter remain valid rules. Show passive coverage as **Full** when all match paths are guaranteed to pass a derived filter (one compatible criterion is sufficient for an `all` rule), **Partial** when an `any` rule has a mix of derivable and non-derivable criteria, and **Browser scan only** when no criterion can derive a filter. Manually configured filters may provide additional coverage, but are not assumed to make an otherwise partial rule fully covered. A derived filter is an OR at the BlueZ acquisition layer; it may admit extra advertisements, which are still discarded by the software matcher unless the complete rule's all/any criteria match. Saving a rule never changes the saved scan mode to active. Temporary Devices browser mode continues to use its existing active, unfiltered scan override and is stopped independently.

The Live Feed and device browser continue to show only advertisements received by the current scan mode. A passive filter derived from a watch rule may broaden what normal passive scanning receives, but does not turn it into an active scan or a persistent device inventory.

## Event storage and SD-card impact

The raw advertisement cache remains bounded and volatile under `/run`; the Live Feed reads that existing cache. Do not add raw advertisement rows to SQLite, log individual packets, or save the Devices inventory durably.

Watch-rule configuration is written only when an operator creates, changes, disables, or deletes a rule/list. Qualifying watch-rule matches use the existing bounded SQLite event store and its cooldown, retention, and row-count limits. Add a nullable watch-list field to stored events so historical matches retain their grouping even if the rule is later renamed or removed. Migrate existing SQLite databases in place; old rows have no watch-list value and remain readable.

Do not log observed addresses or payloads during rule saves, scanner startup, or ordinary matching. Existing event retention behavior remains unchanged. Saving a watch rule is an explicit choice to monitor the selected characteristics; address-based rules may cause the existing match event record to contain the observed address as it does for other signature matches.

## Service and API behavior

- Add authenticated page routes for `/live` and `/watchlists`.
- Keep `/api/scans` as the bounded, redacted Live Feed source.
- Add authenticated APIs to list watch lists/rules and to create, rename, enable/disable, and delete them. Mutating routes require CSRF tokens.
- Add the watch-list name to serialized match events and render it in Monitor's recent match list.
- Configure the scanner runtime with the validated union of manual BlueZ filters and derived enabled watch-rule filters. Browser-mode override still removes passive filters while active and restores the latest configured-plus-derived passive filters after Stop.
- On watch-rule mutation, persist atomically, restart only the existing scanner service, and roll back the file if the restart fails.
- If a configured passive scanner has no manual filters, an enabled compatible watch rule may supply derived filters. Permit an empty manual filter list only when the referenced signature file contains at least one enabled watch rule that derives a passive filter; otherwise preserve the existing configuration validation error and explain that no passive scan filters are available.

## Security and privacy

- Keep all pages and APIs behind the existing UI session authentication.
- Require CSRF protection for all mutating endpoints.
- Continue redacting observed identifiers from `/api/scans` and the Live Feed.
- Keep full observed addresses limited to the authenticated Devices page and operator-selected exact-address rules; never put them in URLs or logs.
- Use safe YAML parsing, strict schema validation, unique stable rule IDs, bounded field lengths, and atomic writes. Reject unknown fields and malformed hexadecimal data.
- A saved watch rule labels a pattern match; it does not establish manufacturer, product, ownership, or individual identity.
- A SIG company name is an assigned-number lookup label only; do not present it as verified device-vendor identity.
- Do not use SIG company identifiers as BLE address OUIs; they are manufacturer-data identifiers carried inside advertisements.

## Out of scope

- Continuous active scanning or changing the configured scan mode automatically.
- Connecting, pairing, GATT enumeration, or controlling BLE devices.
- Notifications for new watch rules; they remain disabled unless separately enabled through existing notification configuration.
- Durable raw advertisement capture, device-history export, or address correlation across rotations.
- Runtime network lookups for assigned company names, or claims that a SIG company identifier or payload prefix identifies a specific product, device maker, owner, or operator.

## Acceptance criteria

1. The Monitor page no longer renders the volatile advertisement window; `/live` displays the same bounded, redacted, volatile feed.
2. Devices browser rows can open a rule form prefilled with observed characteristics and save a rule into a named watch list.
3. Rules support address, name, manufacturer-data prefix, service UUID, and service-data prefix predicates; multiple predicates support all/any matching.
4. Watch-list rules load through the existing signature matcher, honor its minimum observation count and cooldown, and appear in retained Monitor event history with their list name.
5. Rule CRUD is authenticated, CSRF-protected, validated, atomic, and restarts the scanner; failed restarts roll back saved data.
6. Compatible enabled rules contribute deduplicated passive BlueZ filters at scanner startup without modifying the manually configured filter list or enabling active scanning.
7. Rules with full, partial, or no derived passive filter coverage are labeled clearly and still work during the temporary broad Device Browser scan when their criteria match.
8. Reboot clears the raw advertisement window as it does today; named watch rules persist in the signature file.
9. Routine advertisements and volatile device rows are not added to durable storage or per-packet logs. Watch-rule match events obey existing SQLite retention and size limits.
10. Existing signatures without a watch-list name, Monitor event history, Settings filters, and temporary browser start/stop behavior remain compatible.
11. Known manufacturer company IDs display the bundled SIG company name in Live Feed, Devices, and Watch Lists; unknown IDs keep their numeric value and receive an unknown label.
12. The Pi can render company names with no Internet connection, scanning does not fetch or persist registry updates, and a missing company ID never prevents the advertisement from appearing.

## Verification approach

Add tests for watch-rule YAML parsing and round-tripping, all/any matching, derived BlueZ filter mappings and deduplication, unsupported-filter status, and preservation of manually configured filters. Test atomic watch-list mutations, restart rollback, CSRF/auth rejection, SQLite migration and watch-list event retention, SIG registry parsing and unknown-ID fallback, and API serialization. Verify page navigation and that the Live Feed remains redacted and volatile. Run existing scanner, signature, pipeline, storage, web, and browser-mode regression coverage. On the Pi, save compatible and address-only rules, confirm passive coverage labels and scanner status, confirm a derived passive filter reaches the existing matcher, and confirm Device Browser Stop restores passive filters without changing saved scan mode.
