# BLE's Clues — Temporary Device Browser Mode

**Date:** 2026-10-18
**Status:** Approved

## Purpose

Add a separate authenticated Devices page for broad, live BLE discovery. An administrator can explicitly start a temporary browser session, inspect nearby advertising devices while it runs, and stop the session to return the detector to its configured scan mode and BlueZ advertisement filters.

Active scanning is allowed in this mode. The scanner may send BLE scan requests to advertisers that permit them. It must never connect to or pair with discovered devices.

## Goals

- Discover and show advertising BLE devices that do not match the configured passive `or_patterns`.
- Keep the existing passive filtered mode as the normal mode and preserve its saved settings.
- Provide explicit Start and Stop controls on a separate Devices page.
- Keep the detector's existing signature evaluation and notification pipeline running while browsing.
- Keep observations volatile and bounded to limit SD-card writes.
- Make the live inventory useful without implying that a BLE address identifies a real-world device or owner.

## Out of scope

- Wi-Fi scanning, Wi-Fi OUI matching, BLE connection, GATT enumeration, pairing, or device control.
- Adding or editing signature rules. The existing Settings page continues to manage BlueZ advertisement filters for normal passive scanning.
- Inferring that an observed name, address, company ID, or payload belongs to a particular product or organization.
- Saving a durable inventory or exporting observed-device histories.

## User experience

Add a **Devices** item to the authenticated navigation, separate from Monitor. It contains:

- The current scanner mode and whether a browser session is active.
- A short explanation that broad discovery uses active scan requests and does not connect or pair.
- A Start button when normal scanning is active and a Stop button during browser mode. Disable the control while a mode transition is pending and report transition failures clearly.
- A live table of currently observed devices, refreshed from same-origin authenticated API requests. Show observed name (or “Unnamed device”), observed BLE address, address type if the platform exposes it, RSSI, first seen, last seen, manufacturer data, and service UUIDs when present.
- A recent-activity list or last-seen indicator so repeated advertisements update a device row rather than creating a new row for every packet.
- Clear empty, scanning, stopped, and adapter-error states.

The address is an observed radio identifier, not a verified identity; BLE addresses may be private or rotate. The page labels these as observed devices and does not show manufacturer or prefix matches as product identification.

## Mode behavior and scanner ownership

The existing scanner systemd service remains the sole owner of the Bluetooth adapter. The web service never starts a second Bleak scanner. Starting or stopping browser mode calls a narrow privileged helper which manages a volatile override and restarts the existing scanner service.

- **Normal mode:** load the saved configuration and request its configured scan mode and BlueZ filters. With the current setup this is passive scanning constrained by `or_patterns`.
- **Browser mode:** use the same adapter, scanner reconnect behavior, callback, and detection pipeline, but request active scanning with no BlueZ `or_patterns`. This enables broad discovery without changing the persisted YAML.
- **Stop:** remove the volatile override and restart the scanner; it reloads the saved mode and filters.
- **Reboot:** `/run` is cleared, so the saved configured mode starts automatically. Browser mode is never made the persistent default.
- **Scanner/service restart while active:** the override remains in `/run`, so systemd recovery continues the active session until Stop or reboot. The UI reports the active mode based on the runtime state, not only the saved config.
- **Conflicting operation:** a second Start while browser mode is already active and a Stop when it is already stopped are idempotent. Simultaneous mode changes are serialized by the helper.

The helper accepts only `start` and `stop`, validates the expected runtime directory and state, and restarts only the detector scanner unit. The web process continues to use its existing narrowly scoped sudo integration; no shell input or arbitrary command is exposed by the API.

## Observation flow and state

Every advertisement received in either mode continues through the existing `DetectionPipeline`. Existing signature rules, observation thresholds, cooldowns, event persistence, and notifications keep their current semantics. Browser mode changes what the adapter receives; it does not disable detection.

The Devices inventory is a separate in-memory view keyed by the exact observed BLE address. For a repeated address, update last seen, RSSI, and fields present in the latest advertisement; preserve first seen for the current in-memory presence. A changed or randomized address appears as a separate row. Do not correlate it to a previous address.

Keep at most the configured live-scan limit (currently `web.max_live_scans`, default 100) and expire entries after the existing detector absence interval. Eviction is in memory only. Do not write ordinary device rows or raw advertisements to SQLite, config, journal, or release/update files. Continue the existing bounded volatile `/run` feed only as needed for the Monitor live window; avoid a disk flush on every advertisement, and rate-limit any mode transition log to one message per transition.

The authenticated Devices API may return full observed BLE addresses because the browser needs stable row keys and the dashboard already has UI-password authentication. Preserve authentication and CSRF requirements for mode-changing requests. Do not place addresses in URLs, systemd command lines, or logs. Existing `/api/scans` redaction remains unchanged for the Monitor feed.

## API and status contract

- Add `GET /api/devices/status` returning saved mode, effective runtime mode, browser-active state, and scanner service state.
- Add `GET /api/devices` returning a bounded volatile inventory with an update timestamp.
- Add `POST /api/devices/start` and `POST /api/devices/stop`; require the existing session and CSRF token. Return the resulting effective mode or a clear failure response.
- Existing `/api/status` reports the effective mode and browser-active flag so Monitor does not imply that the saved passive mode is currently in effect.
- Keep existing settings API behavior: editing `or_patterns` updates the saved passive configuration and restarts the scanner. If a browser session is active, Stop returns to the latest saved configuration, including any edits made during that session.

## Failure handling

- If the mode helper cannot write/remove its runtime override or restart systemd, return an error and leave the UI in the mode the service actually reports. Roll back the override if restart fails so requested and effective state do not drift.
- If the scanner cannot start active scanning, retain the scanner's existing capped reconnect/error behavior and expose its service status/error in the dashboard. Do not silently report a successful browser session as scanning.
- If Bluetooth is unavailable, keep the Devices page usable with an adapter-unavailable state and allow Stop to restore normal mode.
- A web service restart does not change scanner mode. Scanner restart recovery honors the runtime override while it exists.

## Acceptance criteria

1. Starting Devices mode changes the existing scanner to active, unfiltered BLE scanning without changing the saved configuration or spawning a second scanner.
2. The page displays a bounded, deduplicated live inventory and updates rows for repeated observations.
3. Advertisements continue through the normal detection pipeline while Devices mode is active.
4. Stop removes the runtime override and restores the saved scan mode and passive BlueZ filters.
5. Browser mode ends on reboot because its state is volatile; a normal startup uses saved configuration.
6. Start/Stop endpoints require authentication and CSRF protection and cannot invoke arbitrary commands.
7. No routine device inventory or advertisement payload is written to persistent storage or logs.
8. The scanner never connects, pairs, enumerates GATT services, or attempts device control.
9. Existing Monitor feed redaction, Settings behavior, signature evaluation, and normal passive scanning remain intact.

## Verification approach

Use injected scanner and service-control interfaces for automated coverage. Verify scanner construction uses active mode with no BlueZ filter in browser mode and restores the configured settings after Stop. Cover repeated device updates, inventory bounds and expiry, mode-transition rollback, idempotent Start/Stop, runtime state on scanner restart, CSRF/auth rejection, and continued pipeline processing. Run existing regression tests for scanner, pipeline, settings, and web behavior. On the Pi, confirm normal mode after reboot, start browser mode from the Devices page, observe at least one advertisement, stop, and confirm the configured passive mode and filters are active again.
