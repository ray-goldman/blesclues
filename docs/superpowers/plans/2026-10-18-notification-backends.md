# Notification Backends Implementation Plan

> **For agentic workers:** Required sub-skill: use `superpowers:executing-plans` to implement this plan task by task. Do not begin implementation until the user approves the plan and selects an execution method.

**Goal:** Deliver offline audio, ntfy, and optional Twilio SMS notifications behind one failure-isolated event interface.

**Architecture:** A bounded asynchronous dispatcher fans each `DetectionEvent` to enabled backend adapters independently. Backends read credentials from secure references and never change scanner behavior.

**Tech Stack:** Python `asyncio`, `unittest`, `urllib`/HTTP, `aplay`, optional Twilio SDK.

**Spec:** [2026-10-18-raspberry-pi-ble-signature-detector-design.md](../specs/2026-10-18-raspberry-pi-ble-signature-detector-design.md)

## Global Constraints

- Only confirmed, alert-enabled signatures dispatch by default.
- Network timeouts or backend errors never interrupt scanning or other backends.
- Remote notifications omit complete Bluetooth identifiers by default.
- SMS is disabled by default and test sends require explicit confirmation.
- The full test suite uses fake transports and needs no network, audio device, or Twilio credentials.

## Review Focus

- Queue saturation/outage must remain bounded and observable: `test_notifications.py::test_queue_saturation_is_counted_without_blocking_submit`.
- A backend exception must not prevent another backend's delivery: `test_notifications.py::test_backend_failure_does_not_block_other_backends`.
- Remote message content must not leak full observed identifiers: `test_notifications.py::test_ntfy_message_redacts_identifier`.
- SMS rate limits must apply even when detector cooldown differs: `test_notifications.py::test_sms_rate_limit_suppresses_excess_messages`.
- Missing optional provider credentials must disable SMS cleanly: `test_notifications.py::test_sms_missing_credentials_is_disabled`.

---

### Task 1: Notifier contract and bounded dispatcher

**Files:**
- Create: `src/bt_signature_detector/notifications/__init__.py`
- Create: `src/bt_signature_detector/notifications/base.py`
- Create: `src/bt_signature_detector/notifications/dispatcher.py`
- Create: `tests/test_notifications.py`

**Interfaces:**
- Consumes `DetectionEvent` from the detection core plan.
- Produces `Notifier.send(event: DetectionEvent) -> Awaitable[None]`, `Notifier.test() -> Awaitable[None]`, and `NotificationDispatcher.submit(event) -> bool`.
- Dispatcher accepts a fixed list of notifiers, bounded queue size, timeout, and injectable counters; each notifier has an isolated worker.

- [ ] **Step 1: Write failing tests** for confirmed/alert-enabled filtering, fan-out, exception isolation, timeout, bounded queue saturation, and graceful drain.
- [ ] **Step 2: Run** `python -m unittest tests.test_notifications -v`; confirm dispatcher tests fail before implementation.
- [ ] **Step 3: Implement the protocol and bounded worker dispatcher**; preserve the same `DetectionEvent` instance/data for every enabled backend.
- [ ] **Step 4: Run** `python -m unittest tests.test_notifications -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: add notification dispatcher`.

### Task 2: Audio and ntfy adapters

**Files:**
- Create: `src/bt_signature_detector/notifications/audio.py`
- Create: `src/bt_signature_detector/notifications/ntfy.py`
- Modify: `config/detector.example.yaml`
- Modify: `tests/test_notifications.py`

**Interfaces:**
- Consumes the notifier protocol and notification config.
- Produces `AudioNotifier(sound_path: Path, player: str = "aplay")` and `NtfyNotifier(server_url, topic, priority, timeout, auth_provider, http_transport)`.
- HTTP transport is injected for tests; default implementation sends a bounded-timeout POST and excludes `event.observed_identifier`.

- [ ] **Step 1: Write failing tests** for offline audio invocation/test command, ntfy message/priority/auth headers, identifier redaction, and network timeout behavior.
- [ ] **Step 2: Run** `python -m unittest tests.test_notifications -v`; verify the new cases fail.
- [ ] **Step 3: Implement audio and ntfy adapters**; run subprocess/HTTP work outside the scanner callback.
- [ ] **Step 4: Run** `python -m unittest tests.test_notifications -v`; confirm all pass.
- [ ] **Step 5: Commit** with `feat: add audio and ntfy notifications`.

### Task 3: Twilio SMS, rate limits, and CLI test-alert integration

**Files:**
- Create: `src/bt_signature_detector/notifications/sms.py`
- Modify: `src/bt_signature_detector/cli.py`
- Modify: `pyproject.toml`
- Modify: `config/detector.example.yaml`
- Modify: `tests/test_notifications.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Produces `SmsProvider.send_message(to: str, body: str) -> Awaitable[str]`, `TwilioProvider`, and `SmsNotifier(provider, destination, cooldown, clock)`.
- Twilio SDK is an optional extra and imported only when Twilio SMS is enabled.
- `detector test-alert --confirm-sms` is required before an SMS test message can be sent.

- [ ] **Step 1: Write failing tests** for provider injection, secrets resolution, SMS message brevity/redaction, rate-limit behavior, missing credentials, disabled-by-default behavior, and explicit CLI confirmation.
- [ ] **Step 2: Run** `python -m unittest tests.test_notifications tests.test_cli -v`; confirm failures.
- [ ] **Step 3: Implement provider abstraction and Twilio adapter** with no credentials in files/examples; wire enabled backends into `test-alert`.
- [ ] **Step 4: Run** `python -m unittest discover -s tests -v`; confirm core and backend suites pass.
- [ ] **Step 5: Commit** with `feat: add optional Twilio SMS alerts`.
