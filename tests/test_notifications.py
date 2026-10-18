import asyncio
import unittest
from datetime import datetime, timezone

from bt_signature_detector.models import Confidence, DetectionEvent
from bt_signature_detector.notifications.dispatcher import NotificationDispatcher
from bt_signature_detector.notifications.ntfy import NtfyNotifier
from bt_signature_detector.notifications.sms import SmsNotifier


def event(confidence=Confidence.CONFIRMED):
    return DetectionEvent("sig", "Equipment", confidence, "aa:bb:cc:dd", datetime.now(timezone.utc), datetime.now(timezone.utc), -50, 3, alert_enabled=True)


class NotificationsTests(unittest.IsolatedAsyncioTestCase):
    async def test_backend_failure_does_not_block_other_backends(self):
        received = []
        class Broken:
            async def send(self, event): raise RuntimeError("offline")
        class Good:
            async def send(self, item): received.append(item)
        dispatcher = NotificationDispatcher([Broken(), Good()], queue_size=2)
        await dispatcher.start()
        dispatcher.submit(event())
        await dispatcher.close()
        self.assertEqual(len(received), 1)
        self.assertEqual(dispatcher.errors, 1)

    async def test_non_confirmed_and_not_alert_enabled_are_not_submitted(self):
        class Notify:
            async def send(self, item): raise AssertionError("should not send")
        dispatcher = NotificationDispatcher([Notify()], queue_size=2)
        await dispatcher.start()
        self.assertFalse(dispatcher.submit(event(Confidence.POSSIBLE)))
        denied = event()
        denied = DetectionEvent(denied.signature_id, denied.signature_name, denied.confidence,
            denied.observed_identifier, denied.first_seen, denied.last_seen, denied.strongest_rssi,
            denied.observation_count, alert_enabled=False)
        self.assertFalse(dispatcher.submit(denied))
        await dispatcher.close()

    async def test_queue_saturation_is_counted_without_blocking_submit(self):
        gate = asyncio.Event()
        sending = asyncio.Event()
        class Slow:
            async def send(self, item):
                sending.set()
                await gate.wait()
        dispatcher = NotificationDispatcher([Slow()], queue_size=1)
        await dispatcher.start()
        self.assertTrue(dispatcher.submit(event()))
        await sending.wait()
        self.assertTrue(dispatcher.submit(event()))
        self.assertFalse(dispatcher.submit(event()))
        self.assertEqual(dispatcher.dropped, 1)
        gate.set()
        await dispatcher.close()

    async def test_ntfy_message_redacts_identifier(self):
        requests = []
        def transport(url, body, headers, timeout): requests.append((url, body, headers, timeout))
        notifier = NtfyNotifier("https://ntfy.sh", "demo", 4, 2, http_transport=transport)
        await notifier.send(event())
        self.assertNotIn(b"aa:bb:cc:dd", requests[0][1])
        self.assertEqual(requests[0][2]["Priority"], "4")

    async def test_sms_rate_limit_suppresses_excess_messages(self):
        sent = []
        now = [0]
        class Provider:
            async def send_message(self, to, body): sent.append(body)
        notifier = SmsNotifier(Provider(), "+15555550123", cooldown_seconds=60, clock=lambda: now[0])
        await notifier.send(event())
        await notifier.send(event())
        now[0] = 60
        await notifier.send(event())
        self.assertEqual(len(sent), 2)
        self.assertNotIn("aa:bb", sent[0])


if __name__ == "__main__": unittest.main()
