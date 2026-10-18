from __future__ import annotations

import asyncio
import os
import time
from typing import Protocol

from ..models import DetectionEvent


class SmsProvider(Protocol):
    async def send_message(self, to: str, body: str) -> str: ...


class TwilioProvider:
    def __init__(self, account_sid: str, auth_token: str, from_number: str) -> None:
        self.account_sid, self.auth_token, self.from_number = account_sid, auth_token, from_number

    async def send_message(self, to: str, body: str) -> str:
        def send():
            try:
                from twilio.rest import Client
            except ImportError as exc:
                raise RuntimeError("SMS requires the optional Twilio extra") from exc
            message = Client(self.account_sid, self.auth_token).messages.create(to=to, from_=self.from_number, body=body)
            return message.sid
        return await asyncio.to_thread(send)


class SmsNotifier:
    def __init__(self, provider: SmsProvider | None, destination: str, *, cooldown_seconds: int = 300,
                 clock=time.monotonic) -> None:
        self.provider = provider
        self.destination = destination
        self.cooldown = cooldown_seconds
        self.clock = clock
        self.last_sent: float | None = None

    @classmethod
    def from_environment(cls, destination: str, *, cooldown_seconds: int = 300,
                         account_sid_env: str = "TWILIO_ACCOUNT_SID",
                         auth_token_env: str = "TWILIO_AUTH_TOKEN",
                         from_number_env: str = "TWILIO_FROM_NUMBER"):
        account, token, sender = (os.environ.get(name) for name in (account_sid_env, auth_token_env, from_number_env))
        if not account or not token or not sender:
            return cls(None, destination, cooldown_seconds=cooldown_seconds)
        return cls(TwilioProvider(account, token, sender), destination, cooldown_seconds=cooldown_seconds)

    async def send(self, event: DetectionEvent) -> None:
        if self.provider is None:
            return
        now = self.clock()
        if self.last_sent is not None and now - self.last_sent < self.cooldown:
            return
        body = f"BLE signature detected: {event.signature_name} ({event.confidence.value})"
        await self.provider.send_message(self.destination, body)
        self.last_sent = now

    async def test(self) -> None:
        if self.provider is None:
            raise RuntimeError("SMS is disabled because Twilio credentials are missing")
        await self.provider.send_message(self.destination, "BLE detector test message")
