from __future__ import annotations

import asyncio
import base64
import json
from urllib.request import Request, urlopen

from ..models import DetectionEvent


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> None:
    request = Request(url, data=body, headers=headers, method="POST")
    with urlopen(request, timeout=timeout) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"ntfy returned HTTP {response.status}")


class NtfyNotifier:
    def __init__(self, server_url: str, topic: str, priority: int = 3, timeout: float = 5.0,
                 auth_provider=None, http_transport=None) -> None:
        if not topic or any(ch in topic for ch in "/?#"):
            raise ValueError("ntfy topic must be a non-empty topic name")
        self.url = server_url.rstrip("/") + "/" + topic
        self.priority = priority
        self.timeout = timeout
        self.auth_provider = auth_provider
        self.transport = http_transport or _post

    def _headers(self, title: str) -> dict[str, str]:
        headers = {"Title": title, "Priority": str(self.priority), "Content-Type": "text/plain; charset=utf-8"}
        auth = self.auth_provider() if callable(self.auth_provider) else self.auth_provider
        if isinstance(auth, tuple) and len(auth) == 2:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        elif isinstance(auth, str) and auth:
            headers["Authorization"] = "Bearer " + auth
        return headers

    async def send(self, event: DetectionEvent) -> None:
        # Identifiers and addresses are deliberately excluded from remote messages.
        body = f"BLE signature detected: {event.signature_name} ({event.confidence.value})".encode("utf-8")
        await asyncio.wait_for(asyncio.to_thread(self.transport, self.url, body,
            self._headers(event.signature_name), self.timeout), timeout=self.timeout)

    async def test(self) -> None:
        await asyncio.wait_for(asyncio.to_thread(self.transport, self.url,
            b"BLE detector test notification", self._headers("BLE detector test"), self.timeout), timeout=self.timeout)
