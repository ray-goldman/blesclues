from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Callable


@dataclass(frozen=True, slots=True)
class AccessPointStatus:
    active: bool
    ssid: str | None = None
    interface: str | None = None
    address: str | None = None
    error: str | None = None


class AccessPointClient:
    PROFILE = "BLE-Detector"
    def __init__(self, runner: Callable = subprocess.run) -> None:
        self.runner = runner

    def update(self, profile: str, changes: dict[str, object]) -> None:
        if profile != self.PROFILE:
            raise ValueError("only the fixed BLE-Detector profile may be changed")
        allowed = {"ssid", "passphrase", "channel", "country"}
        if not isinstance(changes, dict) or set(changes) - allowed:
            raise ValueError("AP changes contain unsupported fields")
        commands = []
        country = None
        if "ssid" in changes:
            ssid = changes["ssid"]
            if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32: raise ValueError("invalid SSID")
            commands.extend(["802-11-wireless.ssid", ssid])
        if "passphrase" in changes:
            password = changes["passphrase"]
            if not isinstance(password, str) or not 8 <= len(password) <= 63: raise ValueError("invalid WPA2 passphrase")
            commands.extend(["802-11-wireless-security.psk", password])
        if "channel" in changes:
            channel = changes["channel"]
            if isinstance(channel, bool) or not isinstance(channel, int) or not 1 <= channel <= 13: raise ValueError("invalid channel")
            commands.extend(["802-11-wireless.channel", str(channel)])
        if "country" in changes:
            country = changes["country"]
            if not isinstance(country, str) or len(country) != 2 or not country.isalpha(): raise ValueError("invalid country code")
            country = country.upper()
        try:
            if country:
                self.runner(["iw", "reg", "set", country], check=True, capture_output=True, text=True)
            if commands:
                self.runner(["nmcli", "connection", "modify", profile, *commands], check=True, capture_output=True, text=True)
            if commands or country:
                self.runner(["nmcli", "connection", "up", profile], check=True, capture_output=True, text=True)
        except subprocess.SubprocessError:
            raise RuntimeError("NetworkManager rejected the access point update") from None

    def activate(self, country: str) -> None:
        if not isinstance(country, str) or len(country) != 2 or not country.isalpha():
            raise ValueError("a two-letter regulatory country code is required")
        self.runner(["iw", "reg", "set", country.upper()], check=True, capture_output=True, text=True)
        self.runner(["nmcli", "connection", "up", self.PROFILE], check=True, capture_output=True, text=True)

    def read(self) -> AccessPointStatus:
        try:
            result = self.runner(["nmcli", "-t", "-f", "NAME,DEVICE,TYPE", "connection", "show", "--active"],
                                 check=True, capture_output=True, text=True)
            for row in result.stdout.splitlines():
                if row.startswith(self.PROFILE + ":"):
                    _, interface, _ = row.split(":", 2)
                    return AccessPointStatus(True, self.PROFILE, interface)
            return AccessPointStatus(False)
        except (OSError, subprocess.SubprocessError) as exc:
            return AccessPointStatus(False, error=str(exc))
