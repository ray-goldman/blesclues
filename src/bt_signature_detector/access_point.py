from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
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
    PROFILE = "Detector-Admin"
    ENABLE_MARKER = "/run/bt-signature-detector-ap.enabled"
    def __init__(self, runner: Callable = subprocess.run, enabled_marker: Path | None = None) -> None:
        self.runner = runner
        self.enabled_marker = enabled_marker or Path(self.ENABLE_MARKER)

    def _set_enabled_marker(self, enabled: bool) -> None:
        if enabled:
            self.enabled_marker.parent.mkdir(parents=True, exist_ok=True)
            self.enabled_marker.write_text("enabled\n", encoding="ascii")
        else:
            try:
                self.enabled_marker.unlink()
            except FileNotFoundError:
                pass

    def update(self, profile: str, changes: dict[str, object]) -> None:
        if profile != self.PROFILE:
            raise ValueError("only the fixed Detector-Admin profile may be changed")
        allowed = {"ssid", "passphrase", "channel", "country", "enabled"}
        if not isinstance(changes, dict) or set(changes) - allowed:
            raise ValueError("AP changes contain unsupported fields")
        commands = []
        country = None
        enabled = changes.get("enabled")
        if "enabled" in changes and not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
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
            if enabled is True:
                self.runner(["systemctl", "stop", "bt-signature-detector-wifi.service"], check=True, capture_output=True, text=True)
                self.runner(["nmcli", "radio", "wifi", "on"], check=True, capture_output=True, text=True)
                self.runner(["nmcli", "connection", "up", profile], check=True, capture_output=True, text=True)
                self._set_enabled_marker(True)
                self.runner(["systemctl", "start", "bt-signature-detector-dhcp.service"], check=True, capture_output=True, text=True)
            elif enabled is False:
                self.runner(["systemctl", "stop", "bt-signature-detector-dhcp.service"], check=True, capture_output=True, text=True)
                try:
                    self.runner(["nmcli", "connection", "down", profile], check=True, capture_output=True, text=True)
                finally:
                    self._set_enabled_marker(False)
            elif commands and self.enabled_marker.exists():
                self.runner(["nmcli", "connection", "up", profile], check=True, capture_output=True, text=True)
        except subprocess.SubprocessError:
            raise RuntimeError("NetworkManager rejected the hidden Wi-Fi network update") from None

    def activate(self, country: str, enabled: bool = False) -> None:
        if not isinstance(country, str) or len(country) != 2 or not country.isalpha():
            raise ValueError("a two-letter regulatory country code is required")
        if enabled:
            self.runner(["systemctl", "stop", "bt-signature-detector-wifi.service"], check=True, capture_output=True, text=True)
            self.runner(["iw", "reg", "set", country.upper()], check=True, capture_output=True, text=True)
            self.runner(["nmcli", "radio", "wifi", "on"], check=True, capture_output=True, text=True)
            self.runner(["nmcli", "connection", "up", self.PROFILE], check=True, capture_output=True, text=True)
            self._set_enabled_marker(True)
        else:
            self.runner(["systemctl", "stop", "bt-signature-detector-dhcp.service"], check=False, capture_output=True, text=True)
            self.runner(["nmcli", "connection", "down", self.PROFILE], check=False, capture_output=True, text=True)
            self._set_enabled_marker(False)

    def deactivate(self) -> None:
        self.runner(["nmcli", "connection", "down", self.PROFILE], check=False, capture_output=True, text=True)
        self._set_enabled_marker(False)

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
