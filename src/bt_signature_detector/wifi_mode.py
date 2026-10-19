"""Serialized transitions for the shared WLAN radio."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Callable, Literal

WifiMode = Literal["idle", "scan", "admin_ap"]


@dataclass(frozen=True, slots=True)
class WifiModeStatus:
    mode: WifiMode


class WifiModeController:
    def __init__(self, *, action: Callable[[str], None], initial_mode: WifiMode = "idle") -> None:
        if initial_mode not in {"idle", "scan", "admin_ap"}:
            raise ValueError("invalid initial Wi-Fi mode")
        self.action = action
        self._mode: WifiMode = initial_mode
        self._lock = threading.RLock()

    @property
    def mode(self) -> WifiMode:
        with self._lock:
            return self._mode

    @staticmethod
    def _stop_action(mode: WifiMode) -> str | None:
        return {"scan": "scan-stop", "admin_ap": "ap-stop", "idle": None}[mode]

    @staticmethod
    def _start_action(mode: WifiMode) -> str | None:
        return {"scan": "scan-start", "admin_ap": "ap-start", "idle": None}[mode]

    def set_mode(self, mode: WifiMode) -> WifiModeStatus:
        if mode not in {"idle", "scan", "admin_ap"}:
            raise ValueError("mode must be idle, scan, or admin_ap")
        with self._lock:
            previous = self._mode
            if mode == previous:
                return WifiModeStatus(mode)
            stop = self._stop_action(previous)
            start = self._start_action(mode)
            if stop:
                self.action(stop)
            try:
                if start:
                    self.action(start)
            except Exception as start_error:
                cleanup = self._stop_action(mode)
                if cleanup:
                    try:
                        self.action(cleanup)
                    except Exception:
                        pass
                # A failed transition leaves the shared radio idle. Restoring
                # the previous mode could unexpectedly re-enable the AP or
                # scanner after the operator requested a different mode.
                self._mode = "idle"
                raise
            self._mode = mode
            return WifiModeStatus(mode)

    def reconcile(self, configured_mode: WifiMode) -> WifiModeStatus:
        if configured_mode not in {"idle", "scan", "admin_ap"}:
            raise ValueError("configured mode must be idle, scan, or admin_ap")
        with self._lock:
            self.action("scan-stop")
            self.action("ap-stop")
            self._mode = "idle"
            return self.set_mode(configured_mode)
