from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from .config import load_app_config
from .wifi_mode import WifiModeController


def _systemd_action(action: str) -> None:
    commands = {
        "scan-start": ["systemctl", "start", "bt-signature-detector-wifi.service"],
        "scan-stop": ["systemctl", "stop", "bt-signature-detector-wifi.service"],
        "ap-start": ["systemctl", "start", "bt-signature-detector-ap.service"],
        "ap-stop": ["systemctl", "stop", "bt-signature-detector-ap.service"],
    }
    subprocess.run(commands[action], check=True, capture_output=True, text=True, timeout=45)


def main(argv=None) -> int:
    if os.geteuid() != 0:
        print("Wi-Fi mode reconciler must run as root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("reconcile",))
    parser.add_argument("--config", type=Path, default=Path("/etc/bt-signature-detector/detector.yaml"))
    args = parser.parse_args(argv)
    try:
        config = load_app_config(args.config)
        mode = "scan" if config.wifi_scanning.enabled else "admin_ap" if config.access_point.enabled else "idle"
        WifiModeController(action=_systemd_action).reconcile(mode)
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
