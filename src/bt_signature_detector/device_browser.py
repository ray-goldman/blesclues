from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Callable


RUNTIME_STATE = Path("/run/bt-signature-detector-web/device-browser.json")


def _read_marker(state_file: Path) -> bytes | None:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(state_file, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128:
            return None
        with os.fdopen(fd, "rb") as source:
            fd = -1
            return source.read(129)
    finally:
        if fd >= 0:
            os.close(fd)


def _is_active(state_file: Path) -> bool:
    raw = _read_marker(state_file)
    if raw is None:
        return False
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(state, dict) and state.get("mode") == "active"


def _write_active(state_file: Path) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".device-browser-", dir=state_file.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump({"mode": "active"}, output, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        try:
            import grp
            os.chown(temp_name, -1, grp.getgrnam("bt-detector").gr_gid)
        except (ImportError, KeyError, PermissionError):
            pass
        os.chmod(temp_name, 0o640)
        os.replace(temp_name, state_file)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _restore(state_file: Path, previous: bytes | None) -> None:
    if previous is None:
        try:
            state_file.unlink()
        except FileNotFoundError:
            pass
        return
    state_file.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".device-browser-restore-", dir=state_file.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(previous)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_name, 0o640)
        os.replace(temp_name, state_file)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def set_browser_mode(active: bool, *, state_file: Path,
                     restart: Callable[[], None]) -> bool:
    """Change the volatile scan-mode override and restart the scanner once."""
    state_file = Path(state_file)
    was_active = _is_active(state_file)
    if was_active == active:
        return active
    previous = _read_marker(state_file)
    if active:
        _write_active(state_file)
    else:
        try:
            state_file.unlink()
        except FileNotFoundError:
            pass
    try:
        restart()
    except Exception:
        _restore(state_file, previous)
        raise
    return active


def main(argv: list[str] | None = None, *, state_file: Path = RUNTIME_STATE,
         restart: Callable[[], None] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0] not in {"start", "stop"}:
        print("Usage: bt-detector-device-browser start|stop", file=sys.stderr)
        return 2
    if restart is None:
        restart = lambda: subprocess.run(
            ["systemctl", "restart", "bt-signature-detector.service"],
            check=True, capture_output=True, text=True, timeout=30)
    try:
        set_browser_mode(arguments[0] == "start", state_file=state_file, restart=restart)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"Unable to change BLE browser mode: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
