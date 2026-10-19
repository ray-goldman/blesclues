import json
from pathlib import Path
import tempfile
import unittest

from bt_signature_detector.device_browser import RUNTIME_STATE, main, set_browser_mode


class DeviceBrowserControllerTests(unittest.TestCase):
    def test_default_marker_uses_writable_web_runtime_directory(self):
        self.assertEqual(RUNTIME_STATE, Path("/run/bt-signature-detector-web/device-browser.json"))

    def test_start_writes_active_marker_and_restarts_once(self):
        with tempfile.TemporaryDirectory() as temp:
            state_file = Path(temp) / "device-browser.json"
            restarts = []

            active = set_browser_mode(True, state_file=state_file, restart=lambda: restarts.append("restart"))

            self.assertTrue(active)
            self.assertEqual(json.loads(state_file.read_text()), {"mode": "active"})
            self.assertEqual(restarts, ["restart"])

    def test_repeating_start_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            state_file = Path(temp) / "device-browser.json"
            state_file.write_text('{"mode":"active"}')
            restarts = []

            active = set_browser_mode(True, state_file=state_file, restart=lambda: restarts.append("restart"))

            self.assertTrue(active)
            self.assertEqual(restarts, [])

    def test_symlinked_marker_is_not_trusted_as_active_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_file = root / "device-browser.json"
            target = root / "target.json"
            target.write_text('{"mode":"active"}')
            try:
                state_file.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            restarts = []

            set_browser_mode(True, state_file=state_file, restart=lambda: restarts.append("restart"))

            self.assertEqual(restarts, ["restart"])
            self.assertFalse(state_file.is_symlink())
            self.assertEqual(json.loads(state_file.read_text()), {"mode": "active"})

    def test_stop_removes_marker_and_restarts_once(self):
        with tempfile.TemporaryDirectory() as temp:
            state_file = Path(temp) / "device-browser.json"
            state_file.write_text('{"mode":"active"}')
            restarts = []

            active = set_browser_mode(False, state_file=state_file, restart=lambda: restarts.append("restart"))

            self.assertFalse(active)
            self.assertFalse(state_file.exists())
            self.assertEqual(restarts, ["restart"])

    def test_restart_failure_restores_previous_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            state_file = Path(temp) / "device-browser.json"
            original = b'{"mode":"active"}'
            state_file.write_bytes(original)

            with self.assertRaisesRegex(RuntimeError, "restart failed"):
                set_browser_mode(False, state_file=state_file,
                                 restart=lambda: (_ for _ in ()).throw(RuntimeError("restart failed")))

            self.assertEqual(state_file.read_bytes(), original)

    def test_main_rejects_anything_but_start_or_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            restarts = []
            self.assertEqual(main(["restart"], state_file=Path(temp) / "state.json",
                                  restart=lambda: restarts.append("restart")), 2)
            self.assertEqual(restarts, [])


if __name__ == "__main__":
    unittest.main()
