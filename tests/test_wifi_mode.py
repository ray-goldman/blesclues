import threading
import unittest

from bt_signature_detector.wifi_mode import WifiModeController


class WifiModeTests(unittest.TestCase):
    def test_switches_between_idle_scan_and_admin_ap_and_is_idempotent(self):
        actions = []
        controller = WifiModeController(action=actions.append)
        self.assertEqual(controller.set_mode("scan").mode, "scan")
        self.assertEqual(controller.set_mode("scan").mode, "scan")
        self.assertEqual(controller.set_mode("admin_ap").mode, "admin_ap")
        self.assertEqual(controller.set_mode("idle").mode, "idle")
        self.assertEqual(actions, ["scan-start", "scan-stop", "ap-start", "ap-stop"])

    def test_start_failure_leaves_both_modes_off(self):
        actions = []
        def action(name):
            actions.append(name)
            if name == "ap-start":
                raise RuntimeError("AP unavailable")
        controller = WifiModeController(action=action)
        controller.set_mode("scan")
        with self.assertRaisesRegex(RuntimeError, "AP unavailable"):
            controller.set_mode("admin_ap")
        self.assertEqual(controller.mode, "idle")
        self.assertEqual(actions, ["scan-start", "scan-stop", "ap-start", "ap-stop"])

    def test_scan_start_failure_does_not_restore_admin_ap(self):
        actions = []
        def action(name):
            actions.append(name)
            if name == "scan-start": raise RuntimeError("scanner unavailable")
        controller = WifiModeController(action=action, initial_mode="admin_ap")
        with self.assertRaisesRegex(RuntimeError, "scanner unavailable"):
            controller.set_mode("scan")
        self.assertEqual(controller.mode, "idle")
        self.assertEqual(actions, ["ap-stop", "scan-start", "scan-stop"])

    def test_reconcile_stops_both_before_starting_saved_mode(self):
        actions = []
        controller = WifiModeController(action=actions.append)
        controller.reconcile("admin_ap")
        self.assertEqual(actions, ["scan-stop", "ap-stop", "ap-start"])
        self.assertIn(controller.mode, {"scan", "admin_ap"})

    def test_concurrent_switches_are_serialized(self):
        actions = []
        controller = WifiModeController(action=actions.append)
        barrier = threading.Barrier(3)
        def switch(mode):
            barrier.wait()
            controller.set_mode(mode)
        threads = [threading.Thread(target=switch, args=(mode,)) for mode in ("scan", "admin_ap")]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join()
        self.assertIn(controller.mode, {"scan", "admin_ap"})
        self.assertEqual(actions.count("scan-start") + actions.count("ap-start"), 2)
        self.assertEqual(actions.count("scan-stop") + actions.count("ap-stop"), 1)


if __name__ == "__main__": unittest.main()
