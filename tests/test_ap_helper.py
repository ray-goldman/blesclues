import unittest
import subprocess

from bt_signature_detector.access_point import AccessPointClient, AccessPointStatus


class ApHelperTests(unittest.TestCase):
    def test_rejects_unlisted_fields_profile_names_and_bad_values(self):
        client = AccessPointClient(runner=lambda *args, **kwargs: None)
        with self.assertRaises(ValueError): client.update("other", {"ssid": "x"})
        with self.assertRaises(ValueError): client.update("Detector-Admin", {"dns": "8.8.8.8"})
        with self.assertRaises(ValueError): client.update("Detector-Admin", {"passphrase": "secret"})

    def test_allowed_changes_use_fixed_nmcli_profile_and_do_not_return_secrets(self):
        calls = []
        client = AccessPointClient(runner=lambda command, **kwargs: calls.append(command))
        client.update("Detector-Admin", {"ssid": "Detector", "passphrase": "newpassword", "channel": 11, "country": "US", "enabled": True})
        modify = next(call for call in calls if "modify" in call)
        self.assertIn("Detector", modify)
        self.assertIn("newpassword", modify)
        self.assertEqual(modify[3], "Detector-Admin")
        self.assertIn(["nmcli", "connection", "up", "Detector-Admin"], calls)

    def test_status_failure_is_reported_as_data(self):
        def fail(*args, **kwargs): raise OSError("nmcli missing")
        self.assertIn("nmcli missing", AccessPointClient(runner=fail).read().error)

    def test_activate_enables_wifi_then_sets_country_and_starts_profile(self):
        calls = []
        client = AccessPointClient(runner=lambda command, **kwargs: calls.append(command))
        client.activate("US", enabled=True)
        self.assertEqual(calls, [
            ["systemctl", "stop", "bt-signature-detector-wifi.service"],
            ["iw", "reg", "set", "US"],
            ["nmcli", "radio", "wifi", "on"],
            ["nmcli", "connection", "up", "Detector-Admin"],
        ])

    def test_nmcli_error_does_not_echo_wifi_passphrase(self):
        def fail(command, **kwargs): raise subprocess.CalledProcessError(1, command)
        with self.assertRaises(RuntimeError) as error:
            AccessPointClient(runner=fail).update("Detector-Admin", {"passphrase": "private-passphrase"})
        self.assertNotIn("private-passphrase", str(error.exception))


if __name__ == "__main__": unittest.main()
