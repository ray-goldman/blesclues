# CarPlay and Siri testing notes

CarPlay and Siri behavior depends on the iOS version, vehicle head unit, notification permissions, Focus settings, and notification provider. BLE's Clues cannot guarantee that an alert will appear in CarPlay or be read aloud by Siri.

Test with a vehicle and phone you control while parked. Confirm the dashboard works, then send a non-SMS test notification. Allow notifications from the chosen provider in iOS, connect CarPlay, and check the vehicle display and notification settings. Do not handle the phone while driving.

ntfy notifications may not appear in CarPlay. SMS tests require working Twilio credentials, an approved sender, a verified destination when required, and any applicable carrier or A2P registration. Carrier filtering and message charges may apply. `detector test-alert --confirm-sms` sends a real SMS. Use a synthetic dry run; do not use a real equipment signature as the test signal.
