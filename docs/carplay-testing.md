# CarPlay and Siri testing notes

CarPlay and Siri integration varies by iOS version, vehicle head unit, notification permission, focus mode, and provider. The detector does not promise that an alert will appear in CarPlay or be spoken by Siri.

Test with a vehicle and phone you control while parked. First validate the local dashboard, then send a non-SMS test notification. Enable notifications for the chosen provider in iOS, connect CarPlay, and check the vehicle display and notification settings. Do not handle the phone while driving.

ntfy notifications are not guaranteed to surface in CarPlay. If testing SMS, Twilio must have valid credentials, an approved sender, a verified destination when required, and applicable carrier/A2P registration. SMS costs and carrier filtering can apply. `detector test-alert --confirm-sms` is an explicit live send. Never use a real equipment signature as the test signal; use the synthetic dry run.
