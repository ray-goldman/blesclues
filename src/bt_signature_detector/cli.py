from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
import sys

from .config import load_app_config
from .pipeline import DetectionPipeline
from .scanner import BleScanner
from .signatures import load_signatures
from .store import EventStore
from .synthetic import run_synthetic
from .notifications.audio import AudioNotifier
from .notifications.dispatcher import NotificationDispatcher
from .notifications.ntfy import NtfyNotifier
from .notifications.sms import SmsNotifier
from .runtime_cache import RuntimeScanCache


def _parser():
    parser = argparse.ArgumentParser(prog="detector", description="Passive BLE signature detector")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "test-alert", "list-signatures", "status", "recent", "validate-config"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, default=Path("config/detector.yaml"))
        if name == "scan": command.add_argument("--dry-run", action="store_true")
        if name == "test-alert": command.add_argument("--confirm-sms", action="store_true")
        if name == "list-signatures": command.add_argument("--signatures", type=Path)
        if name == "recent": command.add_argument("--limit", type=int, default=20)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        config = load_app_config(args.config)
        logging.basicConfig(level=config.logging.level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        if args.command == "validate-config":
            print(f"Configuration valid: {args.config}")
            return 0
        signatures_path = args.signatures if args.command == "list-signatures" and args.signatures else config.detection.signature_file
        if not signatures_path.is_absolute():
            signatures_path = args.config.resolve().parent / signatures_path
        signatures = () if args.command == "test-alert" else load_signatures(signatures_path)
        if args.command == "list-signatures":
            for signature in signatures: print(f"{signature.signature_id}\t{signature.confidence.value}\t{signature.name}")
            return 0
        store = EventStore(config.storage.path, retention_days=config.storage.retention_days, max_events=config.storage.max_events)
        from datetime import datetime, timezone
        store.prune(datetime.now(timezone.utc))
        if args.command == "recent":
            for event in store.recent(args.limit): print(f"{event.last_seen.isoformat()}\t{event.signature_name}\t{event.observed_identifier}")
            return 0
        if args.command == "status":
            print(f"signatures={len(signatures)} events={len(store.recent(10000))} scan_mode={config.bluetooth.scan_mode}")
            return 0
        notifiers = []
        if config.notifications.audio.enabled:
            if config.notifications.audio.sound_path is None:
                raise ValueError("notifications.audio.sound_path is required when audio is enabled")
            notifiers.append(AudioNotifier(config.notifications.audio.sound_path, config.notifications.audio.player))
        if config.notifications.ntfy.enabled:
            ntfy = config.notifications.ntfy
            auth_provider = None
            if ntfy.token_env:
                import os
                auth_provider = lambda: os.environ.get(ntfy.token_env)
            elif ntfy.username_env and ntfy.password_env:
                import os
                auth_provider = lambda: (os.environ.get(ntfy.username_env, ""), os.environ.get(ntfy.password_env, ""))
            notifiers.append(NtfyNotifier(ntfy.server_url, ntfy.topic, ntfy.priority, ntfy.timeout_seconds, auth_provider))
        if config.notifications.sms.enabled:
            sms = config.notifications.sms
            notifiers.append(SmsNotifier.from_environment(sms.destination,
                cooldown_seconds=sms.cooldown_seconds, account_sid_env=sms.account_sid_env,
                auth_token_env=sms.auth_token_env, from_number_env=sms.from_number_env))
        if args.command == "test-alert":
            if config.notifications.sms.enabled and not args.confirm_sms:
                raise ValueError("SMS test requires --confirm-sms")
            if not notifiers:
                raise ValueError("no notification backend is enabled")
            async def dispatch_tests():
                for notifier in notifiers:
                    await notifier.test()
            asyncio.run(dispatch_tests())
            print("Test notification sent to enabled backends")
            return 0
        dispatcher = NotificationDispatcher(notifiers, queue_size=config.notifications.queue_size,
                                            timeout_seconds=config.notifications.timeout_seconds)
        pipeline = DetectionPipeline(signatures, store=store,
            cooldown_seconds=config.detection.cooldown_seconds,
            absence_seconds=config.detection.absence_seconds,
            global_min_rssi=config.detection.global_min_rssi, dispatcher=dispatcher,
            scan_cache=RuntimeScanCache(Path("/run/bt-signature-detector/scans.json"), config.web.max_live_scans)
            if sys.platform != "win32" and Path("/run/bt-signature-detector").is_dir() else None)
        async def run():
            await dispatcher.start()
            stop = asyncio.Event()
            try:
                if args.dry_run:
                    await run_synthetic(pipeline.process, stop)
                else:
                    await BleScanner(config.bluetooth).run(pipeline.process, stop)
            finally:
                await dispatcher.close()
        asyncio.run(run())
        print(f"advertisements_processed={pipeline.advertisements_processed} store_errors={pipeline.store_errors}")
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
