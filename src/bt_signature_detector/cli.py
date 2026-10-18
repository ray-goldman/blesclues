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


def _parser():
    parser = argparse.ArgumentParser(prog="detector", description="Passive BLE signature detector")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "test-alert", "list-signatures", "status", "recent", "validate-config"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, default=Path("config/detector.yaml"))
        if name == "scan": command.add_argument("--dry-run", action="store_true")
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
        signatures = load_signatures(signatures_path)
        if args.command == "list-signatures":
            for signature in signatures: print(f"{signature.signature_id}\t{signature.confidence.value}\t{signature.name}")
            return 0
        store = EventStore(config.storage.path, retention_days=config.storage.retention_days, max_events=config.storage.max_events)
        if args.command == "recent":
            for event in store.recent(args.limit): print(f"{event.last_seen.isoformat()}\t{event.signature_name}\t{event.observed_identifier}")
            return 0
        if args.command == "status":
            print(f"signatures={len(signatures)} events={len(store.recent(10000))} scan_mode={config.bluetooth.scan_mode}")
            return 0
        if args.command == "test-alert":
            print("Test alert requested (notification backend initializes with service runtime).")
            return 0
        pipeline = DetectionPipeline(signatures, store=store,
            cooldown_seconds=config.detection.cooldown_seconds,
            absence_seconds=config.detection.absence_seconds,
            global_min_rssi=config.detection.global_min_rssi)
        stop = asyncio.Event()
        async def run():
            if args.dry_run:
                await run_synthetic(pipeline.process, stop)
            else:
                await BleScanner(config.bluetooth).run(pipeline.process, stop)
        asyncio.run(run())
        print(f"advertisements_processed={pipeline.advertisements_processed} store_errors={pipeline.store_errors}")
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
