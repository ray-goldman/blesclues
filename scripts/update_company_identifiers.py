#!/usr/bin/env python3
"""Generate the packaged Bluetooth SIG Company Identifier snapshot for a release."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bt_signature_detector.company_ids import SOURCE_URL, parse_company_registry, write_company_snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "src/bt_signature_detector/data/company_identifiers.json")
    args = parser.parse_args(argv)
    with urlopen(SOURCE_URL, timeout=30) as response:
        source = response.read().decode("utf-8")
    companies = parse_company_registry(source)
    write_company_snapshot(companies, args.output, retrieved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    print(f"Wrote {len(companies)} Bluetooth SIG company identifiers to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
