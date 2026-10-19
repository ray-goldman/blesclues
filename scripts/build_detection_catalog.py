from __future__ import annotations

import argparse
from pathlib import Path

from bt_signature_detector.builtin_rules import (
    catalog_as_json,
    parse_scoring_settings,
    parse_source_catalog,
)


def build_catalog(source_dir: Path, output: Path) -> None:
    signatures = (source_dir / "signatures.json").read_text(encoding="utf-8")
    ssids = (source_dir / "ssid_patterns.txt").read_text(encoding="utf-8")
    names = (source_dir / "ble_name_patterns.txt").read_text(encoding="utf-8")
    ouis = (source_dir / "ouis.csv").read_text(encoding="utf-8")
    rules = parse_source_catalog(signatures, ssids, names, ouis)
    scoring = parse_scoring_settings(signatures)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(catalog_as_json(rules, scoring), encoding="utf-8")
    temporary.replace(output)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the normalized BLE/Wi-Fi detection catalog.")
    parser.add_argument("--source-dir", type=Path, default=Path("src/bt_signature_detector/data/source"))
    parser.add_argument("--output", type=Path, default=Path("src/bt_signature_detector/data/default_detection_rules.json"))
    args = parser.parse_args()
    build_catalog(args.source_dir, args.output)


if __name__ == "__main__":
    main()
