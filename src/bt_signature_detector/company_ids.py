from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import tempfile
import os
from importlib.resources import files
from types import MappingProxyType
from typing import Mapping

import yaml


SOURCE_URL = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml"
_ID_RE = re.compile(r"^0x([0-9A-F]{4})$")


@dataclass(frozen=True, slots=True)
class CompanyIdentifierRegistry:
    source_url: str
    retrieved_at: str
    companies: Mapping[int, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "companies", MappingProxyType(dict(self.companies)))

    @classmethod
    def from_package(cls) -> "CompanyIdentifierRegistry":
        resource = files("bt_signature_detector").joinpath("data", "company_identifiers.json")
        return cls.from_text(resource.read_text(encoding="utf-8"))

    @classmethod
    def from_json(cls, path: Path) -> "CompanyIdentifierRegistry":
        try:
            return cls.from_text(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"{path}: unable to read company identifier registry: {exc}") from exc

    @classmethod
    def from_text(cls, source: str) -> "CompanyIdentifierRegistry":
        try:
            data = json.loads(source)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("company identifier registry must be valid JSON") from exc
        if not isinstance(data, dict) or set(data) != {"source_url", "retrieved_at", "companies"}:
            raise ValueError("company identifier registry has an invalid shape")
        if not isinstance(data["source_url"], str) or not data["source_url"].strip():
            raise ValueError("source_url must be a non-empty string")
        if not isinstance(data["retrieved_at"], str) or not data["retrieved_at"].strip():
            raise ValueError("retrieved_at must be a non-empty string")
        raw = data["companies"]
        if not isinstance(raw, dict):
            raise ValueError("companies must be a mapping")
        companies: dict[int, str] = {}
        for key, name in raw.items():
            match = _ID_RE.fullmatch(key) if isinstance(key, str) else None
            if match is None:
                raise ValueError(f"invalid company identifier key: {key!r}")
            company_id = int(match.group(1), 16)
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"company name for {key} must be a non-empty string")
            companies[company_id] = name.strip()
        return cls(data["source_url"], data["retrieved_at"], companies)

    def lookup(self, company_id: int) -> str | None:
        if isinstance(company_id, bool) or not isinstance(company_id, int) or not 0 <= company_id <= 0xFFFF:
            return None
        return self.companies.get(company_id)


def parse_company_registry(source: str) -> dict[int, str]:
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ValueError(f"unable to parse Bluetooth SIG company registry: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"company_identifiers"} or not isinstance(data["company_identifiers"], list):
        raise ValueError("expected company_identifiers list")
    companies: dict[int, str] = {}
    for index, record in enumerate(data["company_identifiers"]):
        if not isinstance(record, dict) or set(record) != {"value", "name"}:
            raise ValueError(f"company_identifiers[{index}] must contain value and name")
        company_id, name = record["value"], record["name"]
        if isinstance(company_id, bool) or not isinstance(company_id, int) or not 0 <= company_id <= 0xFFFF:
            raise ValueError(f"company_identifiers[{index}].value must be an integer from 0 to 65535")
        if company_id in companies:
            raise ValueError(f"duplicate company identifier 0x{company_id:04X}")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"company_identifiers[{index}].name must be a non-empty string")
        companies[company_id] = name.strip()
    return companies


def write_company_snapshot(companies: Mapping[int, str], path: Path, *, retrieved_at: str | None = None,
                           source_url: str = SOURCE_URL) -> None:
    validated: dict[int, str] = {}
    for company_id, name in companies.items():
        if isinstance(company_id, bool) or not isinstance(company_id, int) or not 0 <= company_id <= 0xFFFF:
            raise ValueError("company identifiers must be integers from 0 to 65535")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"company name for 0x{company_id:04X} must not be empty")
        validated[company_id] = name.strip()
    output = {"source_url": source_url,
              "retrieved_at": retrieved_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "companies": {f"0x{company_id:04X}": validated[company_id] for company_id in sorted(validated)}}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(output, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
