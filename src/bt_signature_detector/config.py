from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Any
from urllib.parse import urlsplit

import yaml


@dataclass(frozen=True, slots=True)
class OrPatternConfig:
    start_position: int
    ad_data_type: int
    pattern: bytes


@dataclass(frozen=True, slots=True)
class BluetoothConfig:
    adapter: str | None = None
    scan_mode: str = "passive"
    or_patterns: tuple[OrPatternConfig, ...] = ()
    reconnect_initial_seconds: float = 1.0
    reconnect_max_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    global_min_rssi: int | None = None
    cooldown_seconds: int = 300
    absence_seconds: int = 120
    min_observations: int = 3
    signature_file: Path = Path("signatures.yaml")


@dataclass(frozen=True, slots=True)
class StorageConfig:
    path: Path = Path("events.sqlite3")
    retention_days: int = 30
    max_events: int = 10000


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "INFO"
    debug: bool = False


@dataclass(frozen=True, slots=True)
class AudioConfig:
    enabled: bool = False
    sound_path: Path | None = None
    player: str = "aplay"


@dataclass(frozen=True, slots=True)
class NtfyConfig:
    enabled: bool = False
    server_url: str = "https://ntfy.sh"
    topic: str = ""
    priority: int = 3
    timeout_seconds: float = 5.0
    token_env: str | None = None
    username_env: str | None = None
    password_env: str | None = None


@dataclass(frozen=True, slots=True)
class SmsConfig:
    enabled: bool = False
    provider: str = "twilio"
    destination: str = ""
    account_sid_env: str = "TWILIO_ACCOUNT_SID"
    auth_token_env: str = "TWILIO_AUTH_TOKEN"
    from_number_env: str = "TWILIO_FROM_NUMBER"
    cooldown_seconds: int = 300


@dataclass(frozen=True, slots=True)
class NotificationConfig:
    queue_size: int = 64
    timeout_seconds: float = 5.0
    audio: AudioConfig = AudioConfig()
    ntfy: NtfyConfig = NtfyConfig()
    sms: SmsConfig = SmsConfig()


@dataclass(frozen=True, slots=True)
class AccessPointConfig:
    enabled: bool = True
    ssid: str = "BLE-Detector"
    passphrase: str = "easypassword"
    interface_address: str = "192.168.4.1/24"
    country: str = ""
    channel: int = 6
    profile_name: str = "BLE-Detector"


@dataclass(frozen=True, slots=True)
class WebConfig:
    enabled: bool = True
    port: int = 8080
    password_hash_file: Path = Path("ui-password.hash")
    session_key_file: Path = Path("ui-session.key")
    max_live_scans: int = 100


@dataclass(frozen=True, slots=True)
class UpdateConfig:
    enabled: bool = True
    manifest_url: str | None = None
    public_key_file: Path = Path("/etc/bt-signature-detector/update.pub")
    max_bundle_bytes: int = 20_000_000
    timeout_seconds: float = 10.0


@dataclass(frozen=True, slots=True)
class AppConfig:
    bluetooth: BluetoothConfig = BluetoothConfig()
    detection: DetectionConfig = DetectionConfig()
    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    notifications: NotificationConfig = NotificationConfig()
    access_point: AccessPointConfig = AccessPointConfig()
    web: WebConfig = WebConfig()
    updates: UpdateConfig = UpdateConfig()
    schema_version: int = 1


def _mapping(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must be a mapping")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{path} keys must be strings")
    return value


def _section(root: Mapping[str, Any], name: str, allowed: set[str]) -> Mapping[str, Any]:
    section = _mapping(root.get(name, {}), name)
    unknown = set(section) - allowed
    if unknown:
        key = sorted(unknown)[0]
        raise ValueError(f"{name}.{key} is not a supported setting")
    return section


def _int(value: object, path: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{path} must be an integer from {minimum} to {maximum}")
    return value


def _float(value: object, path: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= float(value) <= maximum:
        raise ValueError(f"{path} must be a number from {minimum} to {maximum}")
    return float(value)


def _bool(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be true or false")
    return value


def validate_config_data(data: Mapping[str, object]) -> AppConfig:
    root = _mapping(data, "config")
    root_unknown = set(root) - {"schema_version", "bluetooth", "detection", "storage", "logging", "notifications", "access_point", "web", "updates"}
    if root_unknown:
        raise ValueError(f"{sorted(root_unknown)[0]} is not a supported setting")
    version = root.get("schema_version", 1)
    if version != 1:
        raise ValueError("schema_version must be 1")

    b = _section(root, "bluetooth", {"adapter", "scan_mode", "or_patterns", "reconnect_initial_seconds", "reconnect_max_seconds"})
    scan_mode = b.get("scan_mode", "passive")
    if scan_mode not in {"passive", "active"}:
        raise ValueError("bluetooth.scan_mode must be passive or active")
    patterns_raw = b.get("or_patterns", [])
    if not isinstance(patterns_raw, list):
        raise ValueError("bluetooth.or_patterns must be a list")
    patterns: list[OrPatternConfig] = []
    for index, raw in enumerate(patterns_raw):
        item = _mapping(raw, f"bluetooth.or_patterns[{index}]")
        unknown = set(item) - {"start_position", "ad_data_type", "pattern"}
        if unknown:
            raise ValueError(f"bluetooth.or_patterns[{index}].{sorted(unknown)[0]} is not supported")
        try:
            content = bytes.fromhex(str(item.get("pattern", "")))
        except ValueError as exc:
            raise ValueError(f"bluetooth.or_patterns[{index}].pattern must be hexadecimal") from exc
        if not content:
            raise ValueError(f"bluetooth.or_patterns[{index}].pattern must contain at least one byte")
        patterns.append(OrPatternConfig(
            _int(item.get("start_position", 0), f"bluetooth.or_patterns[{index}].start_position", minimum=0, maximum=255),
            _int(item.get("ad_data_type"), f"bluetooth.or_patterns[{index}].ad_data_type", minimum=1, maximum=255),
            content,
        ))
    if scan_mode == "passive" and not patterns:
        raise ValueError("bluetooth.or_patterns is required for passive scanning")
    adapter = b.get("adapter")
    if adapter is not None and (not isinstance(adapter, str) or not adapter.strip()):
        raise ValueError("bluetooth.adapter must be a non-empty string or null")
    reconnect_initial = _float(b.get("reconnect_initial_seconds", 1), "bluetooth.reconnect_initial_seconds", minimum=0.1, maximum=60)
    reconnect_max = _float(b.get("reconnect_max_seconds", 30), "bluetooth.reconnect_max_seconds", minimum=reconnect_initial, maximum=600)

    d = _section(root, "detection", {"global_min_rssi", "cooldown_seconds", "absence_seconds", "min_observations", "signature_file"})
    min_rssi = d.get("global_min_rssi")
    if min_rssi is not None:
        min_rssi = _int(min_rssi, "detection.global_min_rssi", minimum=-127, maximum=20)
    detection = DetectionConfig(
        global_min_rssi=min_rssi,
        cooldown_seconds=_int(d.get("cooldown_seconds", 300), "detection.cooldown_seconds", minimum=0, maximum=86400),
        absence_seconds=_int(d.get("absence_seconds", 120), "detection.absence_seconds", minimum=1, maximum=604800),
        min_observations=_int(d.get("min_observations", 3), "detection.min_observations", minimum=3, maximum=100000),
        signature_file=Path(d.get("signature_file", "signatures.yaml")),
    )

    s = _section(root, "storage", {"path", "retention_days", "max_events"})
    storage = StorageConfig(
        path=Path(s.get("path", "events.sqlite3")),
        retention_days=_int(s.get("retention_days", 30), "storage.retention_days", minimum=1, maximum=36500),
        max_events=_int(s.get("max_events", 10000), "storage.max_events", minimum=1, maximum=10_000_000),
    )

    l = _section(root, "logging", {"level", "debug"})
    level = l.get("level", "INFO")
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("logging.level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    logging_config = LoggingConfig(level=level, debug=_bool(l.get("debug", False), "logging.debug"))

    n = _section(root, "notifications", {"queue_size", "timeout_seconds", "audio", "ntfy", "sms"})
    audio_raw = _section(n, "audio", {"enabled", "sound_path", "player"})
    ntfy_raw = _section(n, "ntfy", {"enabled", "server_url", "topic", "priority", "timeout_seconds", "token_env", "username_env", "password_env"})
    sms_raw = _section(n, "sms", {"enabled", "provider", "destination", "account_sid_env", "auth_token_env", "from_number_env", "cooldown_seconds"})
    topic = ntfy_raw.get("topic", "")
    if not isinstance(topic, str):
        raise ValueError("notifications.ntfy.topic must be a string")
    server_url = ntfy_raw.get("server_url", "https://ntfy.sh")
    if not isinstance(server_url, str) or not server_url.startswith(("http://", "https://")):
        raise ValueError("notifications.ntfy.server_url must be an HTTP(S) URL")
    provider = sms_raw.get("provider", "twilio")
    if provider != "twilio":
        raise ValueError("notifications.sms.provider must be twilio")
    notifications = NotificationConfig(
        queue_size=_int(n.get("queue_size", 64), "notifications.queue_size", minimum=1, maximum=10000),
        timeout_seconds=_float(n.get("timeout_seconds", 5), "notifications.timeout_seconds", minimum=0.1, maximum=300),
        audio=AudioConfig(
            enabled=_bool(audio_raw.get("enabled", False), "notifications.audio.enabled"),
            sound_path=Path(audio_raw["sound_path"]) if audio_raw.get("sound_path") else None,
            player=str(audio_raw.get("player", "aplay")),
        ),
        ntfy=NtfyConfig(
            enabled=_bool(ntfy_raw.get("enabled", False), "notifications.ntfy.enabled"),
            server_url=server_url,
            topic=topic,
            priority=_int(ntfy_raw.get("priority", 3), "notifications.ntfy.priority", minimum=1, maximum=5),
            timeout_seconds=_float(ntfy_raw.get("timeout_seconds", 5), "notifications.ntfy.timeout_seconds", minimum=0.1, maximum=300),
            token_env=ntfy_raw.get("token_env"),
            username_env=ntfy_raw.get("username_env"),
            password_env=ntfy_raw.get("password_env"),
        ),
        sms=SmsConfig(
            enabled=_bool(sms_raw.get("enabled", False), "notifications.sms.enabled"),
            provider=provider,
            destination=str(sms_raw.get("destination", "")),
            account_sid_env=str(sms_raw.get("account_sid_env", "TWILIO_ACCOUNT_SID")),
            auth_token_env=str(sms_raw.get("auth_token_env", "TWILIO_AUTH_TOKEN")),
            from_number_env=str(sms_raw.get("from_number_env", "TWILIO_FROM_NUMBER")),
            cooldown_seconds=_int(sms_raw.get("cooldown_seconds", 300), "notifications.sms.cooldown_seconds", minimum=0, maximum=86400),
        ),
    )

    ap = _section(root, "access_point", {"enabled", "ssid", "passphrase", "interface_address", "country", "channel", "profile_name"})
    ssid = ap.get("ssid", "BLE-Detector")
    passphrase = ap.get("passphrase", "easypassword")
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32:
        raise ValueError("access_point.ssid must be 1 to 32 UTF-8 bytes")
    if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63:
        raise ValueError("access_point.passphrase must be 8 to 63 characters")
    country = ap.get("country", "")
    if not isinstance(country, str) or len(country) not in {0, 2}:
        raise ValueError("access_point.country must be an ISO 3166-1 alpha-2 code")
    access_point = AccessPointConfig(
        enabled=_bool(ap.get("enabled", True), "access_point.enabled"),
        ssid=ssid,
        passphrase=passphrase,
        interface_address=str(ap.get("interface_address", "192.168.4.1/24")),
        country=country.upper(),
        channel=_int(ap.get("channel", 6), "access_point.channel", minimum=1, maximum=13),
        profile_name=str(ap.get("profile_name", "BLE-Detector")),
    )

    w = _section(root, "web", {"enabled", "port", "password_hash_file", "session_key_file", "max_live_scans"})
    web = WebConfig(
        enabled=_bool(w.get("enabled", True), "web.enabled"),
        port=_int(w.get("port", 8080), "web.port", minimum=1, maximum=65535),
        password_hash_file=Path(w.get("password_hash_file", "ui-password.hash")),
        session_key_file=Path(w.get("session_key_file", "ui-session.key")),
        max_live_scans=_int(w.get("max_live_scans", 100), "web.max_live_scans", minimum=1, maximum=10000),
    )

    u = _section(root, "updates", {"enabled", "manifest_url", "public_key_file", "max_bundle_bytes", "timeout_seconds"})
    manifest_url = u.get("manifest_url")
    if manifest_url is not None:
        parsed_url = urlsplit(manifest_url) if isinstance(manifest_url, str) else None
        if parsed_url is None or parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.fragment:
            raise ValueError("updates.manifest_url must be a valid HTTPS URL or null")
    updates = UpdateConfig(
        enabled=_bool(u.get("enabled", True), "updates.enabled"),
        manifest_url=manifest_url,
        public_key_file=Path(u.get("public_key_file", "/etc/bt-signature-detector/update.pub")),
        max_bundle_bytes=_int(u.get("max_bundle_bytes", 20_000_000), "updates.max_bundle_bytes", minimum=1024, maximum=500_000_000),
        timeout_seconds=_float(u.get("timeout_seconds", 10), "updates.timeout_seconds", minimum=0.1, maximum=300),
    )

    return AppConfig(
        bluetooth=BluetoothConfig(adapter=adapter, scan_mode=scan_mode, or_patterns=tuple(patterns), reconnect_initial_seconds=reconnect_initial, reconnect_max_seconds=reconnect_max),
        detection=detection,
        storage=storage,
        logging=logging_config,
        notifications=notifications,
        access_point=access_point,
        web=web,
        updates=updates,
        schema_version=version,
    )


def load_app_config(path: Path) -> AppConfig:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: unable to load configuration: {exc}") from exc
    if data is None:
        raise ValueError(f"{path}: configuration is empty")
    try:
        return validate_config_data(_mapping(data, str(path)))
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
