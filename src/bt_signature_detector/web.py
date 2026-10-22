from __future__ import annotations

from dataclasses import dataclass, asdict
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
from functools import wraps
from typing import Callable
import tempfile
import subprocess
import threading
import time
import yaml

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from .watchlists import WatchListStore
from .watch_filters import watch_rule_filter_coverage
from .company_ids import CompanyIdentifierRegistry
from . import BUILD_NAME, __version__

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WebServices:
    password_hash_file: Path
    session_key_file: Path
    status: Callable[[], dict] = lambda: {}
    events: Callable[[int], list] = lambda limit: []
    scans: Callable[[], list] = lambda: []
    devices: Callable[[], list] = lambda: []
    wifi_status: Callable[[], dict] = lambda: {"mode": "idle", "scan_active": False, "admin_ap_active": False}
    wifi_observations: Callable[[], list] = lambda: []
    errors: Callable[[], list] = lambda: []
    max_live_scans: int = 100
    config_file: Path | None = None
    ap_update: Callable[[dict], None] | None = None
    set_wifi_mode: Callable[[str], None] | None = None
    update_manager: object | None = None
    max_update_bytes: int = 20_000_000
    restart_scanner: Callable[[], None] | None = None
    watchlists: WatchListStore | None = None
    company_identifiers: CompanyIdentifierRegistry | None = None


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt + digest).decode("ascii")


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, payload = encoded.split("$", 1)
        raw = base64.b64decode(payload, validate=True)
        if algorithm != "scrypt" or len(raw) != 48: return False
        expected = hashlib.scrypt(password.encode("utf-8"), salt=raw[:16], n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(expected, raw[16:])
    except (ValueError, TypeError):
        return False


def _session_signing_key(key: bytes, password_hash: str) -> bytes:
    return hmac.new(key, b"blesclues-ui-session\0" + password_hash.encode("ascii"), hashlib.sha256).digest()


def _ensure_dashboard_certificate(cert_file: Path, key_file: Path, hosts: list[str]) -> None:
    if cert_file.exists() and key_file.exists():
        return
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key_file.parent.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = [x509.DNSName("blesclues.local")]
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BLE's Clues local dashboard")])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    key_tmp = key_file.with_suffix(key_file.suffix + ".tmp")
    cert_tmp = cert_file.with_suffix(cert_file.suffix + ".tmp")
    key_tmp.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    os.chmod(key_tmp, 0o600)
    cert_tmp.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_tmp, 0o644)
    os.replace(key_tmp, key_file)
    os.replace(cert_tmp, cert_file)


def _jsonable(item):
    if hasattr(item, "__dataclass_fields__"):
        value = asdict(item)
        for key, field in list(value.items()):
            if hasattr(field, "isoformat"): value[key] = field.isoformat()
            elif hasattr(field, "value"): value[key] = field.value
        return value
    if isinstance(item, dict): return dict(item)
    return item


def create_app(services: WebServices) -> Flask:
    app = Flask(__name__, template_folder="web_templates", static_folder="web_static", static_url_path="/static")
    services.password_hash_file.parent.mkdir(parents=True, exist_ok=True)
    services.session_key_file.parent.mkdir(parents=True, exist_ok=True)
    if not services.session_key_file.exists():
        services.session_key_file.write_bytes(secrets.token_bytes(32))
        try: os.chmod(services.session_key_file, 0o600)
        except OSError: pass
    session_key = services.session_key_file.read_bytes()
    try:
        password_hash = services.password_hash_file.read_text(encoding="ascii")
    except OSError:
        password_hash = ""
    app.secret_key = _session_signing_key(session_key, password_hash)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=True)
    app.config["MAX_CONTENT_LENGTH"] = services.max_update_bytes + 65_536
    app.extensions["web_services"] = services
    login_attempts: dict[str, dict[str, float | int]] = {}
    login_attempts_lock = threading.Lock()
    @app.context_processor
    def inject_build_info():
        return {"build_name": BUILD_NAME, "build_version": __version__}
    settings_lock = threading.RLock()

    def serialize_settings(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            with settings_lock:
                return fn(*args, **kwargs)
        return wrapped

    def init_csrf(): session.setdefault("csrf_token", secrets.token_urlsafe(32))

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                if request.path.startswith("/api/"): return jsonify({"error": "authentication required"}), 401
                return redirect(url_for("login"))
            init_csrf()
            return fn(*args, **kwargs)
        return wrapped

    def login_retry_after(address: str, now: float) -> int:
        with login_attempts_lock:
            for client, state in list(login_attempts.items()):
                if now - float(state["last_seen"]) > 600:
                    login_attempts.pop(client, None)
            state = login_attempts.get(address)
            if state is None:
                return 0
            state["last_seen"] = now
            return max(0, int(float(state.get("blocked_until", 0)) - now + 0.999))

    def record_login_failure(address: str, now: float) -> int:
        with login_attempts_lock:
            state = login_attempts.setdefault(address, {"failures": 0, "last_seen": now})
            if len(login_attempts) > 1024:
                oldest = min(login_attempts, key=lambda client: float(login_attempts[client]["last_seen"]))
                if oldest != address:
                    login_attempts.pop(oldest, None)
            state["failures"] = int(state["failures"]) + 1
            state["last_seen"] = now
            failures = int(state["failures"])
            if failures >= 5:
                state["blocked_until"] = now + min(300, 30 * (2 ** min(failures - 5, 3)))
            return failures

    def record_login_success(address: str) -> None:
        with login_attempts_lock:
            login_attempts.pop(address, None)

    @app.get("/")
    def index():
        if not services.password_hash_file.exists(): return redirect(url_for("setup"))
        if not session.get("authenticated"): return redirect(url_for("login"))
        init_csrf()
        return render_template("index.html", csrf=session["csrf_token"])

    @app.get("/devices")
    @login_required
    def devices_page():
        init_csrf()
        return render_template("devices.html", csrf=session["csrf_token"])

    @app.get("/live")
    @login_required
    def live_page():
        return render_template("live.html", csrf=session["csrf_token"])

    @app.get("/watchlists")
    @login_required
    def watchlists_page():
        return render_template("watchlists.html", csrf=session["csrf_token"])

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if services.password_hash_file.exists(): return redirect(url_for("login"))
        if request.method == "GET": return render_template("login.html", setup=True)
        password = request.form.get("password", "")
        if len(password) < 12: return "Password must be at least 12 characters", 400
        services.password_hash_file.write_text(_password_hash(password), encoding="ascii")
        try: os.chmod(services.password_hash_file, 0o600)
        except OSError: pass
        app.secret_key = _session_signing_key(session_key, services.password_hash_file.read_text(encoding="ascii"))
        session.clear()
        session["authenticated"] = True
        init_csrf()
        logger.info("Initial dashboard password configured from %s", request.remote_addr or "unknown")
        return "UI password created", 200

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET": return render_template("login.html", setup=False)
        address = request.remote_addr or "unknown"
        now = time.monotonic()
        retry_after = login_retry_after(address, now)
        if retry_after:
            return "Too many failed login attempts. Wait before trying again.", 429, {"Retry-After": str(retry_after)}
        try: stored = services.password_hash_file.read_text(encoding="ascii")
        except OSError: return redirect(url_for("setup"))
        if not _verify_password(request.form.get("password", ""), stored):
            failures = record_login_failure(address, now)
            logger.warning("Dashboard login failed from %s (failure %d)", address, failures)
            return "Invalid password", 401
        record_login_success(address)
        session.clear()
        session["authenticated"] = True
        init_csrf()
        logger.info("Dashboard login succeeded from %s", address)
        return "Logged in", 200

    @app.before_request
    def csrf_guard():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint not in {"setup", "login"}:
            if request.path.startswith("/api/") and not session.get("authenticated"):
                return jsonify({"error": "authentication required"}), 401
            token = str(request.headers.get("X-CSRF-Token", request.form.get("csrf_token", "")))
            if not session.get("authenticated") or not hmac.compare_digest(token, str(session.get("csrf_token", ""))): abort(403)

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return "Logged out", 200

    @app.post("/password")
    @login_required
    def change_password():
        old, new = request.form.get("old_password", ""), request.form.get("new_password", "")
        try: stored = services.password_hash_file.read_text(encoding="ascii")
        except OSError: return "Password is not configured", 400
        if not _verify_password(old, stored): return "Invalid current password", 401
        if len(new) < 12: return "Password must be at least 12 characters", 400
        new_hash = _password_hash(new)
        services.password_hash_file.write_text(new_hash, encoding="ascii")
        try: os.chmod(services.password_hash_file, 0o600)
        except OSError: pass
        app.secret_key = _session_signing_key(session_key, new_hash)
        session.clear()
        logger.info("Dashboard password changed from %s", request.remote_addr or "unknown")
        return "Password changed. Sign in again.", 200

    def current_scan_status():
        status = dict(services.status())
        configured = status.get("configured_scan_mode", status.get("scan_mode", "unknown"))
        status["configured_scan_mode"] = configured
        status["effective_scan_mode"] = configured
        status["scan_mode"] = configured
        return status

    @app.get("/api/status")
    @login_required
    def api_status(): return jsonify(current_scan_status())

    @app.get("/api/devices/status")
    @login_required
    def api_devices_status(): return jsonify(current_scan_status())

    @app.get("/api/devices")
    @login_required
    def api_devices():
        devices = services.devices()[-services.max_live_scans:]
        for item in devices:
            if isinstance(item, dict):
                item["manufacturer_names"] = manufacturer_names(item.get("manufacturer_data"))
        return jsonify({"devices": devices})

    @app.get("/api/wifi/status")
    @login_required
    def api_wifi_status():
        try:
            return jsonify(services.wifi_status())
        except (OSError, RuntimeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 503

    @app.get("/api/wifi/observations")
    @login_required
    def api_wifi_observations():
        try:
            observations = services.wifi_observations()[-services.max_live_scans:]
            if services.watchlists is not None:
                from datetime import datetime
                from .signatures import match_wifi_signature
                from .wifi_scanner import WifiObservation
                ignored = [signature for signature in services.watchlists.list_signatures()
                           if signature.enabled and signature.ignorelist and signature.protocol == "wifi"]
                def is_ignored(item):
                    if not isinstance(item, dict):
                        return False
                    try:
                        stamp = item.get("observed_at")
                        if isinstance(stamp, str):
                            stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                        observation = WifiObservation(str(item.get("ssid") or ""), str(item["bssid"]),
                            item.get("signal"), item.get("channel"), item.get("security"), stamp)
                        return any(match_wifi_signature(signature, observation) for signature in ignored)
                    except (KeyError, TypeError, ValueError):
                        return False
                observations = [item for item in observations if not is_ignored(item)]
            return jsonify({"observations": [_jsonable(item) for item in observations]})
        except (OSError, RuntimeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 503

    @app.get("/api/detections/rules")
    @login_required
    def api_builtin_rules():
        try:
            from .builtin_rules import load_builtin_rules, load_builtin_scoring
            rules = load_builtin_rules()
            scoring = load_builtin_scoring()
            return jsonify({"scoring": asdict(scoring), "rules": [
                {"rule_id": rule.rule_id, "protocol": rule.protocol, "vendor": rule.vendor,
                 "match_type": rule.match_type, "pattern": rule.pattern, "confidence": rule.confidence,
                 "score": rule.score, "source": rule.source, "notes": rule.notes,
                 "device_class": list(rule.device_class), "relevance": rule.relevance,
                 "false_positives": list(rule.false_positives)} for rule in rules]})
        except (OSError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/events")
    @login_required
    def api_events():
        try: limit = min(max(int(request.args.get("limit", "20")), 1), 100)
        except ValueError: limit = 20
        return jsonify({"events": [_jsonable(item) for item in services.events(limit)]})

    @app.get("/api/scans")
    @login_required
    def api_scans():
        scans = [_jsonable(item) for item in services.scans()][-services.max_live_scans:]
        for item in scans:
            if isinstance(item, dict):
                item["manufacturer_names"] = manufacturer_names(item.get("manufacturer_data"))
                if "identifier" in item: item["identifier"] = "redacted"
        return jsonify({"scans": scans})

    def manufacturer_names(manufacturer_data):
        registry = services.company_identifiers
        if registry is None or not isinstance(manufacturer_data, (dict, list, tuple)):
            return {}
        names = {}
        for raw_id in manufacturer_data:
            try:
                company_id = int(raw_id, 0) if isinstance(raw_id, str) else int(raw_id)
            except (TypeError, ValueError):
                continue
            name = registry.lookup(company_id)
            if name is not None:
                names[str(raw_id)] = name
        return names

    def watch_rule_data(signature):
        criteria = {}
        if signature.protocol == "wifi":
            if signature.ssid_pattern is not None:
                criteria[{"exact": "ssid_exact", "contains": "ssid_contains", "regex": "ssid_regex"}[signature.ssid_mode]] = signature.ssid_pattern
            if signature.bssid_exact:
                criteria["bssid_exact"] = signature.bssid_exact
            if signature.bssid_prefixes:
                criteria["bssid_prefixes"] = list(signature.bssid_prefixes)
            if signature.wifi_channels:
                criteria["wifi_channels"] = list(signature.wifi_channels)
            if signature.wifi_security:
                criteria["wifi_security"] = list(signature.wifi_security)
        if signature.protocol == "ble" and signature.exact_identifiers:
            criteria["observed_identifiers"] = list(signature.exact_identifiers)
        if signature.protocol == "ble" and signature.identifier_prefixes:
            criteria["identifier_prefixes"] = list(signature.identifier_prefixes)
        if signature.protocol == "ble" and signature.name_pattern is not None:
            criteria["name_exact" if signature.name_mode == "exact" else "name_regex" if signature.name_mode == "regex" else "name_contains"] = signature.name_pattern
        if signature.protocol == "ble" and signature.manufacturer_ids:
            criteria["manufacturer_ids"] = list(signature.manufacturer_ids)
        if signature.protocol == "ble" and signature.manufacturer_id is not None and signature.manufacturer_pattern is not None:
            value = signature.manufacturer_pattern.hex()
            if signature.manufacturer_mask is not None:
                value = {"pattern": value, "mask": signature.manufacturer_mask.hex()}
            criteria["manufacturer_data"] = {str(signature.manufacturer_id): value}
        if signature.protocol == "ble" and signature.service_uuids:
            criteria["service_uuids"] = list(signature.service_uuids)
        if signature.protocol == "ble" and signature.service_data:
            criteria["service_data"] = {key: value.hex() for key, value in signature.service_data.items()}
        coverage = watch_rule_filter_coverage(signature).status
        return {"id": signature.signature_id, "label": signature.name, "enabled": signature.enabled,
                "protocol": signature.protocol,
                "watchlist_name": signature.watchlist, "ignorelist_name": signature.ignorelist,
                "match_mode": signature.match_mode, "criteria": criteria, "filter_coverage": coverage,
                "manufacturer_names": {**manufacturer_names(criteria.get("manufacturer_data")),
                    **manufacturer_names(criteria.get("manufacturer_ids"))},
                "confidence": signature.confidence.value, "min_observations": signature.min_observations,
                "alert_enabled": signature.alert_enabled}

    def run_watchlist_mutation(operation):
        if services.watchlists is None:
            return jsonify({"error": "watch lists are unavailable"}), 503
        try:
            restart = services.restart_scanner or (lambda: None)
            result = services.watchlists.transaction(operation, restart=restart)
            return result
        except (OSError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/watchlists")
    @login_required
    def api_watchlists():
        if services.watchlists is None: return jsonify({"error": "watch lists are unavailable"}), 503
        try:
            grouped = {}
            for signature in services.watchlists.list_signatures():
                if signature.watchlist is None:
                    continue
                grouped.setdefault(signature.watchlist, []).append(watch_rule_data(signature))
            lists = [{"name": name, "rules": sorted(rules, key=lambda rule: rule["label"].casefold())}
                     for name, rules in sorted(grouped.items(), key=lambda item: item[0].casefold())]
            return jsonify({"watchlists": lists})
        except (OSError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/ignorelists")
    @login_required
    def api_ignorelists():
        if services.watchlists is None: return jsonify({"error": "ignore lists are unavailable"}), 503
        try:
            grouped = {}
            for signature in services.watchlists.list_signatures():
                if signature.ignorelist is not None:
                    grouped.setdefault(signature.ignorelist, []).append(watch_rule_data(signature))
            lists = [{"name": name, "rules": sorted(rules, key=lambda rule: rule["label"].casefold())}
                     for name, rules in sorted(grouped.items(), key=lambda item: item[0].casefold())]
            return jsonify({"ignorelists": lists})
        except (OSError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 500

    @app.post("/api/watchlists/rules")
    @login_required
    def api_create_watch_rule():
        data = request.get_json(silent=True)
        if not isinstance(data, dict): return jsonify({"error": "a JSON object is required"}), 400
        if services.watchlists is None: return jsonify({"error": "watch lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.create_rule(data))
        if isinstance(result, tuple): return result
        return jsonify({"rule": watch_rule_data(result)}), 201

    @app.post("/api/watchlists/rename")
    @login_required
    def api_rename_watchlist():
        data = request.get_json(silent=True)
        if (not isinstance(data, dict) or set(data) != {"old_name", "new_name"}
                or not isinstance(data["old_name"], str) or not isinstance(data["new_name"], str)):
            return jsonify({"error": "old_name and new_name are required"}), 400
        if services.watchlists is None: return jsonify({"error": "watch lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.rename_list(data["old_name"], data["new_name"]))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.post("/api/watchlists/rules/<signature_id>/enabled")
    @login_required
    def api_set_watch_rule_enabled(signature_id):
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {"enabled"} or not isinstance(data["enabled"], bool):
            return jsonify({"error": "enabled must be a boolean"}), 400
        if services.watchlists is None: return jsonify({"error": "watch lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.set_enabled(signature_id, data["enabled"]))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.delete("/api/watchlists/rules/<signature_id>")
    @login_required
    def api_delete_watch_rule(signature_id):
        if services.watchlists is None: return jsonify({"error": "watch lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.delete_rule(signature_id))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.post("/api/watchlists/delete")
    @login_required
    def api_delete_watchlist():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {"name"} or not isinstance(data["name"], str):
            return jsonify({"error": "name is required"}), 400
        if services.watchlists is None: return jsonify({"error": "watch lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.delete_list(data["name"]))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.post("/api/ignorelists/rules")
    @login_required
    def api_create_ignore_rule():
        data = request.get_json(silent=True)
        if not isinstance(data, dict): return jsonify({"error": "a JSON object is required"}), 400
        if services.watchlists is None: return jsonify({"error": "ignore lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.create_ignore_rule(data))
        if isinstance(result, tuple): return result
        return jsonify({"rule": watch_rule_data(result)}), 201

    @app.post("/api/ignorelists/rename")
    @login_required
    def api_rename_ignorelist():
        data = request.get_json(silent=True)
        if (not isinstance(data, dict) or set(data) != {"old_name", "new_name"}
                or not isinstance(data["old_name"], str) or not isinstance(data["new_name"], str)):
            return jsonify({"error": "old_name and new_name are required"}), 400
        if services.watchlists is None: return jsonify({"error": "ignore lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.rename_ignore_list(data["old_name"], data["new_name"]))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.post("/api/ignorelists/rules/<signature_id>/enabled")
    @login_required
    def api_set_ignore_rule_enabled(signature_id):
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {"enabled"} or not isinstance(data["enabled"], bool):
            return jsonify({"error": "enabled must be a boolean"}), 400
        if services.watchlists is None: return jsonify({"error": "ignore lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.set_ignore_rule_enabled(signature_id, data["enabled"]))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.delete("/api/ignorelists/rules/<signature_id>")
    @login_required
    def api_delete_ignore_rule(signature_id):
        if services.watchlists is None: return jsonify({"error": "ignore lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.delete_ignore_rule(signature_id))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.post("/api/ignorelists/delete")
    @login_required
    def api_delete_ignorelist():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {"name"} or not isinstance(data["name"], str):
            return jsonify({"error": "name is required"}), 400
        if services.watchlists is None: return jsonify({"error": "ignore lists are unavailable"}), 503
        result = run_watchlist_mutation(lambda: services.watchlists.delete_ignore_list(data["name"]))
        return result if isinstance(result, tuple) else jsonify({"ok": True})

    @app.get("/api/errors")
    @login_required
    def api_errors(): return jsonify({"errors": services.errors()})

    @app.get("/settings")
    @login_required
    def settings_page():
        init_csrf()
        return render_template("settings.html", csrf=session["csrf_token"])

    @app.get("/updates")
    @login_required
    def updates_page():
        init_csrf()
        return render_template("updates.html", csrf=session["csrf_token"])

    @app.get("/api/settings")
    @login_required
    def api_settings():
        if services.config_file is None: return jsonify({"error": "settings unavailable"}), 503
        try:
            from .config import load_app_config
            config = load_app_config(services.config_file)
        except (OSError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify({
            "global_min_rssi": config.detection.global_min_rssi,
            "cooldown_seconds": config.detection.cooldown_seconds,
            "min_observations": config.detection.min_observations,
            "access_point_enabled": config.access_point.enabled,
            "wifi_scanning_enabled": config.wifi_scanning.enabled,
            "wifi_mode": "scan" if config.wifi_scanning.enabled else "admin_ap" if config.access_point.enabled else "idle",
            "wifi_scan_interval_seconds": config.wifi_scanning.interval_seconds,
            "ssid": config.access_point.ssid,
            "channel": config.access_point.channel,
            "hidden": config.access_point.hidden,
            "wifi_passphrase_configured": bool(config.access_point.passphrase),
            "scan_mode": config.bluetooth.scan_mode,
            "or_patterns": [{
                "start_position": item.start_position,
                "ad_data_type": item.ad_data_type,
                "pattern": item.pattern.hex(),
            } for item in config.bluetooth.or_patterns],
            "manifest_url": config.updates.manifest_url,
        })

    @app.post("/api/settings")
    @login_required
    @serialize_settings
    def api_update_settings():
        if services.config_file is None: return jsonify({"error": "settings unavailable"}), 503
        changes = request.get_json(silent=True)
        allowed = {"global_min_rssi", "cooldown_seconds", "min_observations", "manifest_url", "access_point_enabled", "wifi_scanning_enabled", "ssid", "passphrase", "channel", "or_patterns"}
        if not isinstance(changes, dict) or not changes or set(changes) - allowed:
            return jsonify({"error": "unsupported or empty settings change"}), 400
        try:
            current = yaml.safe_load(services.config_file.read_text(encoding="utf-8")) or {}
            if not isinstance(current, dict): raise ValueError("configuration root must be a mapping")
            merged = {**current,
                "bluetooth": {**current.get("bluetooth", {})},
                "detection": {**current.get("detection", {})},
                "access_point": {**current.get("access_point", {})},
                "wifi_scanning": {**current.get("wifi_scanning", {})},
                "updates": {**current.get("updates", {})}}
            ap_changes = {}
            mode_requested = "access_point_enabled" in changes or "wifi_scanning_enabled" in changes
            for key, value in changes.items():
                if key in {"global_min_rssi", "cooldown_seconds", "min_observations"}:
                    merged["detection"][key] = value
                elif key == "manifest_url":
                    merged["updates"]["manifest_url"] = value
                elif key == "or_patterns":
                    merged["bluetooth"]["or_patterns"] = value
                elif key == "access_point_enabled":
                    merged["access_point"]["enabled"] = value
                    if value is True and "wifi_scanning_enabled" not in changes:
                        merged["wifi_scanning"]["enabled"] = False
                elif key == "wifi_scanning_enabled":
                    merged["wifi_scanning"]["enabled"] = value
                    if value is True and "access_point_enabled" not in changes:
                        merged["access_point"]["enabled"] = False
                else:
                    merged["access_point"][key] = value
                    ap_changes[key] = value
            if merged["access_point"].get("enabled") is True and merged["wifi_scanning"].get("enabled") is True:
                raise ValueError("choose either Wi-Fi scanning or the admin hotspot")
            from .config import validate_config_data
            validate_config_data(merged, base_dir=services.config_file.resolve().parent)
            original = services.config_file.read_bytes()
            original_mode = services.config_file.stat().st_mode & 0o777
            content = yaml.safe_dump(merged, sort_keys=False, allow_unicode=True).encode("utf-8")
            services.config_file.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=".detector-", suffix=".yaml", dir=services.config_file.parent)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temp_name, original_mode)
                os.replace(temp_name, services.config_file)
            except Exception:
                try: os.unlink(temp_name)
                except OSError: pass
                raise
            try:
                if ap_changes and services.ap_update is not None:
                    services.ap_update(ap_changes)
                if any(key in changes for key in {"global_min_rssi", "cooldown_seconds", "min_observations", "or_patterns"}) and services.restart_scanner is not None:
                    services.restart_scanner()
                if "manifest_url" in changes and services.update_manager is not None:
                    services.update_manager.manifest_url = changes["manifest_url"]
                if mode_requested:
                    if services.set_wifi_mode is None:
                        raise RuntimeError("Wi-Fi mode switching is unavailable")
                    target_mode = ("scan" if merged["wifi_scanning"].get("enabled") else
                                   "admin_ap" if merged["access_point"].get("enabled") else "idle")
                    services.set_wifi_mode(target_mode)
            except Exception:
                restore_content = original
                if mode_requested:
                    # A failed transition leaves the radio idle; persist that
                    # fail-safe state so the boot reconciler cannot silently
                    # re-enable the previous AP or scanner mode.
                    original_data = yaml.safe_load(original) or {}
                    if original_data.get("access_point", {}).get("enabled") or original_data.get("wifi_scanning", {}).get("enabled"):
                        original_data.setdefault("access_point", {})["enabled"] = False
                        original_data.setdefault("wifi_scanning", {})["enabled"] = False
                        restore_content = yaml.safe_dump(original_data, sort_keys=False, allow_unicode=True).encode("utf-8")
                restore_fd, restore_name = tempfile.mkstemp(prefix=".detector-restore-", dir=services.config_file.parent)
                with os.fdopen(restore_fd, "wb") as output:
                    output.write(restore_content)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(restore_name, original_mode)
                os.replace(restore_name, services.config_file)
                raise
            return jsonify({"ok": True, "restart_required": False})
        except (OSError, TypeError, ValueError, RuntimeError, yaml.YAMLError, subprocess.SubprocessError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/updates/status")
    @login_required
    def api_update_status():
        if services.update_manager is None: return jsonify({"error": "updates are disabled"}), 503
        return jsonify(services.update_manager.status())

    @app.post("/api/updates/check")
    @login_required
    def api_update_check():
        if services.update_manager is None: return jsonify({"error": "updates are disabled"}), 503
        try: return jsonify(services.update_manager.check())
        except (OSError, ValueError, RuntimeError) as exc: return jsonify({"error": str(exc)}), 400

    @app.post("/api/updates/upload")
    @login_required
    def api_update_upload():
        if services.update_manager is None: return jsonify({"error": "updates are disabled"}), 503
        bundle = request.files.get("bundle")
        if bundle is None: return jsonify({"error": "choose a signed release bundle"}), 400
        try: return jsonify(services.update_manager.upload(bundle.stream)), 201
        except (OSError, ValueError, RuntimeError) as exc: return jsonify({"error": str(exc)}), 400

    @app.post("/api/updates/stage")
    @login_required
    def api_update_stage():
        if services.update_manager is None: return jsonify({"error": "updates are disabled"}), 503
        try: return jsonify(services.update_manager.stage_download()), 201
        except (OSError, ValueError, RuntimeError) as exc: return jsonify({"error": str(exc)}), 400

    @app.post("/api/updates/apply")
    @login_required
    def api_update_apply():
        if services.update_manager is None: return jsonify({"error": "updates are disabled"}), 503
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("confirm") is not True or not isinstance(data.get("id"), str):
            return jsonify({"error": "explicit confirmation and a staged update id are required"}), 400
        try: return jsonify(services.update_manager.apply(data["id"]))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc: return jsonify({"error": str(exc)}), 400

    return app


def _ethernet_ipv4_address(interface: str = "eth0", runner=subprocess.run) -> str:
    result = runner(["ip", "-4", "-o", "addr", "show", "dev", interface],
        capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        fields = line.split()
        if "inet" in fields:
            return fields[fields.index("inet") + 1].split("/", 1)[0]
    raise RuntimeError(f"No IPv4 address is configured on {interface}")


def _serve_dashboard(app: Flask, port: int, hosts: list[str], cert_file: Path, key_file: Path) -> None:
    from gunicorn.app.base import BaseApplication

    class DashboardApplication(BaseApplication):
        def __init__(self):
            self.options = {
                "bind": [f"{host}:{port}" for host in hosts],
                "workers": 1,
                "worker_class": "gthread",
                "threads": 4,
                "certfile": str(cert_file),
                "keyfile": str(key_file),
                "loglevel": "info",
                "errorlog": "-",
                "accesslog": None,
            }
            super().__init__()

        def load_config(self):
            for key, value in self.options.items():
                if key in self.cfg.settings and value is not None:
                    self.cfg.set(key, value)

        def load(self):
            return app

    DashboardApplication().run()


def main():
    from .config import load_app_config
    from .store import EventStore
    from .access_point import AccessPointClient
    from .runtime_cache import RuntimeDeviceCache, RuntimeScanCache, RuntimeWifiCache
    from .web_updates import WebUpdateManager
    from .watchlists import WatchListStore
    from .company_ids import CompanyIdentifierRegistry
    from .wifi_mode import WifiModeController
    import argparse
    import subprocess
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/bt-signature-detector/detector.yaml"))
    args = parser.parse_args()
    config = load_app_config(args.config)
    signatures_path = config.detection.signature_file
    if not signatures_path.is_absolute():
        signatures_path = args.config.resolve().parent / signatures_path
    store = EventStore(config.storage.path, retention_days=config.storage.retention_days, max_events=config.storage.max_events)
    runtime_dir = Path("/run/bt-signature-detector")
    def scanner_status():
        result = subprocess.run(["systemctl", "is-active", "bt-signature-detector.service"], capture_output=True, text=True)
        current = load_app_config(args.config)
        try:
            runtime_status = json.loads((runtime_dir / "scanner-status.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            runtime_status = {}
        configured_mode = current.bluetooth.scan_mode
        wifi_mode = "scan" if current.wifi_scanning.enabled else "admin_ap" if current.access_point.enabled else "idle"
        wifi_service_active = subprocess.run(["systemctl", "is-active", "bt-signature-detector-wifi.service"], capture_output=True, text=True).stdout.strip() == "active"
        return {"scanner": result.stdout.strip() or "unknown",
                "scanner_state": runtime_status.get("state", "unknown"),
                "scanner_error": runtime_status.get("error"),
                "scan_mode": configured_mode,
                "configured_scan_mode": configured_mode,
                "effective_scan_mode": configured_mode,
                "access_point": AccessPointClient().read().active,
                "wifi_mode": wifi_mode,
                "wifi_scanning_enabled": current.wifi_scanning.enabled,
                "wifi_scan_active": wifi_service_active}

    def current_wifi_status():
        current = load_app_config(args.config)
        scan_active = subprocess.run(["systemctl", "is-active", "bt-signature-detector-wifi.service"], capture_output=True, text=True).stdout.strip() == "active"
        ap_active = AccessPointClient().read().active
        mode = "scan" if scan_active else "admin_ap" if ap_active else "idle"
        return {"mode": mode, "configured_mode": "scan" if current.wifi_scanning.enabled else "admin_ap" if current.access_point.enabled else "idle",
                "scan_active": scan_active, "admin_ap_active": ap_active,
                "wifi_scanning_enabled": current.wifi_scanning.enabled,
                "access_point_enabled": current.access_point.enabled,
                "scan_interval_seconds": current.wifi_scanning.interval_seconds}
    def update_ap(changes):
        import json
        changes["country"] = config.access_point.country
        subprocess.run(["sudo", "-n", "/opt/bt-signature-detector/active/bin/python", "-m",
            "bt_signature_detector.ap_helper", "update", "--changes-stdin"],
            input=json.dumps(changes), text=True, check=True, capture_output=True, timeout=30)
    def restart_scanner():
        subprocess.run(["sudo", "-n", "/usr/local/sbin/bt-detector-restart-scanner"],
            check=True, capture_output=True, timeout=30)
    initial_wifi_mode = "scan" if config.wifi_scanning.enabled else "admin_ap" if config.access_point.enabled else "idle"
    def wifi_mode_action(action):
        subprocess.run(["sudo", "-n", "/usr/local/sbin/bt-detector-wifi-mode", action],
            check=True, capture_output=True, text=True, timeout=60)
    wifi_mode_controller = WifiModeController(action=wifi_mode_action, initial_mode=initial_wifi_mode)
    services = WebServices(config.web.password_hash_file, config.web.session_key_file,
        status=scanner_status, events=store.recent,
        scans=lambda: RuntimeScanCache.read(Path("/run/bt-signature-detector/scans.json"), config.web.max_live_scans),
        wifi_status=current_wifi_status,
        wifi_observations=lambda: RuntimeWifiCache.read(runtime_dir / "wifi-observations.json", config.web.max_live_scans),
        devices=lambda: RuntimeDeviceCache.read(runtime_dir / "devices.json", config.web.max_live_scans,
            config.detection.absence_seconds),
        max_live_scans=config.web.max_live_scans,
        config_file=args.config, ap_update=update_ap,
        set_wifi_mode=lambda mode: wifi_mode_controller.set_mode(mode),
        update_manager=WebUpdateManager(manifest_url=config.updates.manifest_url,
            public_key_file=config.updates.public_key_file,
            staging_dir=Path("/var/lib/bt-signature-detector/web/updates"),
            max_bytes=config.updates.max_bundle_bytes, timeout=config.updates.timeout_seconds)
            if config.updates.enabled else None,
        max_update_bytes=config.updates.max_bundle_bytes, restart_scanner=restart_scanner,
        watchlists=WatchListStore(signatures_path), company_identifiers=CompanyIdentifierRegistry.from_package())
    dashboard_hosts = [_ethernet_ipv4_address(), config.access_point.interface_address.split("/", 1)[0]]
    cert_file = config.web.session_key_file.parent / "dashboard.crt"
    key_file = config.web.session_key_file.parent / "dashboard.key"
    _ensure_dashboard_certificate(cert_file, key_file, dashboard_hosts)
    # The AP address is configured even while the optional hotspot is down.
    # Binding each address makes Gunicorn fail at startup when that address is
    # not currently assigned, so listen on all local interfaces instead.
    _serve_dashboard(create_app(services), config.web.port, ["0.0.0.0"], cert_file, key_file)


if __name__ == "__main__": main()
