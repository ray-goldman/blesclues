from __future__ import annotations

from dataclasses import dataclass, asdict
import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from functools import wraps
from typing import Callable
import tempfile
import subprocess
import yaml

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for


@dataclass(slots=True)
class WebServices:
    password_hash_file: Path
    session_key_file: Path
    status: Callable[[], dict] = lambda: {}
    events: Callable[[int], list] = lambda limit: []
    scans: Callable[[], list] = lambda: []
    errors: Callable[[], list] = lambda: []
    max_live_scans: int = 100
    config_file: Path | None = None
    ap_update: Callable[[dict], None] | None = None
    update_manager: object | None = None
    max_update_bytes: int = 20_000_000
    restart_scanner: Callable[[], None] | None = None


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
    app = Flask(__name__, template_folder="web_templates", static_folder="web_static")
    services.password_hash_file.parent.mkdir(parents=True, exist_ok=True)
    services.session_key_file.parent.mkdir(parents=True, exist_ok=True)
    if not services.session_key_file.exists():
        services.session_key_file.write_bytes(secrets.token_bytes(32))
        try: os.chmod(services.session_key_file, 0o600)
        except OSError: pass
    app.secret_key = services.session_key_file.read_bytes()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=False)
    app.config["MAX_CONTENT_LENGTH"] = services.max_update_bytes + 65_536
    app.extensions["web_services"] = services

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

    @app.get("/")
    def index():
        if not services.password_hash_file.exists(): return redirect(url_for("setup"))
        if not session.get("authenticated"): return redirect(url_for("login"))
        init_csrf()
        return render_template("index.html", csrf=session["csrf_token"])

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if services.password_hash_file.exists(): return redirect(url_for("login"))
        if request.method == "GET": return render_template("login.html", setup=True)
        password = request.form.get("password", "")
        if len(password) < 12: return "Password must be at least 12 characters", 400
        services.password_hash_file.write_text(_password_hash(password), encoding="ascii")
        try: os.chmod(services.password_hash_file, 0o600)
        except OSError: pass
        session.clear()
        session["authenticated"] = True
        init_csrf()
        return "UI password created", 200

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET": return render_template("login.html", setup=False)
        try: stored = services.password_hash_file.read_text(encoding="ascii")
        except OSError: return redirect(url_for("setup"))
        if not _verify_password(request.form.get("password", ""), stored): return "Invalid password", 401
        session.clear()
        session["authenticated"] = True
        init_csrf()
        return "Logged in", 200

    @app.before_request
    def csrf_guard():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint not in {"setup", "login"}:
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
        services.password_hash_file.write_text(_password_hash(new), encoding="ascii")
        return "Password changed", 200

    @app.get("/api/status")
    @login_required
    def api_status(): return jsonify(services.status())

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
            if isinstance(item, dict) and "identifier" in item: item["identifier"] = "redacted"
        return jsonify({"scans": scans})

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
            "ssid": config.access_point.ssid,
            "channel": config.access_point.channel,
            "country": config.access_point.country,
            "scan_mode": config.bluetooth.scan_mode,
            "manifest_url": config.updates.manifest_url,
            "wifi_passphrase_configured": bool(config.access_point.passphrase),
        })

    @app.post("/api/settings")
    @login_required
    def api_update_settings():
        if services.config_file is None: return jsonify({"error": "settings unavailable"}), 503
        changes = request.get_json(silent=True)
        allowed = {"global_min_rssi", "cooldown_seconds", "min_observations", "ssid", "passphrase", "channel", "country", "manifest_url"}
        if not isinstance(changes, dict) or not changes or set(changes) - allowed:
            return jsonify({"error": "unsupported or empty settings change"}), 400
        try:
            current = yaml.safe_load(services.config_file.read_text(encoding="utf-8")) or {}
            if not isinstance(current, dict): raise ValueError("configuration root must be a mapping")
            merged = {**current,
                "detection": {**current.get("detection", {})},
                "access_point": {**current.get("access_point", {})},
                "updates": {**current.get("updates", {})}}
            ap_changes = {}
            for key, value in changes.items():
                if key in {"global_min_rssi", "cooldown_seconds", "min_observations"}:
                    merged["detection"][key] = value
                elif key == "manifest_url":
                    merged["updates"]["manifest_url"] = value
                else:
                    merged["access_point"][key] = value
                    if key in {"ssid", "passphrase", "channel", "country"}: ap_changes[key] = value
            from .config import validate_config_data
            validate_config_data(merged)
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
                if any(key in changes for key in {"global_min_rssi", "cooldown_seconds", "min_observations"}) and services.restart_scanner is not None:
                    services.restart_scanner()
                if "manifest_url" in changes and services.update_manager is not None:
                    services.update_manager.manifest_url = changes["manifest_url"]
            except Exception:
                restore_fd, restore_name = tempfile.mkstemp(prefix=".detector-restore-", dir=services.config_file.parent)
                with os.fdopen(restore_fd, "wb") as output:
                    output.write(original)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(restore_name, original_mode)
                os.replace(restore_name, services.config_file)
                raise
            return jsonify({"ok": True, "restart_required": False})
        except (OSError, TypeError, ValueError, yaml.YAMLError, subprocess.SubprocessError) as exc:
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


def main():
    from waitress import serve
    from .config import load_app_config
    from .store import EventStore
    from .access_point import AccessPointClient
    from .runtime_cache import RuntimeScanCache
    from .web_updates import WebUpdateManager
    import argparse
    import subprocess
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/bt-signature-detector/detector.yaml"))
    args = parser.parse_args()
    config = load_app_config(args.config)
    store = EventStore(config.storage.path, retention_days=config.storage.retention_days, max_events=config.storage.max_events)
    def scanner_status():
        result = subprocess.run(["systemctl", "is-active", "bt-signature-detector.service"], capture_output=True, text=True)
        return {"scanner": result.stdout.strip() or "unknown", "scan_mode": config.bluetooth.scan_mode,
                "access_point": AccessPointClient().read().active}
    def update_ap(changes):
        import json
        subprocess.run(["sudo", "-n", "/opt/bt-signature-detector/active/bin/python", "-m",
            "bt_signature_detector.ap_helper", "update", "--changes-stdin"],
            input=json.dumps(changes), text=True, check=True, capture_output=True, timeout=15)
    def restart_scanner():
        subprocess.run(["sudo", "-n", "/usr/local/sbin/bt-detector-restart-scanner"],
            check=True, capture_output=True, timeout=30)
    services = WebServices(config.web.password_hash_file, config.web.session_key_file,
        status=scanner_status, events=store.recent,
        scans=lambda: RuntimeScanCache.read(Path("/run/bt-signature-detector/scans.json"), config.web.max_live_scans),
        max_live_scans=config.web.max_live_scans,
        config_file=args.config, ap_update=update_ap,
        update_manager=WebUpdateManager(manifest_url=config.updates.manifest_url,
            public_key_file=config.updates.public_key_file,
            staging_dir=Path("/var/lib/bt-signature-detector/web/updates"),
            max_bytes=config.updates.max_bundle_bytes, timeout=config.updates.timeout_seconds)
            if config.updates.enabled else None,
        max_update_bytes=config.updates.max_bundle_bytes, restart_scanner=restart_scanner)
    host = config.access_point.interface_address.split("/")[0]
    serve(create_app(services), host=host, port=config.web.port)


if __name__ == "__main__": main()
