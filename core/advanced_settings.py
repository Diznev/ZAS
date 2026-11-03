"""Advanced form validation and additive, atomic local config updates."""

import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit


ADVANCED_DEFAULTS = {
    "fingerprint": False, "waf_detect": False, "cookie_steal": False,
    "cred_harvest": False, "pivot": False, "exfiltration": False,
    "shodan_key": "", "shodan_query": "", "tg_token": "", "tg_chat": "",
    "slack_webhook": "", "discord_webhook": "",
}


def normalize_advanced_settings(values):
    if not isinstance(values, dict):
        raise ValueError("Advanced settings must be a JSON object")
    normalized = {}
    for key, default in ADVANCED_DEFAULTS.items():
        value = values.get(key, default)
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f"Invalid Advanced toggle: {key}")
        else:
            if not isinstance(value, str) or len(value) > 8192:
                raise ValueError(f"Invalid Advanced text field: {key}")
            value = value.strip()
        normalized[key] = value
    if bool(normalized["tg_token"]) != bool(normalized["tg_chat"]):
        raise ValueError("Enter both Telegram Token and Chat, or clear both fields")
    for key in ("slack_webhook", "discord_webhook"):
        value = normalized[key]
        if not value:
            continue
        try:
            parsed = urlsplit(value)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or any(char.isspace() or ord(char) < 32 for char in value)):
                raise ValueError()
            parsed.port
        except ValueError as exc:
            raise ValueError(f"Field {key}: enter a valid HTTP(S) URL without a username or password") from exc
    return normalized


def update_local_config(path, updates):
    """Merge fields without erasing unrelated settings or corrupting old JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("Another process is saving settings. Try again later.") from exc
    temporary = None
    try:
        os.close(descriptor)
        try:
            with open(path, "rb") as stream:
                raw = stream.read(4 * 1024 * 1024 + 1)
        except FileNotFoundError:
            config = {}
        else:
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("Configuration file is too large; the original file was not changed")
            try:
                config = json.loads(raw.decode("utf-8-sig"))
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError("Configuration is invalid; the original file was not changed") from exc
            if not isinstance(config, dict):
                raise ValueError("Configuration must be a JSON object; the original file was not changed")
        merged = dict(config)
        merged.update(updates)
        if "advanced" in updates:
            previous = config.get("advanced", {})
            if not isinstance(previous, dict):
                raise ValueError("The existing Advanced section is invalid; the file was not changed")
            merged["advanced"] = dict(previous, **normalize_advanced_settings(updates["advanced"]))
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".zas-config-",
                                         suffix=".tmp", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(merged, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)
