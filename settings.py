"""Small JSON settings store: language, last used values and named profiles.

Stored per user (``%APPDATA%\\CertificateTool`` on Windows, ``~/.config/certificatetool`` elsewhere).
Override the folder with the CERTTOOL_CONFIG_DIR environment variable (used by the tests).
Never stores common names, SANs, passwords or keys.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Fields that are safe and useful to remember between runs / in profiles
PROFILE_FIELDS = ("o", "ou", "l", "st", "c", "alg", "size", "hash")


def config_dir() -> Path:
    override = os.environ.get("CERTTOOL_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "CertificateTool"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "certificatetool"


def _path() -> Path:
    return config_dir() / "settings.json"


def load() -> dict:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(data: dict) -> None:
    try:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass  # settings are a convenience; never fail the app because of them


def _clean(values: dict) -> dict:
    return {k: str(v) for k, v in values.items() if k in PROFILE_FIELDS}


def get_language() -> str:
    lang = load().get("language", "auto")
    return lang if lang in ("auto", "en", "da") else "auto"


def set_language(lang: str) -> None:
    data = load()
    data["language"] = lang
    save(data)


def get_last_used() -> dict:
    last = load().get("last")
    return _clean(last) if isinstance(last, dict) else {}


def set_last_used(values: dict) -> None:
    data = load()
    data["last"] = _clean(values)
    save(data)


def get_profiles() -> dict[str, dict]:
    profiles = load().get("profiles")
    if not isinstance(profiles, dict):
        return {}
    return {str(n): _clean(v) for n, v in profiles.items() if isinstance(v, dict)}


def save_profile(name: str, values: dict) -> None:
    data = load()
    profiles = data.get("profiles") if isinstance(data.get("profiles"), dict) else {}
    profiles[name] = _clean(values)
    data["profiles"] = profiles
    save(data)


def delete_profile(name: str) -> None:
    data = load()
    profiles = data.get("profiles")
    if isinstance(profiles, dict) and name in profiles:
        del profiles[name]
        save(data)
