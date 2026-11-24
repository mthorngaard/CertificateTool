"""Tiny gettext-like translation layer. English source strings are the keys.

Usage: ``from i18n import _`` and wrap every user-visible literal in ``_("...")``.
For text with dynamic parts use ``_("Saved: {name}").format(name=...)``.
The test suite verifies that every literal passed to ``_()`` has a Danish translation.
"""

from __future__ import annotations

import locale
import sys

LANGUAGES = {"en": "English", "da": "Dansk"}

_lang = "en"
_table: dict[str, str] = {}


def detect_system_language() -> str:
    if sys.platform == "win32":
        try:
            import ctypes

            lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            return "da" if (lang_id & 0x3FF) == 0x06 else "en"
        except Exception:
            pass
    try:
        code = (locale.getlocale()[0] or "").lower()
    except Exception:
        code = ""
    return "da" if code.startswith("da") else "en"


def set_language(code: str) -> str:
    """Activate a language ('auto', 'en' or 'da'). Returns the language actually in use."""
    global _lang, _table
    if code == "auto":
        code = detect_system_language()
    if code == "da":
        from translations_da import DA

        _lang, _table = "da", DA
    else:
        _lang, _table = "en", {}
    return _lang


def current_language() -> str:
    return _lang


def _(text: str) -> str:
    return _table.get(text, text)
