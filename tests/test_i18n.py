import ast
import string
from pathlib import Path

import i18n
from translations_da import DA

ROOT = Path(__file__).resolve().parent.parent


def source_strings() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted(ROOT.glob("*.py")):
        if path.name in ("translations_da.py", "i18n.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_"
                and node.args
            ):
                arg = node.args[0]
                assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), (
                    f"{path.name}:{node.lineno}: _() needs a string literal"
                )
                found[arg.value] = path.name
    return found


def placeholders(text: str) -> set[str]:
    return {name for _lit, name, _spec, _conv in string.Formatter().parse(text) if name}


def test_every_string_has_a_danish_translation():
    missing = [s for s in source_strings() if s not in DA]
    assert not missing, "Missing Danish translations:\n" + "\n".join(missing)


def test_no_stale_translations():
    stale = [s for s in DA if s not in source_strings()]
    assert not stale, "Translations for strings no longer in the code:\n" + "\n".join(stale)


def test_placeholders_match():
    bad = [s for s, t in DA.items() if placeholders(s) != placeholders(t)]
    assert not bad, "Placeholder mismatch:\n" + "\n".join(bad)


def test_language_switching():
    try:
        assert i18n.set_language("da") == "da"
        assert i18n._("Error") == "Fejl"
        assert i18n._("not translated") == "not translated"
        assert i18n.set_language("en") == "en"
        assert i18n._("Error") == "Error"
    finally:
        i18n.set_language("en")
