"""Catalog loading and the installed-locale registry.

The registry is deliberately tiny: T1 ships the two core catalogs and later
tasks add provider packs. A tag resolves to an installed tag by exact match or
by dropping subtags (``es-MX`` -> ``es``), never by guessing a translation.
"""

from __future__ import annotations

import json
from functools import cache, lru_cache
from pathlib import Path
from typing import Final

from babel import Locale

CATALOG_DIR: Final[Path] = Path(__file__).with_name("catalogs")

#: Locales the core product ships; the installation default must be one of them.
CORE_LOCALES: Final[tuple[str, ...]] = ("es", "en")

DEFAULT_LOCALE: Final[str] = "es"


def installed_locales() -> tuple[str, ...]:
    return CORE_LOCALES


def resolve_installed_locale(tag: str | None) -> str | None:
    """Return the installed tag for ``tag`` or ``None`` when it is unknown.

    A reviewed language pack makes its locale installed for every caller, so the
    registry snapshot is consulted first; the core catalogs remain the answer
    when no registry is configured (CLI, migrations, unit imports).
    """
    if not tag:
        return None
    normalized = str(tag).strip().replace("_", "-").lower()
    if not normalized:
        return None
    from itsm.i18n import registry

    snapshot = registry.current_snapshot()
    if snapshot is not None:
        resolved = snapshot.resolve(normalized)
        if resolved is not None:
            return resolved
    return _core_installed_locale(normalized)


def _core_installed_locale(tag: str) -> str | None:
    """Resolve against the core catalogs only; never consults the registry."""
    parts = tag.split("-")
    while parts:
        candidate = "-".join(parts)
        if candidate in CORE_LOCALES:
            return candidate
        parts.pop()
    return None


@cache
def load_catalog(locale: str) -> dict[str, str] | None:
    """Load one installed catalog, or ``None`` when no file backs that locale."""
    installed = _core_installed_locale(str(locale).strip().replace("_", "-").lower())
    if installed is None:
        return None
    path = CATALOG_DIR / f"{installed}.json"
    if not path.is_file():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {str(key): str(value) for key, value in raw.items()}


@lru_cache(maxsize=1)
def catalog_keys() -> frozenset[str]:
    """Every key any installed catalog defines; the bundle serves this set."""
    keys: set[str] = set()
    for locale in CORE_LOCALES:
        keys.update((load_catalog(locale) or {}).keys())
    return frozenset(keys)


def locale_descriptor(tag: str) -> dict[str, str]:
    """Public descriptor: stable English name plus the locale's own name."""
    locale = Locale.parse(tag)
    name = locale.get_display_name("en") or tag
    native = locale.get_display_name(tag) or tag
    return {
        "tag": tag,
        "name": _sentence_case(name),
        "nativeName": _sentence_case(native),
        "provider": "core",
    }


def _sentence_case(value: str) -> str:
    return value[:1].upper() + value[1:]
