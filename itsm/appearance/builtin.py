"""Immutable original appearance presets and their neutral built-in artwork.

The generic preset is always restorable and can never be edited or deleted.
Its logo/favicon are neutral Hadar IT artwork owned by the backend so an
exported package is self-contained instead of pointing at frontend paths.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Final

GENERIC_ID: Final[str] = "generic"
BUILTIN_IDS: Final[tuple[str, ...]] = ("generic", "blue", "forest")

_LOGO_SVG: Final[bytes] = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" '
    b'aria-labelledby="title">\n'
    b'  <title id="title">Hadar IT</title>\n'
    b'  <path d="M24 4 43 14.5 24 25 5 14.5 24 4Z" fill="#7bd3ca"/>\n'
    b'  <path d="m5 22 19 10.5L43 22v6L24 38.5 5 28v-6Z" fill="#2e9e97"/>\n'
    b'  <path d="m5 33 19 10.5L43 33v5.5L24 49 5 38.5V33Z" fill="#b8e5df"/>\n'
    b'  <path d="M24 4v21m0 0v21" stroke="#0b2331" stroke-width="1.2" opacity=".35"/>\n'
    b"</svg>\n"
)

_FAVICON_SVG: Final[bytes] = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" '
    b'aria-labelledby="title">\n'
    b'  <title id="title">Hadar IT</title>\n'
    b'  <rect width="64" height="64" rx="15" fill="#0c2333"/>\n'
    b'  <path d="M32 12 52 23 32 34 12 23l20-11Z" fill="#7bd3ca"/>\n'
    b'  <path d="m12 31 20 11 20-11v6L32 48 12 37v-6Z" fill="#2e9e97"/>\n'
    b'  <path d="m12 42 20 11 20-11v4L32 57 12 46v-4Z" fill="#b8e5df"/>\n'
    b"</svg>\n"
)

BUILTIN_ASSETS: Final[dict[str, tuple[str, bytes]]] = {
    "logo": ("image/svg+xml", _LOGO_SVG),
    "favicon": ("image/svg+xml", _FAVICON_SVG),
}

# The original engine resolved these relative paths; accept them from existing
# browsers while storing only the backend-owned built-in equivalent.
LEGACY_ASSET_PATHS: Final[dict[str, str]] = {
    "assets/svg/logo.svg": "logo",
    "assets/svg/favicon.svg": "favicon",
}


def builtin_asset_url(api_prefix: str, key: str) -> str:
    return f"{api_prefix}/appearance/assets/{key}"


def builtin_presets(api_prefix: str) -> dict[str, dict[str, Any]]:
    """Return fresh copies of the immutable presets, keyed by stable id."""
    logo = builtin_asset_url(api_prefix, "logo")
    favicon = builtin_asset_url(api_prefix, "favicon")
    branding = {
        "appName": "Hadar IT",
        "organizationName": "Operaciones TI",
        "logo": logo,
        "logoDark": "",
        "logoCompact": "",
        "favicon": favicon,
    }
    generic = {
        "id": "generic",
        "name": "Hadar IT",
        "version": 1,
        "description": "Identidad original · Siempre disponible",
        "branding": branding,
        "colors": {
            "light": {"primary": "#0b2331", "secondary": "#0d766e", "accent": "#a65c13"},
            "dark": {"primary": "#071923", "secondary": "#62d4c7", "accent": "#f6bf67"},
        },
        "preferences": {"defaultMode": "system", "compact": False},
    }
    blue = deepcopy(generic)
    blue.update(
        {
            "id": "blue",
            "name": "Azul mineral",
            "description": "Azul profundo y superficies neutras",
            "colors": {
                "light": {"primary": "#10283f", "secondary": "#2357a1", "accent": "#925113"},
                "dark": {"primary": "#0a1d30", "secondary": "#95bbf6", "accent": "#f4c778"},
            },
        }
    )
    forest = deepcopy(generic)
    forest.update(
        {
            "id": "forest",
            "name": "Verde bosque",
            "description": "Verde sobrio y contraste natural",
            "colors": {
                "light": {"primary": "#17372c", "secondary": "#30684b", "accent": "#935026"},
                "dark": {"primary": "#10251d", "secondary": "#9dd6b5", "accent": "#efbb91"},
            },
        }
    )
    return {"generic": generic, "blue": blue, "forest": forest}
