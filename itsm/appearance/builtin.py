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
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img"'
    b' aria-labelledby="hadar-logo-title">\n'
    b'  <title id="hadar-logo-title">Hadar IT</title>\n'
    b'  <rect x="4.14" y="4" width="9.39" height="40" fill="#0d766e"/>\n'
    b'  <rect x="34.47" y="4" width="9.39" height="40" fill="#0d766e"/>\n'
    b'  <path d="M39.63 24C34.92 22.7 28.32 22.08 26.66 21.07C25.74 19.23 25.17 11.93 24'
    b" 6.73C22.83 11.93 22.26 19.23 21.34 21.07C19.68 22.08 13.08 22.7 8.37 24C13.08 25.3"
    b" 19.68 25.92 21.34 26.93C22.26 28.77 22.83 36.07 24 41.27C25.17 36.07 25.74 28.77"
    b' 26.66 26.93C28.32 25.92 34.92 25.3 39.63 24Z" fill="#7bd3ca"/>\n'
    b"</svg>\n"
)

_FAVICON_SVG: Final[bytes] = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img"'
    b' aria-labelledby="hadar-favicon-title">\n'
    b'  <title id="hadar-favicon-title">Hadar IT</title>\n'
    b'  <rect width="64" height="64" rx="14" fill="#0c2333"/>\n'
    b'  <rect x="12.14" y="12" width="9.39" height="40" fill="#14958a"/>\n'
    b'  <rect x="42.47" y="12" width="9.39" height="40" fill="#14958a"/>\n'
    b'  <path d="M47.63 32C41.69 29.93 36.69 28.2 36.06 27.51C35.44 26.82 33.88 21.29 32'
    b" 14.73C30.12 21.29 28.56 26.82 27.94 27.51C27.31 28.2 22.31 29.93 16.37 32C22.31"
    b" 34.07 27.31 35.8 27.94 36.49C28.56 37.18 30.12 42.71 32 49.27C33.88 42.71 35.44"
    b' 37.18 36.06 36.49C36.69 35.8 41.69 34.07 47.63 32Z" fill="#b5ece5"/>\n'
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
