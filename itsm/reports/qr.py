"""Stable asset QR destinations generated with the maintained Segno library.

The destination only depends on the configurable base URL and the asset's
permanent UUID.  Moving the asset, changing its quick code or recategorizing it
never changes the QR target.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import segno

MAX_BASE_URL_LENGTH = 400
MAX_QR_URL_LENGTH = 600
QUIET_ZONE_MODULES = 4
QR_SCALE = 4


def _base_url(base_url: str) -> str:
    if not isinstance(base_url, str):
        raise ValueError("base_url must be a string")
    raw = base_url
    if not raw or raw != raw.strip() or len(raw) > MAX_BASE_URL_LENGTH:
        raise ValueError(f"base_url must contain 1-{MAX_BASE_URL_LENGTH} characters")
    if any(character.isspace() for character in raw):
        raise ValueError("base_url must not contain whitespace")
    try:
        parts = urlsplit(raw)
        _ = parts.port
    except ValueError:
        raise ValueError("base_url must be a valid http(s) URL") from None
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("base_url must be http(s) without credentials, query or fragment")
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, "", ""))


def asset_report_url(base_url: str, asset_id: str) -> str:
    """Return ``<base>/#/reporte/<permanent-uuid>`` or raise ``ValueError``."""
    base = _base_url(base_url)
    if not isinstance(asset_id, str):
        raise ValueError("asset_id must be the permanent asset UUID")
    try:
        permanent = str(UUID(asset_id.strip()))
    except AttributeError, ValueError:
        raise ValueError("asset_id must be the permanent asset UUID") from None
    return f"{base}/#/reporte/{permanent}"


def qr_svg(url: str) -> str:
    """Render ``url`` as an inline SVG QR with a four-module quiet zone."""
    if not isinstance(url, str):
        raise ValueError("QR content must be a string")
    raw = url.strip()
    if not raw or len(raw) > MAX_QR_URL_LENGTH:
        raise ValueError(f"QR content must contain 1-{MAX_QR_URL_LENGTH} characters")
    if any(character.isspace() or ord(character) < 32 for character in raw):
        raise ValueError("QR content must not contain whitespace or control characters")
    if any(character in raw for character in '<>"'):
        raise ValueError("QR content must not contain markup characters")
    try:
        parts = urlsplit(raw)
        _ = parts.port
    except ValueError:
        raise ValueError("QR content must be a valid http(s) URL") from None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("QR content must be a valid http(s) URL")
    qr = segno.make(raw, error="m")
    return qr.svg_inline(
        scale=QR_SCALE,
        border=QUIET_ZONE_MODULES,
        dark="#000000",
        light="#ffffff",
    )
