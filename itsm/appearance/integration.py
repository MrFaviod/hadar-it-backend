"""Narrow, read-only seam from the active appearance into report branding.

The report renderer is unchanged: it still receives the same branding mapping
and optional raster logo bytes. A generic active identity keeps the legacy
report defaults; an applied installation preset supplies the organization
name, light-mode primary/accent colors and a raster logo when no report logo
is configured. Before the appearance migration exists the seam degrades to the
legacy defaults instead of breaking report reads.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session

from itsm.appearance.builtin import GENERIC_ID
from itsm.appearance.models import AppearanceResource, AppearanceState
from itsm.appearance.package import MAX_LOGO_BYTES, sha256_hex
from itsm.attachments.storage import BlobStorage, LocalBlobStorage
from itsm.config import Settings

_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
_RASTER = frozenset({"image/png", "image/jpeg", "image/webp"})


def active_document(session: Session) -> dict[str, Any] | None:
    try:
        state = session.get(AppearanceState, 1)
    except OperationalError, ProgrammingError:
        session.rollback()
        return None
    if state is None or not isinstance(state.active, dict):
        return None
    return state.active


def appearance_report_branding(session: Session) -> dict[str, str]:
    document = active_document(session)
    if document is None or document.get("id") == GENERIC_ID:
        return {}
    branding = document.get("branding") or {}
    colors = (document.get("colors") or {}).get("light") or {}
    result: dict[str, str] = {}
    organization = branding.get("organizationName")
    if isinstance(organization, str) and organization.strip():
        result["name"] = organization.strip()[:120]
    for key in ("primary", "accent"):
        value = colors.get(key)
        if isinstance(value, str) and _HEX.fullmatch(value):
            result[key] = value.lower()
    return result


def appearance_report_logo(
    session: Session, settings: Settings, storage: BlobStorage | None = None
) -> bytes | None:
    document = active_document(session)
    if document is None or document.get("id") == GENERIC_ID:
        return None
    reference = (document.get("branding") or {}).get("logo")
    if not isinstance(reference, str) or not reference:
        return None
    prefix = f"{settings.api_prefix.rstrip('/')}/appearance/resources/"
    if not reference.startswith(prefix):
        return None
    resource_id = reference[len(prefix) :]
    try:
        row = session.get(AppearanceResource, resource_id)
    except OperationalError, ProgrammingError:
        session.rollback()
        return None
    if row is None or row.content_type not in _RASTER:
        return None
    if not 1 <= row.size <= min(settings.attachment_max_bytes, MAX_LOGO_BYTES):
        return None
    try:
        backend = storage or LocalBlobStorage(settings.attachment_storage_path)
        data = backend.read(row.blob_key, row.size + 1)
    except OSError:
        return None
    if len(data) != row.size or sha256_hex(data) != row.sha256:
        return None
    return data
