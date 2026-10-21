"""Bounded public projections shared by both agent transports."""

from __future__ import annotations

from typing import Any

from itsm.identity.service import ValidationFailed
from itsm.inventory.service import AssetView

COMPACT_FIELDS = (
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "responsible",
    "status",
    "ip",
    "archived",
)
PUBLIC_FIELDS = frozenset(AssetView.__dataclass_fields__) | {
    "quickCode",
    "archivedAt",
    "archivedBy",
    "createdAt",
    "updatedAt",
}
PUBLIC_FIELDS -= {"quick_code", "archived_at", "archived_by", "created_at", "updated_at"}


def validate_fields(fields: list[str] | None) -> tuple[str, ...]:
    if fields is None:
        return COMPACT_FIELDS
    if not isinstance(fields, list) or not 1 <= len(fields) <= 24:
        raise ValidationFailed("fields must contain between 1 and 24 public field names")
    if any(not isinstance(name, str) or name not in PUBLIC_FIELDS for name in fields):
        raise ValidationFailed("unknown public inventory field")
    if len(set(fields)) != len(fields):
        raise ValidationFailed("fields must not contain duplicates")
    return tuple(fields)


def project(view: AssetView, fields: list[str] | None = None) -> dict[str, Any]:
    selected = validate_fields(fields)
    payload = view.as_payload()
    return {name: payload[name] for name in selected}
