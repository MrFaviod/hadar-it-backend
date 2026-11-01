"""Catalog-backed report labels: one visible text per document locale.

``schemas.FIELD_LABELS`` and the column tables remain the compatibility map of
which keys have a translation; the rendered text always comes from the catalog,
so English documents never inherit Spanish labels. A key without a translation
falls back to its own name, which keeps unknown custom fields visible.
"""

from __future__ import annotations

import re

from itsm.i18n.documents import DocumentLocale, default_document_locale
from itsm.reports.schemas import FIELD_LABELS, LABEL_FIELD_LABELS

FAMILY_KEYS: dict[str, str] = {
    "inventory": "api.reports.family.inventory",
    "history": "api.reports.family.history",
    "warranty": "api.reports.family.warranty",
}
UNKNOWN_FAMILY_KEY = "api.reports.family.unknown"
SUMMARY_GROUP_KEYS: dict[str, str] = {
    "byStatus": "api.reports.group.by_status",
    "byCategory": "api.reports.group.by_category",
    "bySite": "api.reports.group.by_site",
    "byAction": "api.reports.group.by_action",
    "byActor": "api.reports.group.by_actor",
    "byCoverage": "api.reports.group.by_coverage",
    "byType": "api.reports.group.by_type",
    "groups": "api.reports.group.groups",
}
COVERAGE_KEYS: dict[str, str] = {
    "active": "api.reports.coverage.active",
    "expiring": "api.reports.coverage.expiring",
    "expired": "api.reports.coverage.expired",
    "missing": "api.reports.coverage.missing",
    "unknown": "api.reports.coverage.missing",
}
MISSING_GROUP_KEY = "api.reports.empty_group"
ASSET_NAME_KEY = "api.reports.asset_name"
_CAMEL_CASE = re.compile(r"([A-Z])")


def _resolve(document: DocumentLocale | None) -> DocumentLocale:
    return document if document is not None else default_document_locale()


def field_label(key: str, document: DocumentLocale | None = None) -> str:
    """Visible label for one report field; unknown keys stay as they are."""
    if key not in FIELD_LABELS:
        return key
    return _resolve(document).t(f"api.reports.field.{key}")


def label_field_label(key: str, document: DocumentLocale | None = None) -> str:
    """Visible label of a field printed on a physical label sheet."""
    if key not in LABEL_FIELD_LABELS:
        return field_label(key, document)
    return _resolve(document).t(f"api.reports.label_field.{key}")


def column_label(family: str, key: str, document: DocumentLocale | None = None) -> str:
    """Visible header of one history or warranty column."""
    if family not in {"history", "warranty"}:
        return field_label(key, document)
    return _resolve(document).t(f"api.reports.column.{family}.{key}")


def family_label(family: str, document: DocumentLocale | None = None) -> str:
    resolved = _resolve(document)
    key = FAMILY_KEYS.get(family, UNKNOWN_FAMILY_KEY)
    return resolved.t(key)


def summary_group_label(key: str, document: DocumentLocale | None = None) -> str:
    """Heading of one summary chart named by its camel-case summary key."""
    resolved = _resolve(document)
    known = SUMMARY_GROUP_KEYS.get(key)
    if known is not None:
        return resolved.t(known)
    return _plain_heading(key)


def coverage_label(code: str, document: DocumentLocale | None = None) -> str:
    """Visible warranty coverage value used by the summary chart."""
    resolved = _resolve(document)
    known = COVERAGE_KEYS.get(code)
    return resolved.t(known) if known is not None else code


def missing_group_label(document: DocumentLocale | None = None) -> str:
    return _resolve(document).t(MISSING_GROUP_KEY)


def asset_name_label(document: DocumentLocale | None = None) -> str:
    return _resolve(document).t(ASSET_NAME_KEY)


def export_id_label(identity: str, document: DocumentLocale | None = None) -> str:
    """Header of the identity column prepended to an export."""
    resolved = _resolve(document)
    return resolved.t(
        "api.reports.export_id" if identity == "id" else "api.reports.export_asset_id"
    )


def _plain_heading(key: str) -> str:
    words = _CAMEL_CASE.sub(lambda match: " " + match.group(1), key).strip()
    return words[:1].upper() + words[1:] if words else key


__all__ = [
    "COVERAGE_KEYS",
    "FAMILY_KEYS",
    "MISSING_GROUP_KEY",
    "SUMMARY_GROUP_KEYS",
    "asset_name_label",
    "column_label",
    "coverage_label",
    "export_id_label",
    "family_label",
    "field_label",
    "label_field_label",
    "missing_group_label",
    "summary_group_label",
]
