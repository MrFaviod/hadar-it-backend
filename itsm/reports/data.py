"""Canonical report data: selection, projections, families and file exports.

This module owns what a report *contains*. Composition and rendering live in
the renderer package; this module never builds HTML. Every family returns the
same normalized table shape (``rows``/``columns``/``summary``) that preview,
PDF and spreadsheet outputs share, so a download cannot drift from a preview.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.i18n.documents import DocumentLocale, default_document_locale
from itsm.identity.clock import as_utc
from itsm.identity.service import NotFound, ValidationFailed
from itsm.inventory.models import Asset
from itsm.inventory.service import AssetView, HistoryView, InventoryService
from itsm.reports.labels import (
    column_label,
    export_id_label,
    field_label,
    missing_group_label,
)
from itsm.reports.schemas import (
    ASSET_FIELDS,
    PUBLIC_ASSET_FIELDS,
    WARRANTY_FILTERS,
)

PUBLIC_FIELDS: tuple[str, ...] = PUBLIC_ASSET_FIELDS
DEFAULT_FIELDS: tuple[str, ...] = (
    "id",
    "quickCode",
    "name",
    "category",
    "site",
    "location",
    "status",
    "responsible",
)
WARRANTY_COVERAGE_ALIASES: dict[str, str] = {
    "current": "active",
    "unknown": "missing",
}
WARRANTY_FILTER_TARGETS: dict[str, str] = {
    "active": "active",
    "expiring": "expiring",
    "expired": "expired",
    "missing": "missing",
}
TECHNICAL_ENTITY_TYPES: frozenset[str] = frozenset({"intervention", "incident"})
GROUP_FIELDS: tuple[str, ...] = (
    "none",
    "category",
    "site",
    "responsible",
    "location",
    "status",
)
MISSING_GROUP_LABEL = "Sin datos"
HISTORY_COLUMNS: tuple[dict[str, str], ...] = (
    {"key": "quickCode", "label": "Activo"},
    {"key": "action", "label": "Acción"},
    {"key": "actor", "label": "Actor"},
    {"key": "effectiveAt", "label": "Fecha"},
    {"key": "entityType", "label": "Origen"},
    {"key": "changes", "label": "Cambios"},
    {"key": "notes", "label": "Notas"},
)
HISTORY_FIELDS: tuple[str, ...] = (
    "assetId",
    "quickCode",
    "name",
    "action",
    "actor",
    "effectiveAt",
    "entityType",
    "entityId",
    "statusOld",
    "statusNew",
    "changes",
    "notes",
    "source",
)
DEFAULT_HISTORY_FIELDS: tuple[str, ...] = tuple(column["key"] for column in HISTORY_COLUMNS)
WARRANTY_COLUMNS: tuple[dict[str, str], ...] = (
    {"key": "quickCode", "label": "Activo"},
    {"key": "name", "label": "Nombre"},
    {"key": "category", "label": "Categoría"},
    {"key": "site", "label": "Sede"},
    {"key": "supplier", "label": "Proveedor"},
    {"key": "purchaseDate", "label": "Compra"},
    {"key": "expiresOn", "label": "Vencimiento"},
    {"key": "coverage", "label": "Cobertura"},
    {"key": "receiptId", "label": "Comprobante"},
    {"key": "notes", "label": "Notas"},
)
WARRANTY_FIELDS: tuple[str, ...] = (
    "assetId",
    "quickCode",
    "name",
    "category",
    "site",
    "supplier",
    "purchaseDate",
    "expiresOn",
    "coverage",
    "receiptId",
    "notes",
)
DEFAULT_WARRANTY_FIELDS: tuple[str, ...] = tuple(column["key"] for column in WARRANTY_COLUMNS)
HISTORY_PAGE = 200
HISTORY_ROWS_LIMIT = 5000


@dataclass(frozen=True)
class ReportTable:
    """Normalized rows shared by preview, PDF and spreadsheet outputs."""

    rows: list[dict[str, Any]]
    columns: list[dict[str, str]]
    summary: dict[str, Any]
    assets: tuple[AssetView, ...]


def history_columns(
    fields: Sequence[str], document: DocumentLocale | None = None
) -> list[dict[str, str]]:
    return [{"key": field, "label": column_label("history", field, document)} for field in fields]


def warranty_columns(
    fields: Sequence[str], document: DocumentLocale | None = None
) -> list[dict[str, str]]:
    return [{"key": field, "label": column_label("warranty", field, document)} for field in fields]


def group_table(
    table: ReportTable, group: str, document: DocumentLocale | None = None
) -> ReportTable:
    """Sort rows stably by one asset group and add contiguous group labels."""
    if group not in GROUP_FIELDS:
        raise ValidationFailed("unsupported group", key="api.reports.unsupported_group")
    if group == "none":
        return table
    assets = {asset.quick_code: asset for asset in table.assets}
    decorated: list[tuple[str, int, dict[str, Any]]] = []
    for index, row in enumerate(table.rows):
        value = row.get(group)
        if value in (None, "") and row.get("quickCode") is not None:
            asset = assets.get(str(row["quickCode"]))
            if asset is not None:
                value = (
                    asset.responsible_label or asset.responsible
                    if group == "responsible"
                    else getattr(asset, group, None)
                )
        label = missing_group_label(document) if value in (None, "") else str(value)
        decorated.append((label, index, row))
    decorated.sort(key=lambda item: (item[0].casefold(), item[1]))
    grouped_counts: dict[str, int] = {}
    for label, _, row in decorated:
        row["group"] = label
        grouped_counts[label] = grouped_counts.get(label, 0) + 1
    summary = {
        **table.summary,
        "groups": [
            {"key": group, "label": label, "count": count}
            for label, count in grouped_counts.items()
        ],
    }
    return ReportTable(
        rows=[row for _, _, row in decorated],
        columns=table.columns,
        summary=summary,
        assets=table.assets,
    )


def _filters(filters: Any) -> dict[str, Any]:
    if filters is None:
        return {}
    if not isinstance(filters, Mapping):
        raise ValidationFailed("filters must be an object", key="api.reports.filters_object")
    return dict(filters)


def _text(value: Any, field: str, limit: int = 120) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed(
            f"filters.{field} must be text",
            key="api.reports.filter_text",
            params={"field": f"filters.{field}"},
        )
    normalized = value.strip()
    if len(normalized) > limit:
        raise ValidationFailed(
            f"filters.{field} is too long",
            key="api.reports.filter_too_long",
            params={"field": f"filters.{field}"},
        )
    return normalized or None


def _date(value: Any, field: str) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed(
            f"filters.{field} must be an ISO date",
            key="api.reports.filter_iso_date",
            params={"field": f"filters.{field}"},
        )
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > 32:
        raise ValidationFailed(
            f"filters.{field} is too long",
            key="api.reports.filter_too_long",
            params={"field": f"filters.{field}"},
        )
    try:
        return date.fromisoformat(normalized)
    except ValueError:
        try:
            return datetime.fromisoformat(normalized).date()
        except ValueError as exc:
            raise ValidationFailed(
                f"filters.{field} must be an ISO date",
                key="api.reports.filter_iso_date",
                params={"field": f"filters.{field}"},
            ) from exc


def asset_filters(filters: Any) -> dict[str, Any]:
    """Translate report filters to canonical ``InventoryService.search`` kwargs."""
    values = _filters(filters)
    archived = values.get("archived")
    if archived is not None and type(archived) is not bool:
        raise ValidationFailed(
            "filters.archived must be a boolean", key="api.reports.filter_archived_boolean"
        )
    named = {
        "query": _text(values.get("search"), "search"),
        "category": _text(values.get("category"), "category"),
        "site": _text(values.get("site"), "site"),
        "site_id": _text(values.get("siteId"), "siteId", 64),
        "location_id": _text(values.get("locationId"), "locationId", 64),
        "responsible_person_id": _text(
            values.get("responsiblePersonId"), "responsiblePersonId", 64
        ),
        "status": _text(values.get("status"), "status", 24),
    }
    result = {key: value for key, value in named.items() if value is not None}
    if archived is not None:
        result["archived"] = archived
    return result


def history_filters(filters: Any) -> dict[str, Any]:
    """Period/actor/event filters used by the history family rows."""
    values = _filters(filters)
    start = _date(values.get("from"), "from")
    end = _date(values.get("to"), "to")
    if start is not None and end is not None and start > end:
        raise ValidationFailed(
            "filters.from must not be after filters.to", key="api.reports.filter_range_order"
        )
    return {
        "start": start,
        "end": end,
        "actor": _text(values.get("actor"), "actor", 160),
        "event": _text(values.get("event"), "event", 64),
    }


def warranty_filter(filters: Any) -> str | None:
    values = _filters(filters)
    value = values.get("warrantyFilter")
    if value is None or value == "":
        return None
    if not isinstance(value, str) or value not in WARRANTY_FILTERS:
        raise ValidationFailed(
            "filters.warrantyFilter must be one of " + ", ".join(WARRANTY_FILTERS),
            key="api.reports.warranty_filter_allowed",
            params={"allowed": ", ".join(WARRANTY_FILTERS)},
        )
    return None if value == "all" else value


def _asset_ids(asset_ids: Iterable[Any] | None) -> list[str]:
    if asset_ids is None:
        return []
    if isinstance(asset_ids, str) or not isinstance(asset_ids, Iterable):
        raise ValidationFailed("assetIds must be a list", key="api.reports.asset_ids_list")
    ordered: list[str] = []
    seen: set[str] = set()
    for value in asset_ids:
        if not isinstance(value, str) or not value.strip():
            raise ValidationFailed(
                "assetIds must contain asset UUID strings", key="api.reports.asset_ids_uuid"
            )
        normalized = value.strip()
        if normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return ordered


def select_assets(
    inventory: InventoryService,
    principal: Any,
    *,
    asset_ids: Iterable[Any] | None,
    filters: Any,
    max_assets: int,
) -> tuple[AssetView, ...]:
    """Resolve the bounded selection; explicit ids and filters intersect."""
    ids = _asset_ids(asset_ids)
    if len(ids) > max_assets:
        raise ValidationFailed(
            f"selection exceeds {max_assets} assets",
            key="api.reports.selection_limit",
            params={"limit": max_assets},
        )
    search_filters = asset_filters(filters)
    if ids:
        if not search_filters:
            return tuple(inventory.get(principal, asset_id) for asset_id in ids)
        selected: list[AssetView] = []
        for asset_id in ids:
            page = inventory.search(
                principal, asset_id=asset_id, **search_filters, limit=1, offset=0
            )
            selected.extend(page.items)
        return tuple(selected)
    probe = inventory.search(principal, limit=1, offset=0, **search_filters)
    if probe.total > max_assets:
        raise ValidationFailed(
            f"selection matches {probe.total} assets; the limit is {max_assets}; "
            "narrow the filters",
            key="api.reports.selection_too_broad",
            params={"total": probe.total, "limit": max_assets},
        )
    selected = []
    offset = 0
    while offset < probe.total:
        page = inventory.search(
            principal,
            limit=min(HISTORY_PAGE, probe.total - offset),
            offset=offset,
            **search_filters,
        )
        if not page.items:
            break
        selected.extend(page.items)
        offset += len(page.items)
    return tuple(selected)


def project_asset(view: AssetView, fields: Sequence[str]) -> dict[str, Any]:
    """One asset reduced to the requested wire keys; never the raw ORM row."""
    available: dict[str, Any] = {
        "id": view.id,
        "quickCode": view.quick_code,
        "name": view.name,
        "category": view.category,
        "site": view.site,
        "location": view.location,
        "status": view.status,
        "responsible": view.responsible,
        "serial": view.serial,
        "brand": view.brand,
        "model": view.model,
        "ip": view.ip,
        "purchaseCost": None if view.cost is None else str(view.cost),
        "technical": None if view.technical is None else dict(view.technical),
    }
    return {key: available[key] for key in fields}


def _canonical_fields(fields: Sequence[str] | None) -> tuple[str, ...]:
    if not fields:
        return DEFAULT_FIELDS
    normalized: list[str] = []
    for key in fields:
        if key not in ASSET_FIELDS:
            raise ValidationFailed(
                f"unsupported asset field: {key}",
                key="api.reports.unsupported_asset_field",
                params={"field": key},
            )
        if key not in normalized:
            normalized.append(key)
    return tuple(normalized)


def columns(fields: Sequence[str], document: DocumentLocale | None = None) -> list[dict[str, str]]:
    return [{"key": key, "label": field_label(key, document)} for key in fields]


def _counts(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        label = "unknown" if value is None or value == "" else str(value)
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def inventory_table(
    assets: Sequence[AssetView],
    fields: Sequence[str] | None = None,
    document: DocumentLocale | None = None,
) -> ReportTable:
    selected = _canonical_fields(fields)
    rows = []
    for asset in assets:
        row = project_asset(asset, selected)
        row["id"] = asset.id
        rows.append(row)
    total_cost = sum((asset.cost for asset in assets if asset.cost is not None), Decimal("0"))
    summary = {
        "total": len(assets),
        "cost": str(total_cost.quantize(Decimal("0.01"))),
        "byStatus": _counts(asset.status for asset in assets),
        "byCategory": _counts(asset.category for asset in assets),
        "bySite": _counts(asset.site for asset in assets),
        "withTechnical": sum(1 for asset in assets if asset.technical),
    }
    return ReportTable(
        rows=rows,
        columns=columns(selected, document),
        summary=summary,
        assets=tuple(assets),
    )


def _matches(
    moment: datetime | str,
    actor_username: str | None,
    action: str | None,
    filters: Mapping[str, Any],
) -> date | None:
    if isinstance(moment, str):
        moment = datetime.fromisoformat(moment)
    day = as_utc(moment).date()
    start, end = filters["start"], filters["end"]
    if start is not None and day < start:
        return None
    if end is not None and day > end:
        return None
    actor = filters["actor"]
    if actor is not None and (actor_username or "").casefold() != actor.casefold():
        return None
    event = filters["event"]
    if event is not None and (action or "").casefold() != event.casefold():
        return None
    return day


def _history_matches(entry: HistoryView, filters: Mapping[str, Any]) -> date | None:
    return _matches(
        entry.effective_at or entry.created_at,
        entry.actor_username,
        entry.action,
        filters,
    )


def _technical_history_rows(
    interventions: Any,
    principal: Any,
    asset: AssetView,
    filters: Mapping[str, Any],
    selected: list[tuple[date, str, int, dict[str, Any]]],
) -> None:
    offset = 0
    while True:
        page = interventions.asset_technical_history(
            principal, asset.id, limit=HISTORY_PAGE, offset=offset
        )
        for item in page.items:
            moment = item.get("effectiveAt") or item.get("createdAt")
            if not moment:
                continue
            day = _matches(
                moment,
                item.get("actorUsername"),
                item.get("action"),
                filters,
            )
            if day is None:
                continue
            if len(selected) >= HISTORY_ROWS_LIMIT:
                raise ValidationFailed(
                    f"history selection exceeds {HISTORY_ROWS_LIMIT} rows; narrow the filters",
                    key="api.reports.history_rows_limit",
                    params={"limit": HISTORY_ROWS_LIMIT},
                )
            selected.append(
                (
                    day,
                    asset.quick_code,
                    int(item.get("sequence") or 0),
                    {
                        "assetId": asset.id,
                        "quickCode": asset.quick_code,
                        "name": asset.name,
                        "action": item.get("action"),
                        "actor": item.get("actorUsername"),
                        "source": item.get("source"),
                        "entityType": item.get("entityType"),
                        "entityId": item.get("entityId"),
                        "statusOld": item.get("statusOld"),
                        "statusNew": item.get("statusNew"),
                        "changes": dict(item.get("changes") or {}),
                        "notes": item.get("notes"),
                        "effectiveAt": moment,
                    },
                )
            )
        offset += len(page.items)
        if not page.items or offset >= page.total:
            break


def history_rows(
    inventory: InventoryService,
    interventions: Any,
    principal: Any,
    assets: Sequence[AssetView],
    filters: Any,
) -> list[tuple[date, str, int, dict[str, Any]]]:
    """Bounded per-asset history rows, ordered chronologically.

    Technical entries (interventions/incidents) have a dedicated canonical
    projection and are excluded from the general inventory page before being
    merged here, so each event appears exactly once.
    """
    normalized = history_filters(filters)
    selected: list[tuple[date, str, int, dict[str, Any]]] = []
    for asset in assets:
        offset = 0
        while True:
            page = inventory.history(principal, asset.id, limit=HISTORY_PAGE, offset=offset)
            for entry in page.items:
                if entry.entity_type in TECHNICAL_ENTITY_TYPES:
                    continue
                day = _history_matches(entry, normalized)
                if day is None:
                    continue
                if len(selected) >= HISTORY_ROWS_LIMIT:
                    raise ValidationFailed(
                        f"history selection exceeds {HISTORY_ROWS_LIMIT} rows; narrow the filters",
                        key="api.reports.history_rows_limit",
                        params={"limit": HISTORY_ROWS_LIMIT},
                    )
                selected.append(
                    (
                        day,
                        asset.quick_code,
                        entry.sequence,
                        {
                            "assetId": asset.id,
                            "quickCode": asset.quick_code,
                            "name": asset.name,
                            "action": entry.action,
                            "actor": entry.actor_username,
                            "source": entry.source,
                            "entityType": entry.entity_type,
                            "entityId": entry.entity_id,
                            "statusOld": entry.status_old,
                            "statusNew": entry.status_new,
                            "changes": dict(entry.changes),
                            "notes": entry.notes,
                            "effectiveAt": as_utc(
                                entry.effective_at or entry.created_at
                            ).isoformat(),
                        },
                    )
                )
            offset += len(page.items)
            if not page.items or offset >= page.total:
                break
        if interventions is not None:
            _technical_history_rows(interventions, principal, asset, normalized, selected)
    selected.sort(key=lambda item: (item[0], item[1], item[2]))
    return selected


def history_table(
    inventory: InventoryService,
    interventions: Any,
    principal: Any,
    assets: Sequence[AssetView],
    filters: Any,
    fields: Sequence[str] | None = None,
    document: DocumentLocale | None = None,
) -> ReportTable:
    entries = history_rows(inventory, interventions, principal, assets, filters)
    selected = tuple(fields or DEFAULT_HISTORY_FIELDS)
    rows = [
        {"assetId": entry[3].get("assetId"), **{field: entry[3].get(field) for field in selected}}
        for entry in entries
    ]
    summary = {
        "total": len(rows),
        "byAction": _counts(entry[3]["action"] for entry in entries),
        "byActor": _counts(entry[3]["actor"] for entry in entries),
        "from": None if not entries else entries[0][0].isoformat(),
        "to": None if not entries else entries[-1][0].isoformat(),
    }
    return ReportTable(
        rows=rows,
        columns=history_columns(selected, document),
        summary=summary,
        assets=tuple(assets),
    )


def _coverage(value: Any) -> str:
    return WARRANTY_COVERAGE_ALIASES.get(str(value or "unknown"), str(value or "missing"))


def warranty_table(
    warranties: Any,
    principal: Any,
    assets: Sequence[AssetView],
    filters: Any,
    fields: Sequence[str] | None = None,
    document: DocumentLocale | None = None,
) -> ReportTable:
    wanted = warranty_filter(filters)
    target = None if wanted is None else WARRANTY_FILTER_TARGETS[wanted]
    rows: list[dict[str, Any]] = []
    for asset in assets:
        try:
            warranty = warranties.get(principal, asset.id)
        except NotFound:
            if wanted not in (None, "missing"):
                continue
            rows.append(
                {
                    "assetId": asset.id,
                    "quickCode": asset.quick_code,
                    "name": asset.name,
                    "category": asset.category,
                    "site": asset.site,
                    "supplier": None,
                    "purchaseDate": None,
                    "expiresOn": None,
                    "coverage": "missing",
                    "receiptId": None,
                    "notes": None,
                }
            )
            continue
        coverage = _coverage(warranty.get("coverage"))
        if target is not None and coverage != target:
            continue
        rows.append(
            {
                "assetId": asset.id,
                "quickCode": asset.quick_code,
                "name": asset.name,
                "category": asset.category,
                "site": asset.site,
                "supplier": warranty.get("supplier"),
                "purchaseDate": warranty.get("purchaseDate"),
                "expiresOn": warranty.get("expiresOn"),
                "coverage": coverage,
                "receiptId": warranty.get("receiptId"),
                "notes": warranty.get("notes"),
            }
        )
    rows.sort(key=lambda row: row["quickCode"])
    selected = tuple(fields or DEFAULT_WARRANTY_FIELDS)
    projected = [
        {"assetId": row.get("assetId"), **{field: row.get(field) for field in selected}}
        for row in rows
    ]
    summary = {
        "total": len(projected),
        "byCoverage": _counts(row["coverage"] for row in rows),
    }
    return ReportTable(
        rows=projected,
        columns=warranty_columns(selected, document),
        summary=summary,
        assets=tuple(assets),
    )


def _cell(value: Any) -> Any:
    """Reuse the canonical spreadsheet escaping rules of the export service."""
    from itsm.workflows.service import _cell as export_cell

    return export_cell(value)


def export_table(table: ReportTable, document: DocumentLocale | None = None) -> ReportTable:
    """Prepend the immutable identity column when fields omitted it."""
    keys = {column["key"] for column in table.columns}
    identity = "id" if table.rows and "id" in table.rows[0] else "assetId"
    if identity in keys:
        return table
    label = export_id_label(identity, document)
    return ReportTable(
        rows=table.rows,
        columns=[{"key": identity, "label": label}, *table.columns],
        summary=table.summary,
        assets=table.assets,
    )


def csv_bytes(rows: Sequence[Mapping[str, Any]], columns_: Sequence[Mapping[str, str]]) -> bytes:
    """UTF-8 CSV with the same header/escaped cells as the existing export."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=",")
    writer.writerow([column["label"] for column in columns_])
    for row in rows:
        writer.writerow([_cell(row.get(column["key"])) for column in columns_])
    return buffer.getvalue().encode("utf-8-sig")


def _sheet_name(document: DocumentLocale | None = None) -> str:
    resolved = document if document is not None else default_document_locale()
    return resolved.t("api.reports.sheet_name")


def xlsx_bytes(
    rows: Sequence[Mapping[str, Any]],
    columns_: Sequence[Mapping[str, str]],
    document: DocumentLocale | None = None,
) -> bytes:
    """Write-only XLSX with every supplied value typed as text."""
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet(_sheet_name(document))
    sheet.append([column["label"] for column in columns_])
    for row in rows:
        cells = []
        for column in columns_:
            cell = WriteOnlyCell(sheet, value=str(_cell(row.get(column["key"]))))
            cell.data_type = "s"
            cells.append(cell)
        sheet.append(cells)
    target = io.BytesIO()
    workbook.save(target)
    return target.getvalue()


def public_asset(session: Session, asset: Asset, fields: Sequence[str]) -> dict[str, Any]:
    """Explicit public projection: never IP, serial, responsible, cost or technical."""
    values: dict[str, Any] = {
        "id": asset.id,
        "quickCode": asset.quick_code,
        "name": asset.name,
        "category": asset.category,
        "site": asset.site,
        "location": asset.location,
        "status": asset.status,
    }
    if asset.site_id or asset.location_id:
        from itsm.directory.models import DirectoryLocation

        ids = [value for value in (asset.site_id, asset.location_id) if value]
        names = {
            row.id: row.name
            for row in session.execute(
                select(DirectoryLocation.id, DirectoryLocation.name).where(
                    DirectoryLocation.id.in_(ids)
                )
            )
        }
        if asset.site_id:
            values["site"] = names.get(asset.site_id, asset.site)
        if asset.location_id:
            values["location"] = names.get(asset.location_id, asset.location)
    return {key: values[key] for key in fields}
