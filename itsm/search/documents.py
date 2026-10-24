"""Canonical entity projections for search.

Everything here derives from SQL rows or from the static navigation map the
frontend router already exposes.  Documents carry no authority: they are
labels and targets handed to a caller that was already authorized.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from itsm.directory.models import DirectoryDepartment, DirectoryLocation, DirectoryPerson
from itsm.identity.service import Principal
from itsm.interventions.models import Incident
from itsm.inventory.catalog_models import InventoryCatalogEntry
from itsm.inventory.models import Asset
from itsm.maintenance.models import MaintenancePlan

FETCH_CEILING = 250
EXACT_SCORE = 10000
PREFIX_SCORE = 5000
CONTAINS_SCORE = 1000

#: Types the external engine may hold.  Sections and views are deliberately
#: SQL-only: personal saved views must never leak into a shared index.
INDEXED_TYPES: tuple[str, ...] = (
    "asset",
    "person",
    "location",
    "site",
    "incident",
    "maintenance",
    "category",
)

TYPE_LABELS: dict[str, str] = {
    "asset": "Activos",
    "person": "Personas",
    "location": "Ubicaciones",
    "site": "Sedes",
    "incident": "Incidentes",
    "maintenance": "Mantenimientos",
    "category": "Categorías",
    "section": "Secciones",
    "view": "Vistas guardadas",
}

LOCATION_LEVEL_LABELS = {
    "site": "Sede",
    "building": "Edificio",
    "floor": "Piso",
    "room": "Sala",
    "zone": "Zona",
}

SECTIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "panel",
        "label": "Dashboard",
        "icon": "activity",
        "keywords": ("inicio", "panel", "dashboard"),
    },
    {
        "id": "inventory",
        "label": "Inventario",
        "icon": "inventory",
        "keywords": ("activos", "equipos", "inventario"),
    },
    {
        "id": "people",
        "label": "Personas",
        "icon": "user",
        "keywords": ("directorio", "personas", "responsables"),
    },
    {
        "id": "map",
        "label": "Mapa de infraestructura",
        "icon": "map-pin",
        "keywords": ("mapa", "planos", "ubicaciones", "sedes"),
    },
    {
        "id": "graph",
        "label": "Grafo de relaciones",
        "icon": "network",
        "keywords": ("grafo", "relaciones", "red"),
    },
    {
        "id": "maintenance",
        "label": "Mantenimiento e incidentes",
        "icon": "refresh",
        "keywords": ("mantenimiento", "incidentes", "planes", "intervenciones"),
    },
    {
        "id": "monitoring",
        "label": "Supervisión",
        "icon": "gauge",
        "keywords": ("monitoreo", "supervision", "alertas"),
    },
    {
        "id": "reports",
        "label": "Reportes",
        "icon": "file-text",
        "keywords": ("reportes", "informes", "exportar"),
    },
    {
        "id": "warranties",
        "label": "Garantías",
        "icon": "shield",
        "keywords": ("garantias", "vencimientos"),
    },
    {
        "id": "labels",
        "label": "Etiquetas",
        "icon": "printer",
        "keywords": ("etiquetas", "qr", "impresion"),
    },
)

CONFIG_SECTIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "seguridad",
        "label": "Usuarios y permisos",
        "icon": "user",
        "keywords": ("roles", "sesiones", "seguridad"),
    },
    {
        "id": "general",
        "label": "General",
        "icon": "sliders",
        "keywords": ("identidad", "marca", "general"),
    },
    {
        "id": "apariencia",
        "label": "Apariencia",
        "icon": "sliders",
        "keywords": ("branding", "temas", "presets", "apariencia"),
    },
    {
        "id": "categorias",
        "label": "Categorías",
        "icon": "grid",
        "keywords": ("catalogo", "equipos", "categorias"),
    },
    {
        "id": "activos",
        "label": "Activos",
        "icon": "box",
        "keywords": ("campos", "formularios", "codigos", "activos"),
    },
    {
        "id": "sedes",
        "label": "Sedes y ubicaciones",
        "icon": "building",
        "keywords": ("estructura", "fisica", "sedes", "ubicaciones"),
    },
    {
        "id": "personas",
        "label": "Personas",
        "icon": "user",
        "keywords": ("departamentos", "areas", "personas"),
    },
    {
        "id": "integraciones",
        "label": "Integraciones",
        "icon": "remote",
        "keywords": ("anydesk", "tactical", "rmm", "integraciones"),
    },
    {
        "id": "relaciones",
        "label": "Relaciones",
        "icon": "network",
        "keywords": ("vinculos", "grafo", "relaciones"),
    },
    {
        "id": "mantenimiento",
        "label": "Mantenimiento",
        "icon": "refresh",
        "keywords": ("plantillas", "intervalos", "mantenimiento"),
    },
    {
        "id": "supervision",
        "label": "Supervisión",
        "icon": "gauge",
        "keywords": ("comprobaciones", "umbrales", "supervision"),
    },
    {
        "id": "alertas",
        "label": "Alertas",
        "icon": "bell",
        "keywords": ("silencios", "ventanas", "alertas"),
    },
    {
        "id": "notificaciones",
        "label": "Notificaciones",
        "icon": "send",
        "keywords": ("canales", "escalamiento", "notificaciones"),
    },
    {
        "id": "mapas",
        "label": "Mapas y planos",
        "icon": "map-pin",
        "keywords": ("planos", "capas", "mapas"),
    },
    {
        "id": "datos",
        "label": "Datos e importación",
        "icon": "upload",
        "keywords": ("perfiles", "formatos", "historial", "datos"),
    },
    {
        "id": "reportes",
        "label": "Reportes",
        "icon": "file-text",
        "keywords": ("plantillas", "composicion", "reportes"),
    },
    {
        "id": "garantias",
        "label": "Garantías",
        "icon": "shield",
        "keywords": ("plazos", "vencimientos", "garantias"),
    },
    {
        "id": "qr",
        "label": "Códigos QR",
        "icon": "grid",
        "keywords": ("url", "acceso", "qr", "codigos"),
    },
    {
        "id": "etiquetas",
        "label": "Etiquetas",
        "icon": "printer",
        "keywords": ("formatos", "impresion", "etiquetas"),
    },
)


def normalize(value: Any) -> str:
    """Case- and accent-insensitive comparison key."""
    import unicodedata

    text = unicodedata.normalize("NFKD", " ".join(str(value or "").split()).casefold())
    return "".join(char for char in text if not unicodedata.combining(char))


def tokens(query: str) -> list[str]:
    return [part for part in normalize(query).split(" ") if part]


def matches(haystack: str, query_tokens: Sequence[str]) -> bool:
    hay = normalize(haystack)
    return all(token in hay for token in query_tokens)


def _item(
    kind: str,
    entity_id: str,
    *,
    label: str,
    subtitle: str,
    icon: str,
    target: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "key": f"{kind}:{entity_id}",
        "type": kind,
        "id": entity_id,
        "label": " ".join(str(label or entity_id).split()),
        "subtitle": " ".join(str(subtitle or "").split()),
        "icon": icon,
        "target": dict(target),
    }


def _score(item: Mapping[str, Any], query: str, exact: set[str], hay: str) -> int:
    normalized = normalize(query)
    if normalized in exact:
        return EXACT_SCORE
    if normalize(item["label"]).startswith(normalized) or normalize(item["id"]).startswith(
        normalized
    ):
        return PREFIX_SCORE
    return CONTAINS_SCORE if normalized in normalize(hay) else 0


def _like_pattern(token: str) -> str:
    escaped = token.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _raw_tokens(query: str) -> list[str]:
    """Split without accent folding: SQL LIKE can only match stored spellings."""
    return [part for part in re.split(r"[\W_]+", query, flags=re.UNICODE) if part]


def _filter(*columns: Any, query: str) -> Any:
    return and_(
        *[
            or_(*[column.ilike(_like_pattern(token), escape="\\") for column in columns])
            for token in _raw_tokens(query)
        ]
    )


def _count(session: Session, statement: Any) -> int:
    return int(
        session.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
    )


def _bounded(session: Session, statement: Any, limit: int) -> Any:
    return session.scalars(statement.limit(min(max(limit, 1), FETCH_CEILING)))


# --------------------------------------------------------------------- items
def _asset_details(session: Session, asset: Asset) -> tuple[dict[str, Any], list[str]]:
    label = asset.name or asset.quick_code or asset.id
    subtitle = " · ".join(
        part
        for part in (
            asset.quick_code,
            asset.ip,
            " ".join(filter(None, (asset.brand, asset.model))),
            asset.category,
        )
        if part
    )
    item = _item(
        "asset",
        asset.id,
        label=label,
        subtitle=subtitle,
        icon="box",
        target={"kind": "asset", "id": asset.id},
    )
    keywords = [
        str(part)
        for part in (
            asset.id,
            asset.quick_code,
            asset.serial,
            asset.brand,
            asset.model,
            asset.ip,
            asset.category,
            asset.type,
            asset.description,
        )
        if part
    ]
    return item, keywords


def _person_details(session: Session, person: DirectoryPerson) -> tuple[dict[str, Any], list[str]]:
    department = (
        session.get(DirectoryDepartment, person.department_id) if person.department_id else None
    )
    subtitle = " · ".join(
        part
        for part in (
            person.job_title,
            None if department is None else department.name,
            person.contact_email,
        )
        if part
    )
    item = _item(
        "person",
        person.id,
        label=person.name,
        subtitle=subtitle,
        icon="user",
        target={"kind": "person", "id": person.id},
    )
    keywords = [
        str(part)
        for part in (
            person.id,
            person.job_title,
            person.contact_email,
            person.contact_phone,
            None if department is None else department.name,
        )
        if part
    ]
    return item, keywords


def _site_id(session: Session, location: DirectoryLocation) -> str | None:
    current: DirectoryLocation | None = location
    seen: set[str] = set()
    while current is not None and current.id not in seen:
        seen.add(current.id)
        if current.level == "site":
            return current.id
        parent_id = current.parent_id
        current = session.get(DirectoryLocation, parent_id) if parent_id else None
    return None


def _location_details(
    session: Session, location: DirectoryLocation
) -> tuple[dict[str, Any], list[str]]:
    kind = "site" if location.level == "site" else "location"
    parent = session.get(DirectoryLocation, location.parent_id) if location.parent_id else None
    subtitle = " · ".join(
        part
        for part in (
            "Sede" if kind == "site" else LOCATION_LEVEL_LABELS.get(location.level, "Ubicación"),
            None if parent is None else parent.name,
            location.description,
        )
        if part
    )
    target: dict[str, Any] = {"kind": kind, "id": location.id}
    if kind != "site":
        site_id = _site_id(session, location)
        if site_id:
            target["siteId"] = site_id
    item = _item(
        kind,
        location.id,
        label=location.name,
        subtitle=subtitle,
        icon="building" if kind == "site" else "map-pin",
        target=target,
    )
    keywords = [
        str(part)
        for part in (
            location.id,
            location.level,
            location.description,
            None if parent is None else parent.name,
            location.plan_ref,
        )
        if part
    ]
    return item, keywords


def _incident_details(session: Session, incident: Incident) -> tuple[dict[str, Any], list[str]]:
    label = " ".join(incident.description.split())
    if len(label) > 120:
        label = label[:117].rstrip() + "…"
    item = _item(
        "incident",
        incident.id,
        label=label,
        subtitle=f"{incident.status} · {incident.priority}",
        icon="bell",
        target={"kind": "incident", "id": incident.id},
    )
    keywords = [incident.id, incident.status, incident.priority, incident.description]
    return item, keywords


def _maintenance_details(
    session: Session, plan: MaintenancePlan
) -> tuple[dict[str, Any], list[str]]:
    asset = session.get(Asset, plan.asset_id)
    asset_name = asset.name if asset is not None else plan.asset_id
    item = _item(
        "maintenance",
        plan.id,
        label=f"{asset_name} · {plan.maintenance_type}",
        subtitle=f"Plan · {plan.status} · vence {plan.due_on.isoformat()}",
        icon="refresh",
        target={"kind": "maintenance", "id": plan.id},
    )
    keywords = [
        str(part)
        for part in (
            plan.id,
            plan.maintenance_type,
            plan.status,
            asset_name,
            None if asset is None else asset.quick_code,
            *plan.tasks,
        )
        if part
    ]
    return item, keywords


def _category_payload(entry: InventoryCatalogEntry) -> dict[str, Any]:
    payload = entry.payload
    return dict(payload) if isinstance(payload, Mapping) else {}


def _category_details(
    session: Session, entry: InventoryCatalogEntry
) -> tuple[dict[str, Any], list[str]]:
    payload = _category_payload(entry)
    item = _item(
        "category",
        entry.key,
        label=str(payload.get("label") or entry.key),
        subtitle="Categoría",
        icon=str(payload.get("icon") or "grid"),
        target={"kind": "category", "id": entry.key},
    )
    keywords = [
        str(part)
        for part in (
            entry.key,
            payload.get("label"),
            payload.get("prefix"),
            payload.get("type"),
            payload.get("icon"),
        )
        if part
    ]
    return item, keywords


def _entity_detail(
    session: Session, entity_type: str, entity_id: str
) -> tuple[dict[str, Any], list[str]] | None:
    if entity_type == "asset":
        asset = session.get(Asset, entity_id)
        if asset is None or asset.archived_at is not None:
            return None
        return _asset_details(session, asset)
    if entity_type == "person":
        person = session.get(DirectoryPerson, entity_id)
        if person is None or person.status != "active":
            return None
        return _person_details(session, person)
    if entity_type in {"location", "site"}:
        location = session.get(DirectoryLocation, entity_id)
        if location is None or not location.active:
            return None
        detail = _location_details(session, location)
        return detail if detail[0]["type"] == entity_type else None
    if entity_type == "incident":
        incident = session.get(Incident, entity_id)
        return None if incident is None else _incident_details(session, incident)
    if entity_type == "maintenance":
        plan = session.get(MaintenancePlan, entity_id)
        return None if plan is None else _maintenance_details(session, plan)
    if entity_type == "category":
        entry = session.get(InventoryCatalogEntry, ("categories", entity_id))
        if entry is None or entry.kind != "categories":
            return None
        if _category_payload(entry).get("active") is False:
            return None
        return _category_details(session, entry)
    return None


def build_item(session: Session, kind: str, entity_id: str) -> dict[str, Any] | None:
    """Rehydrate one entity from live SQL; ``None`` means "remove from index"."""
    detail = _entity_detail(session, kind, entity_id)
    return None if detail is None else detail[0]


def build_document(session: Session, entity_type: str, entity_id: str) -> dict[str, Any] | None:
    """Build the Meilisearch document for one canonical entity, or ``None``."""
    detail = _entity_detail(session, entity_type, entity_id)
    if detail is None:
        return None
    item, keywords = detail
    return {
        "id": item["key"],
        "type": item["type"],
        "entity_id": item["id"],
        "label": item["label"],
        "subtitle": item["subtitle"],
        "keywords": [str(part) for part in keywords if part],
    }


# ---------------------------------------------------------------- SQL search
def sql_search(
    session: Session,
    query: str,
    kinds: Sequence[str],
    limit: int,
) -> tuple[list[tuple[int, dict[str, Any]]], int]:
    """Bounded SQL search restricted to already-authorized kinds.

    Returns ``(ranked, total)`` where every entry is ``(score, item)`` so the
    caller can place exact identifier matches ahead of engine hits.
    """
    ranked: list[tuple[int, dict[str, Any]]] = []
    total = 0
    query_tokens = tokens(query)

    def add(kind: str, details: tuple[dict[str, Any], list[str]], exact: set[str]) -> None:
        item, keywords = details
        hay = " ".join([item["label"], item["subtitle"], *keywords])
        if not matches(hay, query_tokens):
            return
        score = _score(item, query, exact, hay)
        if score:
            ranked.append((score, item))

    if "asset" in kinds:
        statement = (
            select(Asset)
            .where(Asset.archived_at.is_(None))
            .where(
                _filter(
                    Asset.id,
                    Asset.quick_code,
                    Asset.name,
                    Asset.brand,
                    Asset.model,
                    Asset.serial,
                    Asset.ip,
                    Asset.category,
                    Asset.type,
                    query=query,
                )
            )
        )
        total += _count(session, statement)
        for asset in _bounded(session, statement, limit):
            add(
                "asset",
                _asset_details(session, asset),
                {normalize(asset.id), normalize(asset.quick_code)},
            )

    if "person" in kinds:
        statement = (
            select(DirectoryPerson)
            .where(DirectoryPerson.status == "active")
            .where(
                _filter(
                    DirectoryPerson.id,
                    DirectoryPerson.name,
                    DirectoryPerson.job_title,
                    DirectoryPerson.contact_email,
                    DirectoryPerson.contact_phone,
                    query=query,
                )
            )
        )
        total += _count(session, statement)
        for person in _bounded(session, statement, limit):
            add("person", _person_details(session, person), {normalize(person.id)})

    location_kinds = [kind for kind in ("location", "site") if kind in kinds]
    if location_kinds:
        statement = (
            select(DirectoryLocation)
            .where(DirectoryLocation.active.is_(True))
            .where(
                _filter(
                    DirectoryLocation.id,
                    DirectoryLocation.name,
                    DirectoryLocation.description,
                    DirectoryLocation.plan_ref,
                    query=query,
                )
            )
        )
        if location_kinds == ["site"]:
            statement = statement.where(DirectoryLocation.level == "site")
        elif location_kinds == ["location"]:
            statement = statement.where(DirectoryLocation.level != "site")
        total += _count(session, statement)
        for location in _bounded(session, statement, limit):
            details = _location_details(session, location)
            if details[0]["type"] in location_kinds:
                add(details[0]["type"], details, {normalize(location.id)})

    if "incident" in kinds:
        statement = select(Incident).where(_filter(Incident.id, Incident.description, query=query))
        total += _count(session, statement)
        for incident in _bounded(session, statement, limit):
            add("incident", _incident_details(session, incident), {normalize(incident.id)})

    if "maintenance" in kinds:
        statement = (
            select(MaintenancePlan)
            .join(Asset, Asset.id == MaintenancePlan.asset_id)
            .where(
                _filter(
                    MaintenancePlan.id,
                    MaintenancePlan.maintenance_type,
                    Asset.name,
                    Asset.quick_code,
                    query=query,
                )
            )
        )
        total += _count(session, statement)
        for plan in _bounded(session, statement, limit):
            add("maintenance", _maintenance_details(session, plan), {normalize(plan.id)})

    if "category" in kinds:
        for entry in session.scalars(
            select(InventoryCatalogEntry).where(InventoryCatalogEntry.kind == "categories")
        ).all():
            if _category_payload(entry).get("active") is False:
                continue
            details = _category_details(session, entry)
            item = details[0]
            hay = " ".join([item["label"], item["subtitle"], *details[1]])
            if not matches(hay, query_tokens):
                continue
            total += 1
            ranked.append((_score(item, query, {normalize(entry.key)}, hay), item))

    ranked.sort(key=lambda pair: (-pair[0], pair[1]["label"].casefold(), pair[1]["key"]))
    return ranked, total


# ------------------------------------------------------------------ sections
def sections() -> Iterator[dict[str, Any]]:
    for section in SECTIONS:
        yield {
            **section,
            "subtitle": "Sección de la aplicación",
            "item": _item(
                "section",
                section["id"],
                label=section["label"],
                subtitle="Sección de la aplicación",
                icon=section["icon"],
                target={"kind": "section", "route": {"name": section["id"]}},
            ),
        }
    for section in CONFIG_SECTIONS:
        identifier = f"config-{section['id']}"
        yield {
            **section,
            "id": identifier,
            "subtitle": "Configuración",
            "item": _item(
                "section",
                identifier,
                label=section["label"],
                subtitle="Configuración",
                icon=section["icon"],
                target={"kind": "section", "route": {"name": "config", "section": section["id"]}},
            ),
        }


# --------------------------------------------------------------------- views
#: The workspace module owns saved views.  Search works with or without it:
#: when the model exists, personal views are read from SQL on demand; shared
#: views may additionally be indexed, but personal ones never enter the shared
#: external index.
ViewSource = Callable[[Session, Principal], Iterable[Mapping[str, Any]]]
_VIEW_SOURCE: ViewSource | None = None


def register_view_source(source: ViewSource | None) -> None:
    global _VIEW_SOURCE
    _VIEW_SOURCE = source


def _workspace_views(session: Session, principal: Principal) -> Iterable[Mapping[str, Any]]:
    try:
        from itsm.workspace.models import WorkspaceView
    except ImportError:
        return []
    try:
        rows = session.scalars(
            select(WorkspaceView).where(
                or_(
                    WorkspaceView.owner_id == principal.actor_id,
                    WorkspaceView.scope == "shared",
                )
            )
        ).all()
    except SQLAlchemyError:
        return []
    return [
        {
            "id": row.id,
            "label": row.name,
            "subtitle": row.route,
            "keywords": (row.route, row.scope),
        }
        for row in rows
    ]


def view_matches(session: Session, principal: Principal, query: str) -> list[dict[str, Any]]:
    source = _VIEW_SOURCE or _workspace_views
    query_tokens = tokens(query)
    results: list[dict[str, Any]] = []
    for row in source(session, principal):
        if not isinstance(row, Mapping):
            continue
        entity_id = str(row.get("id") or "")
        if not entity_id:
            continue
        item = _item(
            "view",
            entity_id,
            label=str(row.get("label") or entity_id),
            subtitle=str(row.get("subtitle") or "Vista guardada"),
            icon=str(row.get("icon") or "eye"),
            target={"kind": "view", "id": entity_id},
        )
        hay = " ".join(
            [item["label"], item["subtitle"], *[str(v) for v in row.get("keywords", ())]]
        )
        if matches(hay, query_tokens):
            results.append(item)
        if len(results) >= FETCH_CEILING:
            break
    return results


# ------------------------------------------------------------------- rebuild
def iter_documents(session: Session) -> Iterator[dict[str, Any]]:
    """Yield every document that belongs in a full index rebuild."""
    for asset in session.scalars(
        select(Asset).where(Asset.archived_at.is_(None)).order_by(Asset.id)
    ):
        yield _document(*_asset_details(session, asset))
    for person in session.scalars(
        select(DirectoryPerson)
        .where(DirectoryPerson.status == "active")
        .order_by(DirectoryPerson.id)
    ):
        yield _document(*_person_details(session, person))
    for location in session.scalars(
        select(DirectoryLocation)
        .where(DirectoryLocation.active.is_(True))
        .order_by(DirectoryLocation.id)
    ):
        yield _document(*_location_details(session, location))
    for incident in session.scalars(select(Incident).order_by(Incident.id)):
        yield _document(*_incident_details(session, incident))
    for plan in session.scalars(select(MaintenancePlan).order_by(MaintenancePlan.id)):
        yield _document(*_maintenance_details(session, plan))
    for entry in session.scalars(
        select(InventoryCatalogEntry)
        .where(InventoryCatalogEntry.kind == "categories")
        .order_by(InventoryCatalogEntry.key)
    ):
        if _category_payload(entry).get("active") is False:
            continue
        yield _document(*_category_details(session, entry))


def _document(item: Mapping[str, Any], keywords: Iterable[str]) -> dict[str, Any]:
    return {
        "id": item["key"],
        "type": item["type"],
        "entity_id": item["id"],
        "label": item["label"],
        "subtitle": item["subtitle"],
        "keywords": [str(part) for part in keywords if part],
    }


def pending_count(session: Session) -> int:
    from itsm.search.models import SearchSyncOutbox

    return int(session.scalar(select(func.count()).select_from(SearchSyncOutbox)) or 0)


__all__ = [
    "CONFIG_SECTIONS",
    "EXACT_SCORE",
    "FETCH_CEILING",
    "INDEXED_TYPES",
    "PREFIX_SCORE",
    "SECTIONS",
    "TYPE_LABELS",
    "build_document",
    "build_item",
    "iter_documents",
    "matches",
    "normalize",
    "pending_count",
    "register_view_source",
    "sections",
    "sql_search",
    "tokens",
    "view_matches",
]
