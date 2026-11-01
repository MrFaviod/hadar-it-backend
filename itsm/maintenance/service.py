"""Preventive maintenance: category templates, asset plans and lifecycle.

The service is the canonical business layer. HTTP, agents and the scheduler
call it; none of them reimplement recurrence or state rules.

Effective-plan identity
-----------------------
A plan id is a UUIDv5 of ``plan/<asset-uuid>/<maintenance-type>``. The same id
identifies the computed (virtual) plan inherited from the category template and
the persisted row created by an override or a real transition. Materializing a
plan never changes its id, so a scheduler reminder or an intervention link keeps
pointing at the same business object.

Templates are snapshots for persisted plans: changing a category template
changes plans that still inherit it, but never rewrites an explicit override or
a cycle that already transitioned. A virtual plan is recomputed on every read
and is never written by a GET.
"""

from __future__ import annotations

import calendar
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.directory.models import DirectoryPerson
from itsm.directory.service import DirectoryService
from itsm.i18n.labels import state_label
from itsm.identity.clock import utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    Principal,
    ValidationFailed,
)
from itsm.inventory.codes import serialized
from itsm.inventory.models import Asset
from itsm.inventory.service import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    InventoryService,
    _history_source,
    _notes,
)
from itsm.maintenance.models import MaintenancePlan, MaintenanceTemplate

DEFAULT_TYPE = "preventivo"
DEFAULT_LIMIT_MAINTENANCE = DEFAULT_LIMIT
MAX_LIMIT_MAINTENANCE = MAX_LIMIT
SCHEDULER_LIMIT = 200
MAX_INTERVAL_MONTHS = 120
MAX_TASKS = 24
MAX_TASK_LENGTH = 240
MAX_UPCOMING_DAYS = 365
STATUS_ACTIVE = "active"
STATUS_POSTPONED = "postponed"
STATUS_CANCELLED = "cancelled"
PLAN_STATUSES = frozenset({STATUS_ACTIVE, STATUS_POSTPONED, STATUS_CANCELLED})
PLAN_STATES = frozenset({"pending", "upcoming", "overdue"})
UNSET = object()
_UNSET = UNSET

_NAMESPACE = uuid5(NAMESPACE_URL, "https://itms.local/maintenance")
_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,31}$")

# Defaults are keyed by the authoritative category ids seeded by migration
# 0004. A category added later still gets a usable default from the fallback.
_DEFAULT_INTERVALS: dict[str, int] = {
    "computadoras": 6,
    "notebooks": 6,
    "servidores": 3,
    "virtualizacion": 3,
    "docker": 3,
    "lxc": 3,
    "contenedores": 3,
    "switches": 6,
    "routers": 6,
    "impresoras": 3,
    "ups": 6,
    "camaras": 6,
    "monitores": 12,
    "otros": 12,
}
_DEFAULT_TASKS: dict[str, tuple[str, ...]] = {
    "computadoras": ("Verificar funcionamiento", "Actualizar sistema", "Revisar antivirus"),
    "notebooks": ("Verificar batería", "Actualizar sistema", "Revisar refrigeración"),
    "servidores": (
        "Verificar estado del hardware",
        "Revisar registros del sistema",
        "Verificar espacio y respaldos",
    ),
    "virtualizacion": (
        "Verificar estado del hipervisor",
        "Revisar uso de recursos",
        "Verificar respaldos de máquinas virtuales",
    ),
    "docker": (
        "Verificar estado de contenedores",
        "Revisar imágenes y actualizaciones",
        "Verificar volúmenes persistentes",
    ),
    "lxc": (
        "Verificar estado de contenedores LXC",
        "Revisar uso de recursos",
        "Verificar respaldos",
    ),
    "contenedores": (
        "Verificar estado de contenedores",
        "Revisar orquestación",
        "Verificar respaldos",
    ),
    "switches": (
        "Verificar estado de puertos",
        "Revisar firmware",
        "Verificar respaldos de configuración",
    ),
    "routers": ("Verificar enlaces", "Revisar firmware", "Verificar respaldos de configuración"),
    "impresoras": ("Verificar funcionamiento", "Revisar consumibles", "Revisar conectividad"),
    "ups": ("Verificar baterías", "Revisar alarmas", "Verificar autonomía"),
    "camaras": ("Verificar grabación", "Revisar imagen", "Verificar firmware"),
    "monitores": ("Verificar funcionamiento", "Revisar conexión"),
    "otros": ("Verificar funcionamiento", "Revisar estado general"),
}
_FALLBACK_INTERVAL = 12
_FALLBACK_TASKS = ("Verificar funcionamiento", "Revisar estado general")
_LEGACY_CATEGORY_ALIASES = {"red": "switches", "redes": "switches", "network": "switches"}


def plan_id(asset_id: str, maintenance_type: str) -> str:
    """Stable business id shared by the virtual plan and its persisted row."""
    return str(uuid5(_NAMESPACE, f"plan/{asset_id}/{maintenance_type}"))


def template_id(category: str, maintenance_type: str) -> str:
    """Stable id of the preconfigured default for one category and type."""
    return str(uuid5(_NAMESPACE, f"template/{category}/{maintenance_type}"))


def add_months(value: date, months: int) -> date:
    """Calendar-month recurrence with an explicit end-of-month clamp."""
    if not isinstance(value, date) or isinstance(value, datetime):
        raise ValidationFailed("date is required")
    if not isinstance(months, int) or isinstance(months, bool):
        raise ValidationFailed("months must be an integer")
    if not 1 <= months <= MAX_INTERVAL_MONTHS:
        raise ValidationFailed(f"months must be between 1 and {MAX_INTERVAL_MONTHS}")
    total = value.year * 12 + (value.month - 1) + months
    year, month_index = divmod(total, 12)
    month = month_index + 1
    try:
        last_day = calendar.monthrange(year, month)[1]
        return date(year, month, min(value.day, last_day))
    except ValueError:
        raise ValidationFailed("resulting date is out of range") from None


def _iso_date(value: date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _iso_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _checked_date(value: Any, label: str) -> date:
    if not isinstance(value, date) or isinstance(value, datetime):
        raise ValidationFailed(f"{label} must be an ISO date")
    return value


def _checked_interval(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationFailed("intervalMonths must be an integer")
    if not 1 <= value <= MAX_INTERVAL_MONTHS:
        raise ValidationFailed(f"intervalMonths must be between 1 and {MAX_INTERVAL_MONTHS}")
    return value


def _checked_type(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationFailed("maintenanceType must be text")
    normalized = value.strip().lower()
    if not _TYPE_PATTERN.fullmatch(normalized):
        raise ValidationFailed(
            "maintenanceType must be 2-32 lowercase letters, digits or underscores"
        )
    return normalized


def _checked_tasks(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ValidationFailed("tasks must be a list of text")
    items: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ValidationFailed("tasks must contain text")
        task = raw.strip()
        if not task or len(task) > MAX_TASK_LENGTH:
            raise ValidationFailed(f"task must be 1-{MAX_TASK_LENGTH} characters")
        if task not in items:
            items.append(task)
    if len(items) > MAX_TASKS:
        raise ValidationFailed(f"tasks must have at most {MAX_TASKS} entries")
    return tuple(items)


def _checked_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{label} is required")
    try:
        return str(UUID(value.strip()))
    except ValueError:
        raise ValidationFailed(f"{label} must be a UUID") from None


def _checked_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationFailed(f"{label} must be a boolean")
    return value


def _checked_limit(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_LIMIT:
        raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
    return value


def _checked_offset(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationFailed("offset must be zero or greater")
    return value


def _checked_optional_date(value: Any, label: str) -> date | None:
    if value is None:
        return None
    return _checked_date(value, label)


def _normalized_category(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed("category is required")
    text = value.strip()
    if len(text) > 64:
        raise ValidationFailed("category must have at most 64 characters")
    return text


def _today() -> date:
    return utcnow().date()


@dataclass(frozen=True)
class MaintenanceTemplateView:
    id: str
    category: str
    maintenance_type: str
    interval_months: int
    tasks: list[str]
    responsible_person_id: str | None
    responsible_label: str | None
    active: bool
    source: str
    created_at: datetime | None
    updated_at: datetime | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "maintenanceType": self.maintenance_type,
            "intervalMonths": self.interval_months,
            "tasks": list(self.tasks),
            "responsiblePersonId": self.responsible_person_id,
            "responsibleLabel": self.responsible_label,
            "active": self.active,
            "source": self.source,
            "createdAt": _iso_datetime(self.created_at),
            "updatedAt": _iso_datetime(self.updated_at),
        }


@dataclass(frozen=True)
class MaintenancePlanView:
    id: str
    asset_id: str
    asset_quick_code: str
    asset_name: str
    asset_category: str | None
    site_id: str | None
    site: str | None
    maintenance_type: str
    interval_months: int
    tasks: list[str]
    responsible_person_id: str | None
    responsible_label: str | None
    status: str
    status_label: str
    scheduled_on: date
    last_completed_on: date | None
    due_on: date
    persisted: bool
    created_at: datetime | None
    updated_at: datetime | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "assetId": self.asset_id,
            "assetQuickCode": self.asset_quick_code,
            "assetName": self.asset_name,
            "assetCategory": self.asset_category,
            "siteId": self.site_id,
            "site": self.site,
            "maintenanceType": self.maintenance_type,
            "intervalMonths": self.interval_months,
            "tasks": list(self.tasks),
            "responsiblePersonId": self.responsible_person_id,
            "responsibleLabel": self.responsible_label,
            "status": self.status,
            "statusLabel": self.status_label,
            "scheduledOn": _iso_date(self.scheduled_on),
            "lastCompletedOn": _iso_date(self.last_completed_on),
            "dueOn": _iso_date(self.due_on),
            "persisted": self.persisted,
            "createdAt": _iso_datetime(self.created_at),
            "updatedAt": _iso_datetime(self.updated_at),
        }


@dataclass(frozen=True)
class MaintenanceTemplatePage:
    items: tuple[MaintenanceTemplateView, ...]
    total: int
    limit: int
    offset: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "items": [item.as_payload() for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class MaintenancePlanPage:
    items: tuple[MaintenancePlanView, ...]
    total: int
    limit: int
    offset: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "items": [item.as_payload() for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class _Template:
    id: str
    category: str
    maintenance_type: str
    interval_months: int
    tasks: tuple[str, ...]
    responsible_person_id: str | None
    active: bool
    source: str
    created_at: datetime | None
    updated_at: datetime | None


@dataclass(frozen=True)
class _Effective:
    id: str
    asset_id: str
    maintenance_type: str
    interval_months: int
    tasks: tuple[str, ...]
    responsible_person_id: str | None
    status: str
    scheduled_on: date
    last_completed_on: date | None
    due_on: date
    persisted: bool
    created_at: datetime | None
    updated_at: datetime | None


class MaintenanceService:
    """Canonical preventive maintenance business layer."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        inventory: InventoryService | None = None,
        source: str = "internal",
        locale: str | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._locale = locale
        self._inventory = inventory or InventoryService(session, settings, locale=locale)
        self._source = _history_source(source)

    @property
    def label_locale(self) -> str:
        """Request locale for fixed state labels; workers get the install default."""
        if self._locale is None:
            from itsm.i18n.settings import read_installation_settings

            self._locale = read_installation_settings(self._session).default_locale
        return self._locale

    # ---------------------------------------------------------------- helpers
    def _catalog_categories(self) -> list[dict[str, Any]]:
        rows = self._inventory._catalog._items("categories")
        return [
            item
            for item in rows
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]
        ]

    def _category_key(self, raw: Any, catalog: Sequence[Mapping[str, Any]]) -> str | None:
        if not isinstance(raw, str) or not raw.strip():
            return None
        value = raw.strip()
        for item in catalog:
            if value.casefold() in {item["id"].casefold(), str(item.get("label", "")).casefold()}:
                return item["id"]
        alias = _LEGACY_CATEGORY_ALIASES.get(value.casefold())
        if alias is not None and any(item["id"] == alias for item in catalog):
            return alias
        return value

    def _default_template(self, category: str) -> _Template:
        interval = _DEFAULT_INTERVALS.get(category, _FALLBACK_INTERVAL)
        tasks = _DEFAULT_TASKS.get(category, _FALLBACK_TASKS)
        return _Template(
            id=template_id(category, DEFAULT_TYPE),
            category=category,
            maintenance_type=DEFAULT_TYPE,
            interval_months=interval,
            tasks=tasks,
            responsible_person_id=None,
            active=True,
            source="default",
            created_at=None,
            updated_at=None,
        )

    def _row_template(self, row: MaintenanceTemplate) -> _Template:
        return _Template(
            id=row.id,
            category=row.category,
            maintenance_type=row.maintenance_type,
            interval_months=int(row.interval_months),
            tasks=tuple(row.tasks or ()),
            responsible_person_id=row.responsible_person_id,
            active=bool(row.active),
            source="stored",
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _template_maps(
        self,
    ) -> tuple[dict[tuple[str, str], _Template], list[dict[str, Any]]]:
        catalog = self._catalog_categories()
        stored: dict[tuple[str, str], _Template] = {}
        for row in self._session.execute(select(MaintenanceTemplate)).scalars():
            stored[(row.category, row.maintenance_type)] = self._row_template(row)
        for item in catalog:
            key = (item["id"], DEFAULT_TYPE)
            if key not in stored:
                stored[key] = self._default_template(item["id"])
        return stored, catalog

    def _template_for(
        self,
        asset_category: Any,
        maintenance_type: str,
        templates: Mapping[tuple[str, str], _Template],
        catalog: Sequence[Mapping[str, Any]],
    ) -> _Template | None:
        category = self._category_key(asset_category, catalog)
        if category is None:
            return None
        record = templates.get((category, maintenance_type))
        if record is not None:
            return record
        if maintenance_type == DEFAULT_TYPE:
            return self._default_template(category)
        return None

    def _labels(self, person_ids: Iterable[str | None]) -> dict[str, str]:
        checked = {person_id for person_id in person_ids if person_id}
        if not checked:
            return {}
        rows = self._session.execute(
            select(DirectoryPerson.id, DirectoryPerson.name).where(DirectoryPerson.id.in_(checked))
        ).all()
        return {person_id: name for person_id, name in rows}

    def _person(
        self, principal: Principal, value: Any, *, required: bool
    ) -> tuple[str | None, str | None]:
        if value is _UNSET:
            return None, None
        if value is None:
            return None, None
        checked = _checked_uuid(value, "responsiblePersonId")
        if not required:
            row = self._session.get(DirectoryPerson, checked)
            if row is None:
                raise NotFound("responsible person not found")
            return row.id, row.name
        label = DirectoryService(self._session, self._settings).person_label(principal, checked)
        return checked, label

    def _asset(self, asset_id: Any, *, require_active: bool = True) -> Asset:
        checked = _checked_uuid(asset_id, "assetId")
        asset = self._session.get(Asset, checked)
        if asset is None:
            raise NotFound("asset not found")
        if require_active and asset.archived_at is not None:
            raise Conflict("asset is archived")
        return asset

    def _plan_key(self, plan_id_value: Any) -> str:
        return _checked_uuid(plan_id_value, "plan id")

    def _row_effective(self, row: MaintenancePlan) -> _Effective:
        return _Effective(
            id=row.id,
            asset_id=row.asset_id,
            maintenance_type=row.maintenance_type,
            interval_months=int(row.interval_months),
            tasks=tuple(row.tasks or ()),
            responsible_person_id=row.responsible_person_id,
            status=row.status,
            scheduled_on=row.scheduled_on,
            last_completed_on=row.last_completed_on,
            due_on=row.due_on,
            persisted=True,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _virtual_effective(
        self,
        asset: Asset,
        maintenance_type: str,
        templates: Mapping[tuple[str, str], _Template],
        catalog: Sequence[Mapping[str, Any]],
    ) -> _Effective | None:
        record = self._template_for(asset.category, maintenance_type, templates, catalog)
        if record is None or not record.active:
            return None
        scheduled_on = asset.created_at.date()
        return _Effective(
            id=plan_id(asset.id, maintenance_type),
            asset_id=asset.id,
            maintenance_type=maintenance_type,
            interval_months=record.interval_months,
            tasks=record.tasks,
            responsible_person_id=record.responsible_person_id,
            status=STATUS_ACTIVE,
            scheduled_on=scheduled_on,
            last_completed_on=None,
            due_on=add_months(scheduled_on, record.interval_months),
            persisted=False,
            created_at=None,
            updated_at=None,
        )

    def _view(
        self, effective: _Effective, asset: Asset, labels: Mapping[str, str]
    ) -> MaintenancePlanView:
        return MaintenancePlanView(
            id=effective.id,
            asset_id=asset.id,
            asset_quick_code=asset.quick_code,
            asset_name=asset.name,
            asset_category=asset.category,
            site_id=asset.site_id,
            site=asset.site,
            maintenance_type=effective.maintenance_type,
            interval_months=effective.interval_months,
            tasks=list(effective.tasks),
            responsible_person_id=effective.responsible_person_id,
            responsible_label=(
                labels.get(effective.responsible_person_id)
                if effective.responsible_person_id
                else None
            ),
            status=effective.status,
            status_label=state_label("api.maintenance.status", effective.status, self.label_locale),
            scheduled_on=effective.scheduled_on,
            last_completed_on=effective.last_completed_on,
            due_on=effective.due_on,
            persisted=effective.persisted,
            created_at=effective.created_at,
            updated_at=effective.updated_at,
        )

    def _template_view(
        self, record: _Template, labels: Mapping[str, str]
    ) -> MaintenanceTemplateView:
        return MaintenanceTemplateView(
            id=record.id,
            category=record.category,
            maintenance_type=record.maintenance_type,
            interval_months=record.interval_months,
            tasks=list(record.tasks),
            responsible_person_id=record.responsible_person_id,
            responsible_label=(
                labels.get(record.responsible_person_id) if record.responsible_person_id else None
            ),
            active=record.active,
            source=record.source,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def _ensure_row(self, effective: _Effective) -> MaintenancePlan:
        existing = self._session.get(MaintenancePlan, effective.id)
        if existing is not None:
            return existing
        row = MaintenancePlan(
            id=effective.id,
            asset_id=effective.asset_id,
            maintenance_type=effective.maintenance_type,
            interval_months=effective.interval_months,
            tasks=list(effective.tasks),
            responsible_person_id=effective.responsible_person_id,
            status=effective.status,
            scheduled_on=effective.scheduled_on,
            last_completed_on=effective.last_completed_on,
            due_on=effective.due_on,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def _resolve(
        self, plan_id_value: Any, *, include_archived: bool = False
    ) -> tuple[_Effective, Asset]:
        checked = self._plan_key(plan_id_value)
        row = self._session.get(MaintenancePlan, checked)
        if row is not None:
            asset = self._session.get(Asset, row.asset_id)
            if asset is None:
                raise NotFound("maintenance plan not found")
            return self._row_effective(row), asset
        templates, catalog = self._template_maps()
        statement = select(Asset)
        if not include_archived:
            statement = statement.where(Asset.archived_at.is_(None))
        for asset in self._session.execute(statement).scalars():
            effective = self._virtual_effective(asset, DEFAULT_TYPE, templates, catalog)
            if effective is not None and effective.id == checked:
                return effective, asset
        raise NotFound("maintenance plan not found")

    def _record_history(
        self,
        principal: Principal,
        asset: Asset,
        action: str,
        effective: _Effective,
        changes: Mapping[str, Any],
        notes: Any,
    ) -> None:
        self._inventory._record_history(
            principal,
            asset,
            action,
            changes=changes,
            notes=_notes(notes),
            source=self._source,
            entity_type="maintenance_plan",
            entity_id=effective.id,
        )

    # -------------------------------------------------------------- templates
    def list_templates(
        self,
        principal: Principal,
        *,
        category: str | None = None,
        limit: int = DEFAULT_LIMIT_MAINTENANCE,
        offset: int = 0,
    ) -> MaintenanceTemplatePage:
        """Read default and stored templates; ``config.general`` gates every read."""
        self._identity.authorize(principal, "config.general", resource="maintenance:templates")
        limit = _checked_limit(limit)
        offset = _checked_offset(offset)
        templates, catalog = self._template_maps()
        records = list(templates.values())
        if category is not None:
            key = self._category_key(_normalized_category(category), catalog)
            records = [record for record in records if record.category == key]
        records.sort(key=lambda record: (record.category, record.maintenance_type))
        total = len(records)
        page = records[offset : offset + limit]
        labels = self._labels(record.responsible_person_id for record in page)
        return MaintenanceTemplatePage(
            items=tuple(self._template_view(record, labels) for record in page),
            total=total,
            limit=limit,
            offset=offset,
        )

    @serialized
    def create_template(
        self,
        principal: Principal,
        *,
        category: Any,
        maintenance_type: Any = DEFAULT_TYPE,
        interval_months: Any,
        tasks: Any = None,
        responsible_person_id: Any = None,
        active: Any = True,
    ) -> MaintenanceTemplateView:
        """Create a template for a type that has no default yet.

        Every authoritative category already has a preconfigured ``preventivo``
        default; editing it uses :meth:`update_template`.
        """
        self._identity.authorize(principal, "config.general", resource="maintenance:templates")
        catalog = self._catalog_categories()
        key = self._category_key(_normalized_category(category), catalog)
        if key is None:
            raise ValidationFailed("unknown asset category")
        checked_type = _checked_type(maintenance_type)
        checked_interval = _checked_interval(interval_months)
        checked_tasks = _checked_tasks(tasks)
        person_id, person_label = self._person(principal, responsible_person_id, required=True)
        checked_active = _checked_bool(active, "active")
        checked_id = template_id(key, checked_type)
        if self._session.get(MaintenanceTemplate, checked_id) is not None or (
            checked_type == DEFAULT_TYPE
        ):
            raise Conflict("template already exists; update it instead")
        row = MaintenanceTemplate(
            id=checked_id,
            category=key,
            maintenance_type=checked_type,
            interval_months=checked_interval,
            tasks=list(checked_tasks),
            responsible_person_id=person_id,
            active=checked_active,
        )
        self._session.add(row)
        self._session.flush()
        labels = {person_id: person_label} if person_id and person_label else {}
        view = self._template_view(self._row_template(row), labels)
        self._identity.record_operation(
            principal,
            action="maintenance.template_created",
            resource=f"maintenance:template:{row.id}",
        )
        return view

    @serialized
    def update_template(
        self,
        principal: Principal,
        template_id_value: Any,
        *,
        interval_months: Any = _UNSET,
        tasks: Any = _UNSET,
        responsible_person_id: Any = _UNSET,
        active: Any = _UNSET,
    ) -> MaintenanceTemplateView:
        """Edit a stored template or materialize a category default on first edit."""
        self._identity.authorize(principal, "config.general", resource="maintenance:templates")
        checked_id = _checked_uuid(template_id_value, "template id")
        row = self._session.get(MaintenanceTemplate, checked_id)
        record = None
        if row is None:
            catalog = self._catalog_categories()
            record = next(
                (
                    self._default_template(item["id"])
                    for item in catalog
                    if template_id(item["id"], DEFAULT_TYPE) == checked_id
                ),
                None,
            )
            if record is None:
                raise NotFound("maintenance template not found")
        interval_value: Any = _UNSET
        if interval_months is not _UNSET:
            interval_value = _checked_interval(interval_months)
        task_values: Any = _UNSET
        if tasks is not _UNSET:
            task_values = _checked_tasks(tasks)
        person_id: Any = _UNSET
        if responsible_person_id is not _UNSET:
            person_id, _ = self._person(principal, responsible_person_id, required=True)
        active_value: Any = _UNSET
        if active is not _UNSET:
            active_value = _checked_bool(active, "active")
        if row is None:
            assert record is not None
            row = MaintenanceTemplate(
                id=record.id,
                category=record.category,
                maintenance_type=record.maintenance_type,
                interval_months=record.interval_months,
                tasks=list(record.tasks),
                responsible_person_id=record.responsible_person_id,
                active=record.active,
            )
            self._session.add(row)
        if interval_value is not _UNSET:
            row.interval_months = interval_value
        if task_values is not _UNSET:
            row.tasks = list(task_values)
        if person_id is not _UNSET:
            row.responsible_person_id = person_id
        if active_value is not _UNSET:
            row.active = active_value
        self._session.flush()
        labels = self._labels([row.responsible_person_id])
        view = self._template_view(self._row_template(row), labels)
        self._identity.record_operation(
            principal,
            action="maintenance.template_updated",
            resource=f"maintenance:template:{row.id}",
        )
        return view

    @serialized
    def delete_template(self, principal: Principal, template_id_value: Any) -> dict[str, Any]:
        """Remove one stored template; the category default becomes visible again."""
        self._identity.authorize(principal, "config.general", resource="maintenance:templates")
        checked_id = _checked_uuid(template_id_value, "template id")
        row = self._session.get(MaintenanceTemplate, checked_id)
        if row is None:
            catalog = self._catalog_categories()
            if any(template_id(item["id"], DEFAULT_TYPE) == checked_id for item in catalog):
                raise Conflict("a preconfigured default cannot be deleted; edit it instead")
            raise NotFound("maintenance template not found")
        self._session.delete(row)
        self._session.flush()
        self._identity.record_operation(
            principal,
            action="maintenance.template_deleted",
            resource=f"maintenance:template:{checked_id}",
        )
        return {"removed": True, "id": checked_id}

    # ------------------------------------------------------------------ plans
    def _matches_filters(
        self,
        effective: _Effective,
        asset: Asset,
        *,
        state: str | None,
        status: str | None,
        due_from: date | None,
        due_to: date | None,
        completed_from: date | None,
        completed_to: date | None,
        upcoming_days: int,
        today: date,
    ) -> bool:
        if status is not None and effective.status != status:
            return False
        if state is not None:
            if effective.status == STATUS_CANCELLED:
                return False
            if state == "pending":
                pass
            elif state == "overdue":
                if effective.due_on >= today:
                    return False
            elif state == "upcoming":
                horizon = date.fromordinal(today.toordinal() + upcoming_days)
                if not (today <= effective.due_on <= horizon):
                    return False
        if due_from is not None and effective.due_on < due_from:
            return False
        if due_to is not None and effective.due_on > due_to:
            return False
        if completed_from is not None and (
            effective.last_completed_on is None or effective.last_completed_on < completed_from
        ):
            return False
        return not (
            completed_to is not None
            and (effective.last_completed_on is None or effective.last_completed_on > completed_to)
        )

    def list_plans(
        self,
        principal: Principal,
        *,
        state: Any = None,
        status: Any = None,
        category: Any = None,
        site: Any = None,
        site_id: Any = None,
        asset_id: Any = None,
        maintenance_type: Any = None,
        due_from: Any = None,
        due_to: Any = None,
        completed_from: Any = None,
        completed_to: Any = None,
        upcoming_days: Any = 30,
        archived: Any = False,
        limit: Any = DEFAULT_LIMIT_MAINTENANCE,
        offset: Any = 0,
    ) -> MaintenancePlanPage:
        """Read effective plans with bounded filters and pagination; never writes."""
        self._identity.authorize(principal, "assets.view", resource="inventory:assets")
        if state is not None and state not in PLAN_STATES:
            raise ValidationFailed("state must be pending, upcoming or overdue")
        if status is not None and status not in PLAN_STATUSES:
            raise ValidationFailed("status must be active, postponed or cancelled")
        if (
            not isinstance(upcoming_days, int)
            or isinstance(upcoming_days, bool)
            or not (0 <= upcoming_days <= MAX_UPCOMING_DAYS)
        ):
            raise ValidationFailed(f"upcomingDays must be between 0 and {MAX_UPCOMING_DAYS}")
        if not isinstance(archived, bool):
            raise ValidationFailed("archived must be a boolean")
        limit_value = _checked_limit(limit)
        offset_value = _checked_offset(offset)
        if maintenance_type is not None:
            maintenance_type = _checked_type(maintenance_type)
        if site_id is not None:
            site_id = _checked_uuid(site_id, "siteId")
        due_from_value = _checked_optional_date(due_from, "dueFrom")
        due_to_value = _checked_optional_date(due_to, "dueTo")
        completed_from_value = _checked_optional_date(completed_from, "completedFrom")
        completed_to_value = _checked_optional_date(completed_to, "completedTo")
        if due_from_value and due_to_value and due_from_value > due_to_value:
            raise ValidationFailed("dueFrom cannot be after dueTo")
        if (
            completed_from_value
            and completed_to_value
            and completed_from_value > completed_to_value
        ):
            raise ValidationFailed("completedFrom cannot be after completedTo")

        templates, catalog = self._template_maps()
        statement = select(Asset).where(
            Asset.archived_at.is_(None) if not archived else Asset.archived_at.is_not(None)
        )
        if asset_id is not None:
            asset = self._asset(asset_id, require_active=False)
            if (asset.archived_at is not None) != archived:
                return MaintenancePlanPage(
                    items=(), total=0, limit=limit_value, offset=offset_value
                )
            statement = statement.where(Asset.id == asset.id)
        if category is not None:
            requested = _normalized_category(category)
            key = self._category_key(requested, catalog)
            candidates = {requested.casefold()}
            if key is not None:
                candidates.add(key.casefold())
                for item in catalog:
                    if item["id"] == key:
                        candidates.add(str(item.get("label", "")).casefold())
            statement = statement.where(func.lower(Asset.category).in_(candidates))
        if site is not None:
            if not isinstance(site, str) or not site.strip():
                raise ValidationFailed("site must be non-empty text")
            statement = statement.where(func.lower(Asset.site) == site.strip().casefold())
        if site_id is not None:
            statement = statement.where(Asset.site_id == site_id)
        statement = statement.order_by(Asset.quick_code.asc(), Asset.id.asc())
        assets = list(self._session.execute(statement).scalars())
        asset_ids = [asset.id for asset in assets]
        rows_by_asset: dict[str, list[MaintenancePlan]] = {}
        if asset_ids:
            for row in self._session.execute(
                select(MaintenancePlan).where(MaintenancePlan.asset_id.in_(asset_ids))
            ).scalars():
                rows_by_asset.setdefault(row.asset_id, []).append(row)

        today = _today()
        effective_rows: list[tuple[_Effective, Asset]] = []
        for asset in assets:
            persisted = rows_by_asset.get(asset.id, [])
            persisted_types = {row.maintenance_type for row in persisted}
            for row in persisted:
                if maintenance_type is not None and row.maintenance_type != maintenance_type:
                    continue
                effective_rows.append((self._row_effective(row), asset))
            if maintenance_type is not None and maintenance_type in persisted_types:
                continue
            if maintenance_type is not None and maintenance_type != DEFAULT_TYPE:
                continue
            if DEFAULT_TYPE in persisted_types:
                continue
            virtual = self._virtual_effective(asset, DEFAULT_TYPE, templates, catalog)
            if virtual is not None:
                effective_rows.append((virtual, asset))

        filtered = [
            (effective, asset)
            for effective, asset in effective_rows
            if self._matches_filters(
                effective,
                asset,
                state=state,
                status=status,
                due_from=due_from_value,
                due_to=due_to_value,
                completed_from=completed_from_value,
                completed_to=completed_to_value,
                upcoming_days=upcoming_days,
                today=today,
            )
        ]
        filtered.sort(key=lambda item: (item[0].due_on, item[0].id))
        total = len(filtered)
        page = filtered[offset_value : offset_value + limit_value]
        labels = self._labels(effective.responsible_person_id for effective, _ in page)
        return MaintenancePlanPage(
            items=tuple(self._view(effective, asset, labels) for effective, asset in page),
            total=total,
            limit=limit_value,
            offset=offset_value,
        )

    def get_plan(self, principal: Principal, plan_id_value: Any) -> MaintenancePlanView:
        """Read one effective plan by its stable id."""
        self._identity.authorize(principal, "assets.view", resource="inventory:assets")
        effective, asset = self._resolve(plan_id_value, include_archived=True)
        self._identity.authorize(principal, "assets.view", resource=f"asset:{asset.id}")
        labels = self._labels([effective.responsible_person_id])
        return self._view(effective, asset, labels)

    @serialized
    def create_plan(
        self,
        principal: Principal,
        *,
        asset_id: Any,
        maintenance_type: Any = DEFAULT_TYPE,
        interval_months: Any = _UNSET,
        tasks: Any = _UNSET,
        responsible_person_id: Any = _UNSET,
        due_on: Any = None,
        last_completed_on: Any = None,
    ) -> MaintenancePlanView:
        """Persist an explicit override, or the first plan of a type."""
        checked_type = _checked_type(maintenance_type)
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        templates, catalog = self._template_maps()
        template = self._template_for(asset.category, checked_type, templates, catalog)
        existing = self._session.get(MaintenancePlan, plan_id(asset.id, checked_type))
        if existing is not None:
            raise Conflict("a plan for this asset and maintenance type already exists")

        if interval_months is _UNSET:
            if template is None:
                raise ValidationFailed("intervalMonths is required when no template exists")
            interval_value = template.interval_months
        else:
            interval_value = _checked_interval(interval_months)
        if tasks is _UNSET:
            task_values = template.tasks if template is not None else ()
        else:
            task_values = _checked_tasks(tasks)
        if responsible_person_id is _UNSET:
            person_id = template.responsible_person_id if template is not None else None
            person_label = None
        else:
            person_id, person_label = self._person(principal, responsible_person_id, required=True)
        completed_value = _checked_optional_date(last_completed_on, "lastCompletedOn")
        if completed_value is not None:
            scheduled_on = completed_value
        elif template is not None:
            scheduled_on = asset.created_at.date()
        else:
            scheduled_on = _today()
        due_value = _checked_optional_date(due_on, "dueOn")
        if due_value is None:
            due_value = add_months(
                completed_value if completed_value is not None else scheduled_on,
                interval_value,
            )
        row = MaintenancePlan(
            id=plan_id(asset.id, checked_type),
            asset_id=asset.id,
            maintenance_type=checked_type,
            interval_months=interval_value,
            tasks=list(task_values),
            responsible_person_id=person_id,
            status=STATUS_ACTIVE,
            scheduled_on=scheduled_on,
            last_completed_on=completed_value,
            due_on=due_value,
        )
        self._session.add(row)
        self._session.flush()
        effective = self._row_effective(row)
        self._record_history(
            principal,
            asset,
            "maintenance_plan_created",
            effective,
            {
                "maintenanceType": {"old": None, "new": checked_type},
                "intervalMonths": {"old": None, "new": interval_value},
                "scheduledOn": {"old": None, "new": scheduled_on.isoformat()},
                "lastCompletedOn": {
                    "old": None,
                    "new": completed_value.isoformat() if completed_value else None,
                },
                "dueOn": {"old": None, "new": due_value.isoformat()},
            },
            None,
        )
        labels = self._labels([person_id])
        if person_id and person_label:
            labels[person_id] = person_label
        view = self._view(effective, asset, labels)
        self._identity.record_operation(
            principal,
            action="maintenance.plan_created",
            resource=f"maintenance:plan:{row.id}",
        )
        return view

    @serialized
    def update_plan(
        self,
        principal: Principal,
        plan_id_value: Any,
        *,
        interval_months: Any = _UNSET,
        tasks: Any = _UNSET,
        responsible_person_id: Any = _UNSET,
        due_on: Any = _UNSET,
    ) -> MaintenancePlanView:
        """Materialize or edit an explicit plan; template edits never mutate it."""
        effective, asset = self._resolve(plan_id_value)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        interval_value: Any = _UNSET
        if interval_months is not _UNSET:
            interval_value = _checked_interval(interval_months)
        task_values: Any = _UNSET
        if tasks is not _UNSET:
            task_values = _checked_tasks(tasks)
        person_id: Any = _UNSET
        if responsible_person_id is not _UNSET:
            person_id, _ = self._person(principal, responsible_person_id, required=True)
        due_value: Any = _UNSET
        if due_on is not _UNSET:
            due_value = _checked_date(due_on, "dueOn")
        row = self._ensure_row(effective)
        changes: dict[str, Any] = {}
        if effective.persisted is False:
            changes["persisted"] = {"old": False, "new": True}
        if interval_value is not _UNSET:
            changes["intervalMonths"] = {"old": row.interval_months, "new": interval_value}
            row.interval_months = interval_value
            if due_value is _UNSET:
                base = row.last_completed_on or row.scheduled_on
                new_due = add_months(base, interval_value)
                changes["dueOn"] = {"old": row.due_on.isoformat(), "new": new_due.isoformat()}
                row.due_on = new_due
        if task_values is not _UNSET:
            changes["tasks"] = {"old": list(row.tasks or []), "new": list(task_values)}
            row.tasks = list(task_values)
        if person_id is not _UNSET:
            changes["responsiblePersonId"] = {
                "old": row.responsible_person_id,
                "new": person_id,
            }
            row.responsible_person_id = person_id
        if due_value is not _UNSET and due_value != row.due_on:
            changes["dueOn"] = {"old": row.due_on.isoformat(), "new": due_value.isoformat()}
            row.due_on = due_value
        self._session.flush()
        if changes:
            self._record_history(
                principal, asset, "maintenance_plan_updated", effective, changes, None
            )
        labels = self._labels([row.responsible_person_id])
        view = self._view(self._row_effective(row), asset, labels)
        self._identity.record_operation(
            principal,
            action="maintenance.plan_updated",
            resource=f"maintenance:plan:{row.id}",
        )
        return view

    def _complete_core(
        self,
        principal: Principal,
        effective: _Effective,
        asset: Asset,
        *,
        completed_on: Any,
        notes: Any,
    ) -> MaintenancePlanView:
        if effective.status == STATUS_CANCELLED:
            raise Conflict("a cancelled plan cannot be completed")
        today = _today()
        completed_value = (
            today if completed_on is None else _checked_date(completed_on, "completedOn")
        )
        if completed_value > today:
            raise ValidationFailed("completedOn cannot be in the future")
        if (
            effective.last_completed_on is not None
            and completed_value <= effective.last_completed_on
        ):
            raise Conflict("completedOn must be after the last completion")
        row = self._ensure_row(effective)
        old_status = row.status
        old_last = row.last_completed_on
        old_due = row.due_on
        row.status = STATUS_ACTIVE
        row.last_completed_on = completed_value
        row.due_on = add_months(completed_value, row.interval_months)
        self._session.flush()
        self._record_history(
            principal,
            asset,
            "maintenance_completed",
            self._row_effective(row),
            {
                "status": {"old": old_status, "new": STATUS_ACTIVE},
                "lastCompletedOn": {
                    "old": _iso_date(old_last),
                    "new": completed_value.isoformat(),
                },
                "dueOn": {"old": old_due.isoformat(), "new": row.due_on.isoformat()},
            },
            notes,
        )
        labels = self._labels([row.responsible_person_id])
        return self._view(self._row_effective(row), asset, labels)

    @serialized
    def complete_plan(
        self,
        principal: Principal,
        plan_id_value: Any,
        *,
        completed_on: Any = None,
        notes: Any = None,
    ) -> MaintenancePlanView:
        """Complete preventive work and anchor the next due date to that date."""
        effective, asset = self._resolve(plan_id_value)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        view = self._complete_core(
            principal, effective, asset, completed_on=completed_on, notes=notes
        )
        self._identity.record_operation(
            principal,
            action="maintenance.plan_completed",
            resource=f"maintenance:plan:{view.id}",
        )
        return view

    def complete_in_transaction(
        self,
        principal: Principal,
        plan_id_value: Any,
        *,
        completed_on: Any = None,
        notes: Any = None,
    ) -> MaintenancePlanView:
        """Complete inside a caller-owned transaction: no audit, no commit.

        The intervention domain uses this seam so its corrective record and the
        preventive cycle update share one transaction and one terminal audit.
        It is not a public mutator and is never exposed by the HTTP router.
        """
        effective, asset = self._resolve(plan_id_value)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        return self._complete_core(
            principal, effective, asset, completed_on=completed_on, notes=notes
        )

    @serialized
    def postpone_plan(
        self,
        principal: Principal,
        plan_id_value: Any,
        *,
        due_on: Any,
        notes: Any = None,
    ) -> MaintenancePlanView:
        """Move the pending due date only; completion facts stay untouched."""
        effective, asset = self._resolve(plan_id_value)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        if effective.status == STATUS_CANCELLED:
            raise Conflict("a cancelled plan cannot be postponed")
        due_value = _checked_date(due_on, "dueOn")
        row = self._ensure_row(effective)
        old_status = row.status
        old_due = row.due_on
        row.status = STATUS_POSTPONED
        row.due_on = due_value
        self._session.flush()
        self._record_history(
            principal,
            asset,
            "maintenance_postponed",
            self._row_effective(row),
            {
                "status": {"old": old_status, "new": STATUS_POSTPONED},
                "dueOn": {"old": old_due.isoformat(), "new": due_value.isoformat()},
            },
            notes,
        )
        labels = self._labels([row.responsible_person_id])
        view = self._view(self._row_effective(row), asset, labels)
        self._identity.record_operation(
            principal,
            action="maintenance.plan_postponed",
            resource=f"maintenance:plan:{row.id}",
        )
        return view

    @serialized
    def cancel_plan(
        self,
        principal: Principal,
        plan_id_value: Any,
        *,
        notes: Any = None,
    ) -> MaintenancePlanView:
        """Cancel a plan without inventing a completion or a new due date."""
        effective, asset = self._resolve(plan_id_value)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        if effective.status == STATUS_CANCELLED:
            raise Conflict("a cancelled plan cannot be cancelled again")
        row = self._ensure_row(effective)
        old_status = row.status
        old_due = row.due_on
        old_last = row.last_completed_on
        row.status = STATUS_CANCELLED
        self._session.flush()
        self._record_history(
            principal,
            asset,
            "maintenance_cancelled",
            self._row_effective(row),
            {
                "status": {"old": old_status, "new": STATUS_CANCELLED},
                "dueOn": {"old": old_due.isoformat(), "new": old_due.isoformat()},
                "lastCompletedOn": {
                    "old": _iso_date(old_last),
                    "new": _iso_date(old_last),
                },
            },
            notes,
        )
        labels = self._labels([row.responsible_person_id])
        view = self._view(self._row_effective(row), asset, labels)
        self._identity.record_operation(
            principal,
            action="maintenance.plan_cancelled",
            resource=f"maintenance:plan:{row.id}",
        )
        return view

    # --------------------------------------------------------------- scheduler
    def iter_due_plans(
        self,
        as_of: Any,
        *,
        horizon_days: Any = 30,
        limit: Any = SCHEDULER_LIMIT,
        offset: Any = 0,
    ) -> MaintenancePlanPage:
        """Trusted, read-only due scan with stable pagination for the scheduler.

        No principal is accepted and no write, history row or audit event is
        produced. Reminder persistence belongs to the scheduler adapter.
        """
        checked_as_of = _checked_date(as_of, "as_of")
        if (
            not isinstance(horizon_days, int)
            or isinstance(horizon_days, bool)
            or not (0 <= horizon_days <= MAX_UPCOMING_DAYS)
        ):
            raise ValidationFailed(f"horizon_days must be between 0 and {MAX_UPCOMING_DAYS}")
        limit_value = _checked_limit(limit)
        offset_value = _checked_offset(offset)
        templates, catalog = self._template_maps()
        assets = list(
            self._session.execute(
                select(Asset).where(Asset.archived_at.is_(None)).order_by(Asset.id.asc())
            ).scalars()
        )
        asset_ids = [asset.id for asset in assets]
        rows_by_asset: dict[str, list[MaintenancePlan]] = {}
        if asset_ids:
            for row in self._session.execute(
                select(MaintenancePlan).where(MaintenancePlan.asset_id.in_(asset_ids))
            ).scalars():
                rows_by_asset.setdefault(row.asset_id, []).append(row)
        horizon = date.fromordinal(checked_as_of.toordinal() + horizon_days)
        due: list[tuple[_Effective, Asset]] = []
        for asset in assets:
            persisted = rows_by_asset.get(asset.id, [])
            persisted_types = {row.maintenance_type for row in persisted}
            candidates = [self._row_effective(row) for row in persisted]
            if DEFAULT_TYPE not in persisted_types:
                virtual = self._virtual_effective(asset, DEFAULT_TYPE, templates, catalog)
                if virtual is not None:
                    candidates.append(virtual)
            for effective in candidates:
                if effective.status == STATUS_CANCELLED:
                    continue
                if effective.due_on <= horizon:
                    due.append((effective, asset))
        due.sort(key=lambda item: (item[0].due_on, item[0].id))
        total = len(due)
        page = due[offset_value : offset_value + limit_value]
        labels = self._labels(effective.responsible_person_id for effective, _ in page)
        return MaintenancePlanPage(
            items=tuple(self._view(effective, asset, labels) for effective, asset in page),
            total=total,
            limit=limit_value,
            offset=offset_value,
        )


def iter_due_plans(
    session: Session,
    settings: Settings,
    *,
    as_of: date,
    horizon_days: int = 30,
    limit: int = SCHEDULER_LIMIT,
    offset: int = 0,
) -> MaintenancePlanPage:
    """Module-level trusted scheduler seam; wraps the canonical service read."""
    return MaintenanceService(session, settings).iter_due_plans(
        as_of,
        horizon_days=horizon_days,
        limit=limit,
        offset=offset,
    )
