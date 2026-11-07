"""Authorized technical interventions and incident lifecycle over SQL.

The module owns the operational rules for corrective jobs and incidents:
references are validated before any mutation, money stays decimal, every
mutation appends structured asset history plus one incident actuation event,
and all writes share the canonical inventory mutex and one business audit
commit. Linked preventive completion uses the canonical maintenance service
inside the same transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from itsm.attachments.models import Attachment
from itsm.config import Settings
from itsm.directory.models import DirectoryPerson
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    Principal,
    ValidationFailed,
)
from itsm.interventions.models import (
    Incident,
    IncidentAsset,
    IncidentEvent,
    Intervention,
    InterventionAttachment,
)
from itsm.inventory.codes import serialized
from itsm.inventory.models import Asset, AssetHistory
from itsm.inventory.service import InventoryService

INTERVENTION_TYPES: tuple[str, ...] = (
    "preventive",
    "corrective",
    "inspection",
    "installation",
    "other",
)
DEFAULT_INTERVENTION_TYPE = "corrective"
INTERVENTION_STATUSES: tuple[str, ...] = ("open", "in_progress", "completed", "cancelled")
DEFAULT_INTERVENTION_STATUS = INTERVENTION_STATUSES[0]
INTERVENTION_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "open": frozenset({"in_progress", "completed", "cancelled"}),
    "in_progress": frozenset({"completed", "cancelled"}),
    "completed": frozenset(),
    "cancelled": frozenset(),
}

INCIDENT_PRIORITIES: tuple[str, ...] = ("low", "normal", "high", "critical")
DEFAULT_INCIDENT_PRIORITY = "normal"
INCIDENT_STATUSES: tuple[str, ...] = ("open", "in_progress", "resolved", "closed")
ACTIVE_INCIDENT_STATUSES: tuple[str, ...] = ("open", "in_progress")

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
AFFECTED_MAX = 50
PARTS_MAX = 50
ATTACHMENTS_MAX = 20
DESCRIPTION_MAX = 2000
NOTES_MAX = 2000
PART_NAME_MAX = 120
QUANTITY_MAX = 1_000_000
COST_LIMIT = Decimal("1000000000")
COST_QUANTUM = Decimal("0.01")
TOKEN_BYTES = 32

_INTERVENTION_CREATE_KEYS = frozenset(
    {
        "assetId",
        "type",
        "description",
        "technicianPersonId",
        "occurredOn",
        "status",
        "notes",
        "parts",
        "laborCost",
        "attachmentIds",
        "incidentId",
        "planId",
    }
)
_INTERVENTION_UPDATE_KEYS = frozenset(
    {
        "type",
        "description",
        "technicianPersonId",
        "occurredOn",
        "status",
        "notes",
        "parts",
        "laborCost",
        "attachmentIds",
    }
)
_INCIDENT_CREATE_KEYS = frozenset(
    {
        "primaryAssetId",
        "description",
        "priority",
        "affectedAssetIds",
        "responsiblePersonId",
        "openedOn",
    }
)


# --------------------------------------------------------------------- helpers
def _clip(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _text(
    value: Any,
    field: str,
    *,
    max_length: int,
    required: bool = False,
) -> str | None:
    if value is None:
        if required:
            raise ValidationFailed(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} must be text")
    text = value.strip()
    if not text:
        if required:
            raise ValidationFailed(f"{field} is required")
        return None
    if len(text) > max_length:
        raise ValidationFailed(f"{field} must be at most {max_length} characters")
    return text


def _uuid_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 36:
        raise ValidationFailed(f"{field} must be a UUID")
    try:
        return str(UUID(value))
    except ValueError:
        raise ValidationFailed(f"{field} must be a UUID") from None


def _optional_uuid_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _uuid_text(value, field)


def _enum(value: Any, field: str, allowed: tuple[str, ...], default: str) -> str:
    if value is None:
        return default
    if value not in allowed:
        raise ValidationFailed(f"{field} must be one of " + ", ".join(allowed))
    return value


def _date_value(value: Any, field: str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValidationFailed(f"{field} must be an ISO date (YYYY-MM-DD)") from None


def _date_arg(value: Any, field: str) -> date | None:
    if value is None:
        return None
    return _date_value(value, field)


def _bounded_page(limit: Any, offset: Any) -> tuple[int, int]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValidationFailed("offset must be zero or greater")
    return limit, offset


def _money(value: Any, field: str) -> Decimal | None:
    """Parse one canonical two-decimal amount; floats are never accumulated."""
    if value is None:
        return None
    if isinstance(value, (bool, float)):
        raise ValidationFailed(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value) if isinstance(value, Decimal) else Decimal(str(value).strip())
    except InvalidOperation, ValueError:
        raise ValidationFailed(f"{field} must be a decimal amount") from None
    if not parsed.is_finite() or parsed < 0 or parsed > COST_LIMIT:
        raise ValidationFailed(f"{field} must be a nonnegative decimal below {COST_LIMIT}")
    quantized = parsed.quantize(COST_QUANTUM)
    if quantized != parsed:
        raise ValidationFailed(f"{field} must have at most two decimals")
    return quantized


def _money_text(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value.quantize(COST_QUANTUM), "f")


def _parts(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValidationFailed("parts must be a list")
    if len(value) > PARTS_MAX:
        raise ValidationFailed(f"parts must contain at most {PARTS_MAX} entries")
    prepared: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValidationFailed("each part must be an object with name and quantity")
        unknown = set(item) - {"name", "quantity", "unitCost"}
        if unknown:
            raise ValidationFailed("each part accepts only name, quantity and unitCost")
        name = _text(item.get("name"), "part name", max_length=PART_NAME_MAX, required=True)
        quantity = item.get("quantity")
        if (
            isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or not 1 <= quantity <= QUANTITY_MAX
        ):
            raise ValidationFailed(f"part quantity must be an integer from 1 to {QUANTITY_MAX}")
        entry: dict[str, Any] = {"name": name, "quantity": quantity}
        unit_cost = _money(item.get("unitCost"), "part unitCost")
        if unit_cost is not None:
            entry["unitCost"] = _money_text(unit_cost)
        prepared.append(entry)
    return prepared


def _parts_cost(parts: Sequence[Mapping[str, Any]]) -> Decimal | None:
    total: Decimal | None = None
    for part in parts:
        unit = part.get("unitCost")
        if unit is None:
            continue
        amount = Decimal(str(unit)) * int(part["quantity"])
        total = amount if total is None else total + amount
    return total


def _total_cost(labor_cost: str | None, parts_cost: Decimal | None) -> Decimal | None:
    labor = Decimal(labor_cost) if labor_cost is not None else None
    if labor is None and parts_cost is None:
        return None
    return (labor or Decimal("0")) + (parts_cost or Decimal("0"))


def _iso(value: date | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return as_utc(value).isoformat()
    return value.isoformat()


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------- views
@dataclass(frozen=True)
class InterventionView:
    """One intervention payload; costs are calculated from canonical storage."""

    id: str
    asset_id: str
    asset_name: str | None
    asset_quick_code: str | None
    type: str
    description: str | None
    technician_person_id: str | None
    technician_name: str | None
    occurred_on: date
    status: str
    notes: str | None
    parts: tuple[Mapping[str, Any], ...]
    labor_cost: str | None
    parts_cost: str | None
    total_cost: str | None
    incident_id: str | None
    plan_id: str | None
    attachments: tuple[Mapping[str, Any], ...]
    created_by: str | None
    created_at: datetime
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "assetId": self.asset_id,
            "assetName": self.asset_name,
            "assetQuickCode": self.asset_quick_code,
            "type": self.type,
            "description": self.description,
            "technicianPersonId": self.technician_person_id,
            "technicianName": self.technician_name,
            "occurredOn": _iso(self.occurred_on),
            "status": self.status,
            "notes": self.notes,
            "parts": [dict(part) for part in self.parts],
            "laborCost": self.labor_cost,
            "partsCost": self.parts_cost,
            "totalCost": self.total_cost,
            "incidentId": self.incident_id,
            "planId": self.plan_id,
            "attachments": [dict(item) for item in self.attachments],
            "createdBy": self.created_by,
            "createdAt": _iso(self.created_at),
            "updatedAt": _iso(self.updated_at),
        }


@dataclass(frozen=True)
class InterventionPage:
    items: tuple[InterventionView, ...]
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
class CostSummary:
    total_cost: str | None
    counted_interventions: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "totalCost": self.total_cost,
            "countedInterventions": self.counted_interventions,
        }


@dataclass(frozen=True)
class IncidentView:
    id: str
    description: str
    priority: str
    status: str
    primary_asset_id: str
    primary_asset_name: str | None
    primary_asset_quick_code: str | None
    affected_asset_ids: tuple[str, ...]
    responsible_person_id: str | None
    responsible_name: str | None
    opened_on: date
    resolved_at: datetime | None
    closed_at: datetime | None
    revision: int
    created_at: datetime
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "priority": self.priority,
            "status": self.status,
            "primaryAssetId": self.primary_asset_id,
            "primaryAssetName": self.primary_asset_name,
            "primaryAssetQuickCode": self.primary_asset_quick_code,
            "affectedAssetIds": list(self.affected_asset_ids),
            "responsiblePersonId": self.responsible_person_id,
            "responsibleName": self.responsible_name,
            "openedOn": _iso(self.opened_on),
            "resolvedAt": _iso(self.resolved_at),
            "closedAt": _iso(self.closed_at),
            "revision": self.revision,
            "createdAt": _iso(self.created_at),
            "updatedAt": _iso(self.updated_at),
        }


@dataclass(frozen=True)
class IncidentEventView:
    id: str
    sequence: int
    action: str
    from_status: str | None
    to_status: str | None
    note: str | None
    changes: Mapping[str, Any] | None
    actor_id: str | None
    actor_username: str | None
    source: str
    created_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sequence": self.sequence,
            "action": self.action,
            "fromStatus": self.from_status,
            "toStatus": self.to_status,
            "note": self.note,
            "changes": None if self.changes is None else dict(self.changes),
            "actorId": self.actor_id,
            "actorUsername": self.actor_username,
            "source": self.source,
            "createdAt": _iso(self.created_at),
        }


@dataclass(frozen=True)
class IncidentDetailView:
    incident: IncidentView
    affected_assets: tuple[Mapping[str, Any], ...]
    events: tuple[IncidentEventView, ...]
    interventions: tuple[InterventionView, ...]
    interventions_total: int
    costs: CostSummary
    resolution_prepared: bool
    resolution_prepared_at: datetime | None
    resolution_prepared_by: str | None

    def as_payload(self) -> dict[str, Any]:
        return {
            **self.incident.as_payload(),
            "affectedAssets": [dict(item) for item in self.affected_assets],
            "events": [event.as_payload() for event in self.events],
            "interventions": [item.as_payload() for item in self.interventions],
            "interventionsTotal": self.interventions_total,
            "costs": self.costs.as_payload(),
            "resolution": {
                "prepared": self.resolution_prepared,
                "preparedAt": _iso(self.resolution_prepared_at),
                "preparedBy": self.resolution_prepared_by,
            },
        }


@dataclass(frozen=True)
class IncidentPage:
    items: tuple[IncidentView, ...]
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
class ResolutionSuggestion:
    incident_id: str
    token: str
    revision: int
    prepared_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "incidentId": self.incident_id,
            "token": self.token,
            "revision": self.revision,
            "preparedAt": _iso(self.prepared_at),
        }


@dataclass(frozen=True)
class TechnicalHistoryPage:
    asset_id: str
    items: tuple[Mapping[str, Any], ...]
    total: int
    limit: int
    offset: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "assetId": self.asset_id,
            "items": [dict(item) for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
        }


# --------------------------------------------------------------------- service
class InterventionService:
    """Single implementation of intervention and incident rules for every door."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        source: str = "rest",
        plan_validator: Callable[[Principal, str], None] | None = None,
        completion_hook: Callable[[Principal, Intervention], None] | None = None,
    ):
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._inventory = InventoryService(
            session, settings, identity=self._identity, source=source
        )
        self._source = source
        from itsm.maintenance.service import MaintenanceService

        self._maintenance = MaintenanceService(
            session, settings, identity=self._identity, source=source
        )
        self._plan_validator = plan_validator or self._maintenance.get_plan
        self._completion_hook = completion_hook or self._complete_linked_plan

    def _complete_linked_plan(self, principal: Principal, row: Intervention) -> None:
        self._maintenance.complete_in_transaction(
            principal, row.plan_id, completed_on=row.occurred_on, notes=row.notes
        )

    # ------------------------------------------------------------- references
    def _asset(self, asset_id: Any) -> Asset:
        return self._inventory._asset(asset_id)

    def _assets(self, asset_ids: Sequence[str]) -> dict[str, Asset]:
        keys = sorted({asset_id for asset_id in asset_ids if asset_id})
        if not keys:
            return {}
        rows = self._session.execute(select(Asset).where(Asset.id.in_(keys))).scalars()
        return {row.id: row for row in rows}

    def _person(self, value: Any, field: str) -> DirectoryPerson:
        person_id = _uuid_text(value, field)
        row = self._session.get(DirectoryPerson, person_id)
        if row is None:
            raise ValidationFailed(f"{field} does not reference a directory person")
        if row.status != "active":
            raise ValidationFailed(f"{field} must reference an active directory person")
        return row

    def _person_names(self, person_ids: Sequence[str]) -> dict[str, str]:
        keys = sorted({value for value in person_ids if value})
        if not keys:
            return {}
        rows = self._session.execute(
            select(DirectoryPerson).where(DirectoryPerson.id.in_(keys))
        ).scalars()
        return {row.id: row.name for row in rows}

    def _intervention(self, intervention_id: Any) -> Intervention:
        identifier = _uuid_text(intervention_id, "intervention id")
        row = self._session.get(Intervention, identifier)
        if row is None:
            raise NotFound("intervention not found")
        return row

    def _incident(self, incident_id: Any) -> Incident:
        identifier = _uuid_text(incident_id, "incident id")
        row = self._session.get(Incident, identifier)
        if row is None:
            raise NotFound("incident not found")
        return row

    def _attachments(self, asset_id: str, value: Any) -> tuple[Attachment, ...]:
        if value is None:
            return ()
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise ValidationFailed("attachmentIds must be a list")
        if len(value) > ATTACHMENTS_MAX:
            raise ValidationFailed(f"attachmentIds must contain at most {ATTACHMENTS_MAX} entries")
        ordered: list[str] = []
        for item in value:
            identifier = _uuid_text(item, "attachmentIds must contain attachment UUIDs")
            if identifier in ordered:
                raise ValidationFailed("attachmentIds must be unique")
            ordered.append(identifier)
        if not ordered:
            return ()
        rows = self._session.execute(
            select(Attachment).where(
                Attachment.id.in_(ordered),
                Attachment.asset_id == asset_id,
                Attachment.deleted_at.is_(None),
            )
        ).scalars()
        by_id = {row.id: row for row in rows}
        if len(by_id) != len(ordered):
            raise ValidationFailed(
                "attachmentIds must reference existing attachments of the intervention asset"
            )
        return tuple(by_id[identifier] for identifier in ordered)

    def _affected(self, value: Any, primary_id: str) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise ValidationFailed("affectedAssetIds must be a list")
        if len(value) > AFFECTED_MAX:
            raise ValidationFailed(f"affectedAssetIds must contain at most {AFFECTED_MAX} entries")
        ordered: list[str] = []
        for item in value:
            identifier = _uuid_text(item, "affectedAssetIds must contain asset UUIDs")
            if identifier in ordered:
                raise ValidationFailed("affectedAssetIds must be unique")
            if identifier == primary_id:
                raise ValidationFailed("the primary asset cannot also be an affected asset")
            self._asset(identifier)
            ordered.append(identifier)
        return ordered

    def _incident_link(self, value: Any) -> Incident | None:
        if value is None:
            return None
        identifier = _uuid_text(value, "incidentId")
        row = self._session.get(Incident, identifier)
        if row is None:
            raise ValidationFailed("incidentId does not reference an existing incident")
        if row.status == "closed":
            raise ValidationFailed("incidentId references a closed incident")
        return row

    # --------------------------------------------------------------- builders
    def _attachment_map(self, intervention_ids: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
        keys = sorted({value for value in intervention_ids if value})
        if not keys:
            return {}
        rows = self._session.execute(
            select(InterventionAttachment, Attachment)
            .join(Attachment, Attachment.id == InterventionAttachment.attachment_id)
            .where(
                InterventionAttachment.intervention_id.in_(keys),
                Attachment.deleted_at.is_(None),
            )
            .order_by(
                InterventionAttachment.intervention_id.asc(),
                InterventionAttachment.position.asc(),
            )
        ).all()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for link, attachment in rows:
            grouped.setdefault(link.intervention_id, []).append(
                {
                    "id": attachment.id,
                    "filename": attachment.filename,
                    "category": attachment.category,
                }
            )
        return grouped

    def _intervention_view(
        self,
        row: Intervention,
        *,
        asset: Asset | None,
        technician_name: str | None,
        attachments: Sequence[Mapping[str, Any]],
    ) -> InterventionView:
        parts = tuple(dict(part) for part in (row.parts or ()))
        parts_cost = _parts_cost(parts)
        total = _total_cost(row.labor_cost, parts_cost)
        line_parts = tuple(
            {
                "name": part["name"],
                "quantity": int(part["quantity"]),
                "unitCost": part.get("unitCost"),
                "lineCost": (
                    None
                    if part.get("unitCost") is None
                    else _money_text(Decimal(str(part["unitCost"])) * int(part["quantity"]))
                ),
            }
            for part in parts
        )
        return InterventionView(
            id=row.id,
            asset_id=row.asset_id,
            asset_name=None if asset is None else asset.name,
            asset_quick_code=None if asset is None else asset.quick_code,
            type=row.type,
            description=row.description,
            technician_person_id=row.technician_person_id,
            technician_name=technician_name,
            occurred_on=row.occurred_on,
            status=row.status,
            notes=row.notes,
            parts=line_parts,
            labor_cost=row.labor_cost,
            parts_cost=_money_text(parts_cost),
            total_cost=_money_text(total),
            incident_id=row.incident_id,
            plan_id=row.plan_id,
            attachments=tuple(dict(item) for item in attachments),
            created_by=row.created_by,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _intervention_views(self, rows: Sequence[Intervention]) -> tuple[InterventionView, ...]:
        if not rows:
            return ()
        assets = self._assets([row.asset_id for row in rows])
        names = self._person_names([row.technician_person_id or "" for row in rows])
        attachments = self._attachment_map([row.id for row in rows])
        return tuple(
            self._intervention_view(
                row,
                asset=assets.get(row.asset_id),
                technician_name=(
                    None
                    if row.technician_person_id is None
                    else names.get(row.technician_person_id)
                ),
                attachments=attachments.get(row.id, ()),
            )
            for row in rows
        )

    def _affected_ids(self, incident_id: str) -> list[str]:
        return [
            row.asset_id
            for row in self._session.execute(
                select(IncidentAsset)
                .where(IncidentAsset.incident_id == incident_id)
                .order_by(IncidentAsset.position.asc())
            ).scalars()
        ]

    def _incident_view(
        self,
        row: Incident,
        *,
        asset: Asset | None,
        responsible_name: str | None,
        affected_ids: Sequence[str],
    ) -> IncidentView:
        return IncidentView(
            id=row.id,
            description=row.description,
            priority=row.priority,
            status=row.status,
            primary_asset_id=row.primary_asset_id,
            primary_asset_name=None if asset is None else asset.name,
            primary_asset_quick_code=None if asset is None else asset.quick_code,
            affected_asset_ids=tuple(affected_ids),
            responsible_person_id=row.responsible_person_id,
            responsible_name=responsible_name,
            opened_on=row.opened_on,
            resolved_at=None if row.resolved_at is None else as_utc(row.resolved_at),
            closed_at=None if row.closed_at is None else as_utc(row.closed_at),
            revision=int(row.revision),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _incident_views(self, rows: Sequence[Incident]) -> tuple[IncidentView, ...]:
        if not rows:
            return ()
        assets = self._assets([row.primary_asset_id for row in rows])
        names = self._person_names([row.responsible_person_id or "" for row in rows])
        ids = [row.id for row in rows]
        affected: dict[str, list[str]] = {identifier: [] for identifier in ids}
        for link in self._session.execute(
            select(IncidentAsset)
            .where(IncidentAsset.incident_id.in_(ids))
            .order_by(IncidentAsset.incident_id.asc(), IncidentAsset.position.asc())
        ).scalars():
            affected[link.incident_id].append(link.asset_id)
        return tuple(
            self._incident_view(
                row,
                asset=assets.get(row.primary_asset_id),
                responsible_name=(
                    None
                    if row.responsible_person_id is None
                    else names.get(row.responsible_person_id)
                ),
                affected_ids=affected[row.id],
            )
            for row in rows
        )

    def _incident_detail(self, row: Incident) -> IncidentDetailView:
        affected_ids = self._affected_ids(row.id)
        assets = self._assets([row.primary_asset_id, *affected_ids])
        names = self._person_names([row.responsible_person_id or ""])
        summary = self._incident_view(
            row,
            asset=assets.get(row.primary_asset_id),
            responsible_name=(
                None if row.responsible_person_id is None else names.get(row.responsible_person_id)
            ),
            affected_ids=affected_ids,
        )
        events = tuple(
            IncidentEventView(
                id=event.id,
                sequence=int(event.sequence),
                action=event.action,
                from_status=event.from_status,
                to_status=event.to_status,
                note=event.note,
                changes=event.changes,
                actor_id=event.actor_id,
                actor_username=event.actor_username,
                source=event.source,
                created_at=event.created_at,
            )
            for event in self._session.execute(
                select(IncidentEvent)
                .where(IncidentEvent.incident_id == row.id)
                .order_by(IncidentEvent.sequence.asc())
            ).scalars()
        )
        intervention_rows = list(
            self._session.execute(
                select(Intervention)
                .where(Intervention.incident_id == row.id)
                .order_by(Intervention.occurred_on.asc(), Intervention.created_at.asc())
            ).scalars()
        )
        costs = self._incident_costs(row.id)
        return IncidentDetailView(
            incident=summary,
            affected_assets=tuple(
                {
                    "id": asset_id,
                    "name": assets[asset_id].name if asset_id in assets else None,
                    "quickCode": assets[asset_id].quick_code if asset_id in assets else None,
                }
                for asset_id in affected_ids
            ),
            events=events,
            interventions=self._intervention_views(intervention_rows),
            interventions_total=len(intervention_rows),
            costs=costs,
            resolution_prepared=row.resolution_token is not None,
            resolution_prepared_at=(
                None if row.resolution_prepared_at is None else as_utc(row.resolution_prepared_at)
            ),
            resolution_prepared_by=row.resolution_prepared_by,
        )

    def _incident_costs(self, incident_id: str) -> CostSummary:
        rows = self._session.execute(
            select(Intervention.labor_cost, Intervention.parts).where(
                Intervention.incident_id == incident_id
            )
        ).all()
        return _accumulate_costs(rows)

    # ----------------------------------------------------------- interventions
    def get(self, principal: Principal, intervention_id: Any) -> InterventionView:
        self._identity.authorize(principal, "assets.view", resource="maintenance:interventions")
        row = self._intervention(intervention_id)
        return self._intervention_views([row])[0]

    def _intervention_filters(
        self,
        *,
        category: str | None,
        site: str | None,
        site_id: str | None,
        status: str | None,
        intervention_type: str | None,
        asset_id: str | None,
        technician_person_id: str | None,
        incident_id: str | None,
        plan_id: str | None,
        from_date: Any,
        to_date: Any,
    ) -> list[Any]:
        conditions: list[Any] = []
        if category is not None:
            conditions.append(Asset.category == _text(category, "category", max_length=120))
        if site is not None:
            conditions.append(Asset.site == _text(site, "site", max_length=120))
        if site_id is not None:
            conditions.append(Asset.site_id == _uuid_text(site_id, "siteId"))
        if status is not None:
            conditions.append(
                Intervention.status == _enum(status, "status", INTERVENTION_STATUSES, status)
            )
        if intervention_type is not None:
            conditions.append(
                Intervention.type
                == _enum(intervention_type, "type", INTERVENTION_TYPES, intervention_type)
            )
        if asset_id is not None:
            conditions.append(Intervention.asset_id == _uuid_text(asset_id, "assetId"))
        if technician_person_id is not None:
            conditions.append(
                Intervention.technician_person_id
                == _uuid_text(technician_person_id, "technicianPersonId")
            )
        if incident_id is not None:
            conditions.append(Intervention.incident_id == _uuid_text(incident_id, "incidentId"))
        if plan_id is not None:
            conditions.append(Intervention.plan_id == _uuid_text(plan_id, "planId"))
        start = _date_arg(from_date, "from")
        end = _date_arg(to_date, "to")
        if start is not None:
            conditions.append(Intervention.occurred_on >= start)
        if end is not None:
            conditions.append(Intervention.occurred_on <= end)
        if start is not None and end is not None and start > end:
            raise ValidationFailed("from must not be after to")
        return conditions

    def list(
        self,
        principal: Principal,
        *,
        category: str | None = None,
        site: str | None = None,
        site_id: str | None = None,
        status: str | None = None,
        intervention_type: str | None = None,
        asset_id: str | None = None,
        technician_person_id: str | None = None,
        incident_id: str | None = None,
        plan_id: str | None = None,
        from_date: Any = None,
        to_date: Any = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> InterventionPage:
        self._identity.authorize(principal, "assets.view", resource="maintenance:interventions")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        statement = select(Intervention).join(Asset, Asset.id == Intervention.asset_id)
        conditions = self._intervention_filters(
            category=category,
            site=site,
            site_id=site_id,
            status=status,
            intervention_type=intervention_type,
            asset_id=asset_id,
            technician_person_id=technician_person_id,
            incident_id=incident_id,
            plan_id=plan_id,
            from_date=from_date,
            to_date=to_date,
        )
        statement = statement.where(*conditions)
        total = int(
            self._session.execute(
                select(func.count()).select_from(statement.order_by(None).subquery())
            ).scalar_one()
        )
        rows = list(
            self._session.execute(
                statement.order_by(
                    Intervention.occurred_on.desc(),
                    Intervention.created_at.desc(),
                    Intervention.id.desc(),
                )
                .limit(bounded_limit)
                .offset(bounded_offset)
            ).scalars()
        )
        return InterventionPage(
            items=self._intervention_views(rows),
            total=total,
            limit=bounded_limit,
            offset=bounded_offset,
        )

    def costs(
        self,
        principal: Principal,
        *,
        category: str | None = None,
        site: str | None = None,
        site_id: str | None = None,
        status: str | None = None,
        intervention_type: str | None = None,
        asset_id: str | None = None,
        technician_person_id: str | None = None,
        incident_id: str | None = None,
        plan_id: str | None = None,
        from_date: Any = None,
        to_date: Any = None,
    ) -> CostSummary:
        self._identity.authorize(principal, "assets.view", resource="maintenance:interventions")
        statement = select(Intervention.labor_cost, Intervention.parts).join(
            Asset, Asset.id == Intervention.asset_id
        )
        conditions = self._intervention_filters(
            category=category,
            site=site,
            site_id=site_id,
            status=status,
            intervention_type=intervention_type,
            asset_id=asset_id,
            technician_person_id=technician_person_id,
            incident_id=incident_id,
            plan_id=plan_id,
            from_date=from_date,
            to_date=to_date,
        )
        return _accumulate_costs(self._session.execute(statement.where(*conditions)).all())

    @serialized
    def create(self, principal: Principal, values: Mapping[str, Any]) -> InterventionView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:interventions")
        prepared = self._prepare_create(principal, values)
        now = utcnow()
        row = Intervention(
            id=str(uuid4()),
            asset_id=prepared["asset_id"],
            type=prepared["type"],
            description=prepared["description"],
            technician_person_id=prepared["technician_person_id"],
            occurred_on=prepared["occurred_on"],
            status=prepared["status"],
            notes=prepared["notes"],
            labor_cost=prepared["labor_cost"],
            parts=prepared["parts"],
            incident_id=prepared["incident_id"],
            plan_id=prepared["plan_id"],
            created_by=principal.actor_id,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        self._session.flush()
        self._replace_attachments(row.id, prepared["attachments"])
        self._session.flush()
        self._complete_preventive(principal, row)
        asset = self._asset(row.asset_id)
        self._inventory._record_history(
            principal,
            asset,
            "intervention_logged",
            changes={
                "intervention": {"old": None, "new": row.id},
                "type": {"old": None, "new": row.type},
                "status": {"old": None, "new": row.status},
                "description": {"old": None, "new": row.description},
            },
            notes=_clip(row.description, 500),
            source=self._source,
            entity_type="intervention",
            entity_id=row.id,
        )
        if prepared["incident"] is not None:
            incident = prepared["incident"]
            self._touch(incident)
            self._event(
                principal,
                incident,
                "intervention_linked",
                from_status=incident.status,
                to_status=incident.status,
                changes={"intervention": {"old": None, "new": row.id}},
            )
        self._identity.record_operation(
            principal,
            action="maintenance.intervention_created",
            resource=f"intervention:{row.id}",
        )
        return self._intervention_views([row])[0]

    @serialized
    def update(
        self,
        principal: Principal,
        intervention_id: Any,
        values: Mapping[str, Any],
    ) -> InterventionView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:interventions")
        if not isinstance(values, Mapping):
            raise ValidationFailed("intervention changes must be an object")
        unknown = set(values) - _INTERVENTION_UPDATE_KEYS
        if unknown:
            raise ValidationFailed("unsupported intervention fields: " + ", ".join(sorted(unknown)))
        row = self._intervention(intervention_id)
        asset = self._asset(row.asset_id)
        previous_status = row.status
        before = {
            "status": row.status,
            "attachments": [link.attachment_id for link in self._attachment_links(row.id)],
        }
        changes: dict[str, Any] = {}
        if "type" in values:
            new_type = _enum(values["type"], "type", INTERVENTION_TYPES, row.type)
            if new_type != row.type:
                changes["type"] = {"old": row.type, "new": new_type}
                row.type = new_type
        if "description" in values:
            new_description = _text(
                values["description"], "description", max_length=DESCRIPTION_MAX
            )
            if new_description != row.description:
                changes["description"] = {"old": row.description, "new": new_description}
                row.description = new_description
        if "technicianPersonId" in values:
            if values["technicianPersonId"] is None:
                new_technician = None
                new_name = None
            else:
                technician = self._person(values["technicianPersonId"], "technicianPersonId")
                new_technician = technician.id
                new_name = technician.name
            if new_technician != row.technician_person_id:
                changes["technicianPersonId"] = {
                    "old": row.technician_person_id,
                    "new": new_technician,
                    "newName": new_name,
                }
                row.technician_person_id = new_technician
        if "occurredOn" in values:
            new_date = _date_value(values["occurredOn"], "occurredOn")
            if new_date != row.occurred_on:
                changes["occurredOn"] = {
                    "old": _iso(row.occurred_on),
                    "new": _iso(new_date),
                }
                row.occurred_on = new_date
        if "notes" in values:
            new_notes = _text(values["notes"], "notes", max_length=NOTES_MAX)
            if new_notes != row.notes:
                changes["notes"] = {"old": row.notes, "new": new_notes}
                row.notes = new_notes
        if "laborCost" in values:
            labor = _money(values["laborCost"], "laborCost")
            new_labor = _money_text(labor)
            if new_labor != row.labor_cost:
                changes["laborCost"] = {"old": row.labor_cost, "new": new_labor}
                row.labor_cost = new_labor
        if "parts" in values:
            prepared_parts = _parts(values["parts"])
            if prepared_parts != list(row.parts or ()):
                changes["parts"] = {"old": list(row.parts or ()), "new": prepared_parts}
                row.parts = prepared_parts
        attachments: Sequence[Attachment] | None = None
        if "attachmentIds" in values:
            attachments = self._attachments(row.asset_id, values["attachmentIds"])
            new_ids = [attachment.id for attachment in attachments]
            if new_ids != before["attachments"]:
                changes["attachments"] = {"old": before["attachments"], "new": new_ids}
                self._replace_attachments(row.id, attachments)
        if "status" in values:
            new_status = _enum(values["status"], "status", INTERVENTION_STATUSES, row.status)
            if new_status != row.status:
                if new_status not in INTERVENTION_TRANSITIONS.get(row.status, frozenset()):
                    raise Conflict(f"cannot move an intervention from {row.status} to {new_status}")
                changes["status"] = {"old": row.status, "new": new_status}
                row.status = new_status
        if not changes:
            return self._intervention_views([row])[0]
        row.updated_at = utcnow()
        self._session.flush()
        if previous_status != "completed":
            self._complete_preventive(principal, row)
        action = "intervention_completed" if row.status == "completed" else "intervention_updated"
        self._inventory._record_history(
            principal,
            asset,
            action,
            changes=changes,
            notes=_clip(row.description, 500),
            source=self._source,
            entity_type="intervention",
            entity_id=row.id,
        )
        if row.incident_id is not None:
            incident = self._session.get(Incident, row.incident_id)
            if incident is not None and incident.status != "closed":
                self._touch(incident)
                self._event(
                    principal,
                    incident,
                    action,
                    from_status=incident.status,
                    to_status=incident.status,
                    changes=changes,
                )
        self._identity.record_operation(
            principal,
            action="maintenance.intervention_updated",
            resource=f"intervention:{row.id}",
        )
        return self._intervention_views([row])[0]

    def _prepare_create(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("intervention values must be an object")
        unknown = set(values) - _INTERVENTION_CREATE_KEYS
        if unknown:
            raise ValidationFailed("unsupported intervention fields: " + ", ".join(sorted(unknown)))
        asset = self._asset(values.get("assetId"))
        technician: DirectoryPerson | None = None
        if values.get("technicianPersonId") is not None:
            technician = self._person(values["technicianPersonId"], "technicianPersonId")
        incident = self._incident_link(values.get("incidentId"))
        plan_id = _optional_uuid_text(values.get("planId"), "planId")
        if plan_id is not None:
            plan = self._maintenance.get_plan(principal, plan_id)
            if plan.asset_id != asset.id:
                raise ValidationFailed("planId must belong to the intervention asset")
            self._plan_validator(principal, plan_id)
        occurred_on = (
            _date_value(values["occurredOn"], "occurredOn")
            if values.get("occurredOn") is not None
            else utcnow().date()
        )
        labor = _money(values.get("laborCost"), "laborCost")
        return {
            "asset_id": asset.id,
            "type": _enum(
                values.get("type"), "type", INTERVENTION_TYPES, DEFAULT_INTERVENTION_TYPE
            ),
            "description": _text(
                values.get("description"), "description", max_length=DESCRIPTION_MAX
            ),
            "technician_person_id": None if technician is None else technician.id,
            "occurred_on": occurred_on,
            "status": _enum(
                values.get("status"),
                "status",
                INTERVENTION_STATUSES,
                DEFAULT_INTERVENTION_STATUS,
            ),
            "notes": _text(values.get("notes"), "notes", max_length=NOTES_MAX),
            "labor_cost": _money_text(labor),
            "parts": _parts(values.get("parts")),
            "incident_id": None if incident is None else incident.id,
            "incident": incident,
            "plan_id": plan_id,
            "attachments": self._attachments(asset.id, values.get("attachmentIds")),
        }

    def _complete_preventive(self, principal: Principal, row: Intervention) -> None:
        """Complete the linked preventive plan once, inside this transaction.

        Only a preventive intervention that actually reaches ``completed`` with a
        linked plan triggers it; corrective work never resets preventive cycles.
        """
        if (
            self._completion_hook is None
            or row.type != "preventive"
            or row.status != "completed"
            or row.plan_id is None
        ):
            return
        self._completion_hook(principal, row)

    def _attachment_links(self, intervention_id: str) -> list[InterventionAttachment]:
        return list(
            self._session.execute(
                select(InterventionAttachment)
                .where(InterventionAttachment.intervention_id == intervention_id)
                .order_by(InterventionAttachment.position.asc())
            ).scalars()
        )

    def _replace_attachments(self, intervention_id: str, attachments: Sequence[Attachment]) -> None:
        for link in self._attachment_links(intervention_id):
            self._session.delete(link)
        self._session.flush()
        for position, attachment in enumerate(attachments):
            self._session.add(
                InterventionAttachment(
                    intervention_id=intervention_id,
                    attachment_id=attachment.id,
                    position=position,
                )
            )

    # ----------------------------------------------------------------- incidents
    def get_incident(self, principal: Principal, incident_id: Any) -> IncidentDetailView:
        self._identity.authorize(principal, "assets.view", resource="maintenance:incidents")
        return self._incident_detail(self._incident(incident_id))

    def list_incidents(
        self,
        principal: Principal,
        *,
        active: bool | None = None,
        status: str | None = None,
        priority: str | None = None,
        category: str | None = None,
        site: str | None = None,
        site_id: str | None = None,
        asset_id: str | None = None,
        responsible_person_id: str | None = None,
        from_date: Any = None,
        to_date: Any = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> IncidentPage:
        self._identity.authorize(principal, "assets.view", resource="maintenance:incidents")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        statement = select(Incident).join(Asset, Asset.id == Incident.primary_asset_id)
        conditions = []
        if active is not None:
            if not isinstance(active, bool):
                raise ValidationFailed("active must be a boolean")
            conditions.append(
                Incident.status.in_(ACTIVE_INCIDENT_STATUSES)
                if active
                else Incident.status.not_in(ACTIVE_INCIDENT_STATUSES)
            )
        if status is not None:
            conditions.append(Incident.status == _enum(status, "status", INCIDENT_STATUSES, status))
        if priority is not None:
            conditions.append(
                Incident.priority == _enum(priority, "priority", INCIDENT_PRIORITIES, priority)
            )
        if category is not None:
            conditions.append(Asset.category == _text(category, "category", max_length=120))
        if site is not None:
            conditions.append(Asset.site == _text(site, "site", max_length=120))
        if site_id is not None:
            conditions.append(Asset.site_id == _uuid_text(site_id, "siteId"))
        if asset_id is not None:
            identifier = _uuid_text(asset_id, "assetId")
            conditions.append(
                or_(
                    Incident.primary_asset_id == identifier,
                    Incident.id.in_(
                        select(IncidentAsset.incident_id).where(
                            IncidentAsset.asset_id == identifier
                        )
                    ),
                )
            )
        if responsible_person_id is not None:
            identifier = _uuid_text(responsible_person_id, "responsiblePersonId")
            conditions.append(
                or_(
                    Incident.responsible_person_id == identifier,
                    Asset.responsible_person_id == identifier,
                )
            )
        start = _date_arg(from_date, "from")
        end = _date_arg(to_date, "to")
        if start is not None:
            conditions.append(Incident.opened_on >= start)
        if end is not None:
            conditions.append(Incident.opened_on <= end)
        if start is not None and end is not None and start > end:
            raise ValidationFailed("from must not be after to")
        statement = statement.where(*conditions)
        total = int(
            self._session.execute(
                select(func.count()).select_from(statement.order_by(None).subquery())
            ).scalar_one()
        )
        rows = list(
            self._session.execute(
                statement.order_by(
                    Incident.opened_on.desc(),
                    Incident.created_at.desc(),
                    Incident.id.desc(),
                )
                .limit(bounded_limit)
                .offset(bounded_offset)
            ).scalars()
        )
        return IncidentPage(
            items=self._incident_views(rows),
            total=total,
            limit=bounded_limit,
            offset=bounded_offset,
        )

    @serialized
    def create_incident_in_transaction(
        self, principal: Principal, values: Mapping[str, Any]
    ) -> Incident:
        """Create the incident rows and flush them; the caller owns the commit.

        ``create_incident`` is the committing door. Monitoring link creation
        uses this seam so the incident, its history and the alert link share one
        terminal audit commit and a failure can never leave a half-written link.
        """
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        prepared = self._prepare_incident(principal, values)
        now = utcnow()
        row = Incident(
            id=str(uuid4()),
            description=prepared["description"],
            priority=prepared["priority"],
            status="open",
            primary_asset_id=prepared["primary_asset_id"],
            responsible_person_id=prepared["responsible_person_id"],
            opened_on=prepared["opened_on"],
            revision=1,
            created_by=principal.actor_id,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        self._session.flush()
        for position, asset_id in enumerate(prepared["affected"]):
            self._session.add(
                IncidentAsset(incident_id=row.id, asset_id=asset_id, position=position)
            )
        self._event(
            principal,
            row,
            "created",
            to_status="open",
            changes={
                "description": {"old": None, "new": row.description},
                "priority": {"old": None, "new": row.priority},
                "primaryAsset": {"old": None, "new": row.primary_asset_id},
                "affectedAssets": {"old": [], "new": prepared["affected"]},
            },
        )
        self._session.flush()
        self._incident_history(
            principal,
            row,
            "incident_opened",
            changes={
                "incident": {"old": None, "new": row.id},
                "priority": {"old": None, "new": row.priority},
                "primaryAsset": {"old": None, "new": row.primary_asset_id},
            },
            note=row.description,
        )
        self._session.flush()
        return row

    def create_incident(self, principal: Principal, values: Mapping[str, Any]) -> IncidentView:
        row = self.create_incident_in_transaction(principal, values)
        self._identity.record_operation(
            principal,
            action="maintenance.incident_created",
            resource=f"incident:{row.id}",
        )
        return self._incident_views([row])[0]

    @serialized
    def update_incident_assets(
        self,
        principal: Principal,
        incident_id: Any,
        affected_asset_ids: Sequence[str],
    ) -> IncidentDetailView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        row = self._incident(incident_id)
        if row.status == "closed":
            raise Conflict("a closed incident cannot change its affected assets")
        new_ids = self._affected(affected_asset_ids, row.primary_asset_id)
        old_ids = self._affected_ids(row.id)
        if new_ids == old_ids:
            return self._incident_detail(row)
        for link in self._session.execute(
            select(IncidentAsset).where(IncidentAsset.incident_id == row.id)
        ).scalars():
            self._session.delete(link)
        self._session.flush()
        for position, asset_id in enumerate(new_ids):
            self._session.add(
                IncidentAsset(incident_id=row.id, asset_id=asset_id, position=position)
            )
        self._touch(row)
        changes = {"affectedAssets": {"old": old_ids, "new": new_ids}}
        self._event(
            principal,
            row,
            "affected_assets_updated",
            from_status=row.status,
            to_status=row.status,
            changes=changes,
        )
        self._session.flush()
        changed = [asset_id for asset_id in old_ids if asset_id not in new_ids]
        changed += [asset_id for asset_id in new_ids if asset_id not in old_ids]
        self._incident_history(
            principal,
            row,
            "incident_assets_updated",
            changes=changes,
            extra_asset_ids=changed,
        )
        self._identity.record_operation(
            principal,
            action="maintenance.incident_assets_updated",
            resource=f"incident:{row.id}",
        )
        return self._incident_detail(row)

    @serialized
    def acknowledge_incident(
        self, principal: Principal, incident_id: Any, *, note: Any = None
    ) -> IncidentDetailView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        row = self._incident(incident_id)
        if row.status != "open":
            raise Conflict(f"cannot acknowledge an incident in {row.status}")
        return self._transition(
            principal,
            row,
            "in_progress",
            action="acknowledged",
            history_action="incident_acknowledged",
            note=note,
        )

    @serialized
    def resolve_incident(
        self, principal: Principal, incident_id: Any, *, note: Any = None
    ) -> IncidentDetailView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        row = self._incident(incident_id)
        if row.status != "in_progress":
            raise Conflict(f"cannot resolve an incident in {row.status}")
        return self._transition(
            principal,
            row,
            "resolved",
            action="resolved",
            history_action="incident_resolved",
            note=note,
            resolved=True,
        )

    @serialized
    def close_incident(
        self, principal: Principal, incident_id: Any, *, note: Any = None
    ) -> IncidentDetailView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        row = self._incident(incident_id)
        if row.status != "resolved":
            raise Conflict(f"cannot close an incident in {row.status}")
        return self._transition(
            principal,
            row,
            "closed",
            action="closed",
            history_action="incident_closed",
            note=note,
            closed=True,
        )

    @serialized
    def prepare_resolution(
        self, principal: Principal, incident_id: Any, *, note: Any = None
    ) -> ResolutionSuggestion:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        row = self._incident(incident_id)
        if row.status not in ACTIVE_INCIDENT_STATUSES:
            raise Conflict("only an active incident can prepare a resolution")
        token = secrets.token_urlsafe(TOKEN_BYTES)
        status = row.status
        self._touch(row)
        prepared_at = utcnow()
        row.resolution_token = _token_digest(token)
        row.resolution_revision = row.revision
        row.resolution_prepared_at = prepared_at
        row.resolution_prepared_by = principal.username
        self._event(
            principal,
            row,
            "resolution_prepared",
            from_status=status,
            to_status=status,
            note=note,
        )
        self._session.flush()
        self._incident_history(
            principal,
            row,
            "incident_resolution_prepared",
            changes={"revision": {"old": row.revision - 1, "new": row.revision}},
            note=note,
        )
        self._identity.record_operation(
            principal,
            action="maintenance.incident_resolution_prepared",
            resource=f"incident:{row.id}",
        )
        return ResolutionSuggestion(
            incident_id=row.id,
            token=token,
            revision=int(row.revision),
            prepared_at=prepared_at,
        )

    @serialized
    def confirm_resolution(
        self,
        principal: Principal,
        incident_id: Any,
        token: Any,
        *,
        note: Any = None,
    ) -> IncidentDetailView:
        self._identity.authorize(principal, "assets.edit", resource="maintenance:incidents")
        row = self._incident(incident_id)
        if row.status not in ACTIVE_INCIDENT_STATUSES:
            raise Conflict("only an active incident can confirm a resolution")
        if not isinstance(token, str) or not token or len(token) > 200:
            raise ValidationFailed("token is required")
        stored = row.resolution_token
        if (
            stored is None
            or row.resolution_revision is None
            or int(row.resolution_revision) != int(row.revision)
        ):
            raise Conflict("resolution token is stale; prepare the resolution again")
        if not hmac.compare_digest(_token_digest(token), stored):
            raise Conflict("resolution token is invalid or stale; prepare the resolution again")
        previous = row.status
        row.status = "resolved"
        row.resolved_at = utcnow()
        self._touch(row)
        self._event(
            principal,
            row,
            "resolution_confirmed",
            from_status=previous,
            to_status="resolved",
            note=note,
        )
        self._session.flush()
        self._incident_history(
            principal,
            row,
            "incident_resolution_confirmed",
            changes={"status": {"old": previous, "new": "resolved"}},
            note=note,
        )
        self._identity.record_operation(
            principal,
            action="maintenance.incident_resolution_confirmed",
            resource=f"incident:{row.id}",
        )
        return self._incident_detail(row)

    def asset_technical_history(
        self,
        principal: Principal,
        asset_id: Any,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> TechnicalHistoryPage:
        self._identity.authorize(principal, "assets.view", resource=f"asset:{asset_id}")
        identifier = _uuid_text(asset_id, "asset id")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        entities = ("intervention", "incident")
        total = int(
            self._session.execute(
                select(func.count(AssetHistory.id)).where(
                    AssetHistory.asset_id == identifier,
                    AssetHistory.entity_type.in_(entities),
                )
            ).scalar_one()
        )
        if total == 0 and self._session.get(Asset, identifier) is None:
            raise NotFound("asset not found")
        rows = self._session.execute(
            select(AssetHistory)
            .where(
                AssetHistory.asset_id == identifier,
                AssetHistory.entity_type.in_(entities),
            )
            .order_by(AssetHistory.sequence.asc())
            .limit(bounded_limit)
            .offset(bounded_offset)
        ).scalars()
        return TechnicalHistoryPage(
            asset_id=identifier,
            items=tuple(
                self._inventory._history_view(entry).structured_payload() for entry in rows
            ),
            total=total,
            limit=bounded_limit,
            offset=bounded_offset,
        )

    # ------------------------------------------------------------------ shared
    def _prepare_incident(self, principal: Principal, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("incident values must be an object")
        unknown = set(values) - _INCIDENT_CREATE_KEYS
        if unknown:
            raise ValidationFailed("unsupported incident fields: " + ", ".join(sorted(unknown)))
        primary = self._asset(values.get("primaryAssetId"))
        description = _text(
            values.get("description"), "description", max_length=DESCRIPTION_MAX, required=True
        )
        priority = _enum(
            values.get("priority"),
            "priority",
            INCIDENT_PRIORITIES,
            DEFAULT_INCIDENT_PRIORITY,
        )
        responsible = primary.responsible_person_id
        if values.get("responsiblePersonId") is not None:
            responsible = self._person(values["responsiblePersonId"], "responsiblePersonId").id
        opened_on = (
            _date_value(values["openedOn"], "openedOn")
            if values.get("openedOn") is not None
            else utcnow().date()
        )
        affected = self._affected(values.get("affectedAssetIds"), primary.id)
        return {
            "primary_asset_id": primary.id,
            "description": description,
            "priority": priority,
            "responsible_person_id": responsible,
            "opened_on": opened_on,
            "affected": affected,
        }

    def _transition(
        self,
        principal: Principal,
        row: Incident,
        target: str,
        *,
        action: str,
        history_action: str,
        note: Any,
        resolved: bool = False,
        closed: bool = False,
    ) -> IncidentDetailView:
        previous = row.status
        row.status = target
        if resolved:
            row.resolved_at = utcnow()
        if closed:
            row.closed_at = utcnow()
        self._touch(row)
        clean_note = _text(note, "note", max_length=NOTES_MAX)
        self._event(
            principal,
            row,
            action,
            from_status=previous,
            to_status=target,
            note=clean_note,
            changes={"status": {"old": previous, "new": target}},
        )
        self._session.flush()
        self._incident_history(
            principal,
            row,
            history_action,
            changes={"status": {"old": previous, "new": target}},
            note=clean_note,
        )
        self._identity.record_operation(
            principal,
            action=f"maintenance.{history_action}",
            resource=f"incident:{row.id}",
        )
        return self._incident_detail(row)

    def _touch(self, row: Incident) -> None:
        """Bump the revision and revoke any prepared resolution in one step."""
        row.revision = int(row.revision) + 1
        row.resolution_token = None
        row.resolution_revision = None
        row.resolution_prepared_at = None
        row.resolution_prepared_by = None
        row.updated_at = utcnow()

    def _event(
        self,
        principal: Principal,
        row: Incident,
        action: str,
        *,
        from_status: str | None = None,
        to_status: str | None = None,
        note: Any = None,
        changes: Mapping[str, Any] | None = None,
    ) -> None:
        sequence = (
            int(
                self._session.execute(
                    select(func.coalesce(func.max(IncidentEvent.sequence), 0)).where(
                        IncidentEvent.incident_id == row.id
                    )
                ).scalar_one()
            )
            + 1
        )
        self._session.add(
            IncidentEvent(
                id=str(uuid4()),
                incident_id=row.id,
                sequence=sequence,
                action=action,
                from_status=from_status,
                to_status=to_status,
                note=_text(note, "note", max_length=NOTES_MAX),
                changes=dict(changes) if changes is not None else None,
                actor_id=principal.actor_id,
                actor_username=principal.username,
                source=self._source,
                created_at=utcnow(),
            )
        )

    def _incident_history(
        self,
        principal: Principal,
        row: Incident,
        action: str,
        *,
        changes: Mapping[str, Any],
        note: Any = None,
        extra_asset_ids: Sequence[str] = (),
    ) -> None:
        asset_ids = [row.primary_asset_id, *self._affected_ids(row.id)]
        for asset_id in extra_asset_ids:
            if asset_id not in asset_ids:
                asset_ids.append(asset_id)
        assets = self._assets(asset_ids)
        for asset_id in asset_ids:
            asset = assets.get(asset_id)
            if asset is None:
                continue
            self._inventory._record_history(
                principal,
                asset,
                action,
                changes=changes,
                notes=_clip(note, 500),
                source=self._source,
                entity_type="incident",
                entity_id=row.id,
            )


def _accumulate_costs(rows: Sequence[Any]) -> CostSummary:
    total = Decimal("0")
    counted = 0
    for labor_cost, parts in rows:
        parts_value = _parts_cost(tuple(parts or ()))
        if labor_cost is None and parts_value is None:
            continue
        counted += 1
        total += (Decimal(labor_cost) if labor_cost is not None else Decimal("0")) + (
            parts_value or Decimal("0")
        )
    return CostSummary(
        total_cost=_money_text(total) if counted else None,
        counted_interventions=counted,
    )


__all__ = [
    "ACTIVE_INCIDENT_STATUSES",
    "DEFAULT_INCIDENT_PRIORITY",
    "DEFAULT_INTERVENTION_STATUS",
    "DEFAULT_INTERVENTION_TYPE",
    "INCIDENT_PRIORITIES",
    "INCIDENT_STATUSES",
    "INTERVENTION_STATUSES",
    "INTERVENTION_TRANSITIONS",
    "INTERVENTION_TYPES",
    "CostSummary",
    "IncidentDetailView",
    "IncidentEventView",
    "IncidentPage",
    "IncidentView",
    "InterventionPage",
    "InterventionService",
    "InterventionView",
    "ResolutionSuggestion",
    "TechnicalHistoryPage",
]
