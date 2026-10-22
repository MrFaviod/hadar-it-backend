"""Canonical inventory service: validation, authorization, SQL access and audit.

REST handlers, the Pydantic AI tools and the FastMCP tools are thin adapters over
this module. Nothing here trusts a caller-supplied identity, permission or
database handle: every operation resolves a ``Principal`` through the identity
service and asks it to authorize the concrete permission it needs.

The asset core adds four things without moving rules into an adapter:

* common fields (cost, bounded technical values) and a permanent UUID identity;
* clone (duplicate with a new UUID) and an archive flag that is independent of
  status, responsible and location;
* an append-only history that records old/new values, quick code, lifecycle,
  actor and time, and that survives a permanent purge as a UUID tombstone;
* protected permanent purge whose rules depend only on ``Settings.environment``
  and on a distinct ``assets.purge`` privilege in production.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.permissions import HUMAN_ACTOR_KIND
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from itsm.inventory import organization
from itsm.inventory.catalog import InventoryCatalog
from itsm.inventory.codes import InventoryCodeSequence, allocate, serialized
from itsm.inventory.media import MEDIA_ROLES, validate_image, validate_role
from itsm.inventory.models import Asset, AssetHistory, AssetMedia, AssetTombstone
from itsm.inventory.organization import AssetMap, MapPosition, MapSite

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
BATCH_LIMIT = 50
SEARCH_TEXT_LIMIT = 120
HISTORY_LIMIT = MAX_LIMIT

STATUSES: tuple[str, ...] = ("in_use", "in_storage", "maintenance", "retired")
DEFAULT_STATUS = STATUSES[0]

_UNSET: Any = object()

FIELD_LIMITS: dict[str, int] = {
    "quick_code": 32,
    "name": 160,
    "category": 64,
    "type": 64,
    "brand": 64,
    "model": 80,
    "serial": 80,
    "ip": 64,
    "site": 120,
    "location": 120,
    "responsible": 120,
    "status": 24,
    "description": 1000,
}

# Fields the service accepts on create/update; cost and technical are validated
# by dedicated normalizers, everything else is bounded text.
ASSET_FIELDS: tuple[str, ...] = (
    *FIELD_LIMITS,
    "cost",
    "technical",
    *organization.ORGANIZATION_FIELDS,
)

COST_LIMIT = Decimal("1000000000")
COST_QUANTUM = Decimal("0.01")
TECHNICAL_KEYS_MAX = 40
TECHNICAL_KEY_MAX = 64
TECHNICAL_TEXT_MAX = 500
TECHNICAL_LIST_MAX = 20
TECHNICAL_NUMBER_LIMIT = Decimal("1000000000000")
REASON_MIN = 4
REASON_MAX = 500
NOTES_MAX = 500

# Trusted origin of one history event. Adapters pass their transport context at
# construction time; a request payload can never choose it.
HISTORY_SOURCES: frozenset[str] = frozenset({"rest", "agent", "mcp", "internal"})
DEFAULT_HISTORY_SOURCE = "internal"
_ENTITY_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,31}$")

_QUICK_CODE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,31}$")
_TECHNICAL_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SEARCH_COLUMNS = ("name", "quick_code", "serial", "brand", "model", "responsible", "ip")
_HISTORY_FIELDS = (
    "name",
    "category",
    "type",
    "brand",
    "model",
    "serial",
    "ip",
    "site",
    "location",
    "responsible",
    "status",
    "description",
    "cost",
    "technical",
    "site_id",
    "location_id",
    "responsible_person_id",
    "position_x",
    "position_y",
)


def _assert_not_archived(asset: Asset) -> None:
    """Archived assets keep their organization frozen; a return is still allowed."""
    if asset.archived_at is not None:
        raise Conflict("archived assets cannot change their organization")


def _iso(value: datetime) -> str:
    return as_utc(value).isoformat()


def _escape_like(value: str) -> str:
    """Escape LIKE metacharacters so user text is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _text(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValidationFailed(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} must be text")
    normalized = value.strip()
    if not normalized:
        if required:
            raise ValidationFailed(f"{field} is required")
        return None
    limit = FIELD_LIMITS.get(field, SEARCH_TEXT_LIMIT)
    if len(normalized) > limit:
        raise ValidationFailed(f"{field} must be at most {limit} characters")
    return normalized


def _quick_code(value: Any, *, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise ValidationFailed("quickCode is required")
        return None
    if not isinstance(value, str):
        raise ValidationFailed("quickCode must be text")
    normalized = value.strip()
    if not normalized:
        if required:
            raise ValidationFailed("quickCode is required")
        return None
    if not _QUICK_CODE_PATTERN.match(normalized):
        raise ValidationFailed(
            "quickCode must be 1-32 characters using letters, digits, "
            "dot, dash, slash or underscore"
        )
    return normalized


def _status(value: Any) -> str:
    if not isinstance(value, str) or value not in STATUSES:
        raise ValidationFailed(f"status must be one of {', '.join(STATUSES)}")
    return value


def _ip(value: Any) -> str | None:
    text = _text(value, "ip")
    if text is None:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise ValidationFailed("ip must be a valid IPv4 or IPv6 address") from None
    return text


def _cost(value: Any) -> Decimal | None:
    """Validate money as an exact 2-decimal amount between 0 and 1e9."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float | Decimal | str):
        raise ValidationFailed("cost must be a non-negative number")
    try:
        amount = Decimal(str(value).strip())
    except InvalidOperation:
        raise ValidationFailed("cost must be a non-negative number") from None
    if not amount.is_finite() or amount < 0 or amount > COST_LIMIT:
        raise ValidationFailed(f"cost must be between 0 and {COST_LIMIT}")
    if amount != amount.quantize(COST_QUANTUM):
        raise ValidationFailed("cost must have at most 2 decimals")
    return amount.quantize(COST_QUANTUM)


def _technical_scalar(key: str, value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int | float | Decimal):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValidationFailed(f"technical.{key} must be a finite number")
        amount = Decimal(str(value))
        if not amount.is_finite() or abs(amount) > TECHNICAL_NUMBER_LIMIT:
            raise ValidationFailed(f"technical.{key} is out of range")
        return int(amount) if isinstance(value, int) else float(value)
    if isinstance(value, str):
        if len(value) > TECHNICAL_TEXT_MAX:
            raise ValidationFailed(
                f"technical.{key} must be at most {TECHNICAL_TEXT_MAX} characters"
            )
        return value
    raise ValidationFailed(f"technical.{key} must be text, a number or a boolean")


def _technical(value: Any) -> dict[str, Any] | None:
    """Validate a flat, bounded technical object until the catalog seam lands."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValidationFailed("technical must be an object")
    if len(value) > TECHNICAL_KEYS_MAX:
        raise ValidationFailed(f"technical is limited to {TECHNICAL_KEYS_MAX} keys")
    prepared: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _TECHNICAL_KEY_PATTERN.match(key):
            raise ValidationFailed("technical keys must be 1-64 characters starting with a letter")
        if isinstance(item, list):
            if len(item) > TECHNICAL_LIST_MAX:
                raise ValidationFailed(f"technical.{key} is limited to {TECHNICAL_LIST_MAX} values")
            prepared[key] = [_technical_scalar(key, entry) for entry in item]
        else:
            prepared[key] = _technical_scalar(key, item)
    return prepared


def _reason(value: Any, *, required: bool) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise ValidationFailed("reason is required")
        return None
    if not isinstance(value, str):
        raise ValidationFailed("reason must be text")
    normalized = value.strip()
    if len(normalized) < REASON_MIN:
        raise ValidationFailed(f"reason must be at least {REASON_MIN} characters")
    if len(normalized) > REASON_MAX:
        raise ValidationFailed(f"reason must be at most {REASON_MAX} characters")
    return normalized


def _notes(value: Any) -> str | None:
    """Validate an optional free-text observation attached to one history event."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed("notes must be text")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > NOTES_MAX:
        raise ValidationFailed(f"notes must be at most {NOTES_MAX} characters")
    return normalized


def _effective_at(value: Any) -> datetime | None:
    """Validate an optional effective time; it must carry an explicit timezone."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ValidationFailed("effectiveAt must be an ISO timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationFailed("effectiveAt must include a timezone")
    return as_utc(value)


def _history_source(value: Any) -> str:
    if not isinstance(value, str) or value not in HISTORY_SOURCES:
        raise ValidationFailed("source must be one of " + ", ".join(sorted(HISTORY_SOURCES)))
    return value


def _entity_type(value: Any) -> str:
    if not isinstance(value, str) or not _ENTITY_TYPE_PATTERN.match(value):
        raise ValidationFailed("entityType must be 2-32 lowercase letters, digits or underscore")
    return value


def _entity_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 36:
        raise ValidationFailed("entityId must be 1-36 characters")
    return value.strip()


def _normalize(field: str, value: Any) -> Any:
    if field == "quick_code":
        return _quick_code(value)
    if field == "status":
        return _status(value)
    if field == "cost":
        return _cost(value)
    if field == "technical":
        return _technical(value)
    if field == "ip":
        return _ip(value)
    if field in organization.REFERENCE_FIELDS:
        return organization.reference(value, field)
    if field in organization.POSITION_FIELDS:
        return organization.position(value, field)
    return _text(value, field)


def _stored_cost(amount: Decimal | None) -> str | None:
    return None if amount is None else f"{amount:.2f}"


def _json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return _stored_cost(value)
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, list | tuple):
        return list(value)
    return value


@dataclass(frozen=True)
class AssetView:
    """Public, camelCase-safe projection of one stored asset."""

    id: str
    quick_code: str
    name: str
    category: str | None
    type: str | None
    brand: str | None
    model: str | None
    serial: str | None
    ip: str | None
    site: str | None
    location: str | None
    responsible: str | None
    site_id: str | None
    location_id: str | None
    responsible_person_id: str | None
    responsible_label: str | None
    position_x: str | None
    position_y: str | None
    status: str
    description: str | None
    cost: Decimal | None
    technical: Mapping[str, Any] | None
    archived: bool
    archived_at: datetime | None
    archived_by: str | None
    images: Mapping[str, str]
    created_at: datetime
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "quickCode": self.quick_code,
            "name": self.name,
            "category": self.category,
            "type": self.type,
            "brand": self.brand,
            "model": self.model,
            "serial": self.serial,
            "ip": self.ip,
            "site": self.site,
            "location": self.location,
            "responsible": self.responsible,
            "siteId": self.site_id,
            "locationId": self.location_id,
            "responsiblePersonId": self.responsible_person_id,
            "responsibleLabel": self.responsible_label,
            "positionX": self.position_x,
            "positionY": self.position_y,
            "status": self.status,
            "description": self.description,
            "cost": _stored_cost(self.cost),
            "technical": None if self.technical is None else dict(self.technical),
            "archived": self.archived,
            "archivedAt": None if self.archived_at is None else _iso(self.archived_at),
            "archivedBy": self.archived_by,
            "images": dict(self.images),
            "createdAt": _iso(self.created_at),
            "updatedAt": _iso(self.updated_at),
        }


@dataclass(frozen=True)
class InventoryPage:
    """One bounded page of SQL search results."""

    items: tuple[AssetView, ...]
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
class BatchResult:
    """Outcome of one atomic batch; either both tuples or an exception."""

    created: tuple[AssetView, ...]
    updated: tuple[AssetView, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "created": [asset.as_payload() for asset in self.created],
            "updated": [asset.as_payload() for asset in self.updated],
        }


@dataclass(frozen=True)
class HistoryView:
    """One immutable history entry of an asset, including purged assets."""

    id: str
    sequence: int
    asset_id: str
    action: str
    quick_code_old: str | None
    quick_code_new: str | None
    status_old: str | None
    status_new: str | None
    archived_old: bool | None
    archived_new: bool | None
    changes: Mapping[str, Any]
    reason: str | None
    actor_id: str | None
    actor_username: str | None
    source: str
    entity_type: str
    entity_id: str | None
    effective_at: datetime | None
    notes: str | None
    created_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sequence": self.sequence,
            "assetId": self.asset_id,
            "action": self.action,
            "quickCodeOld": self.quick_code_old,
            "quickCodeNew": self.quick_code_new,
            "statusOld": self.status_old,
            "statusNew": self.status_new,
            "archivedOld": self.archived_old,
            "archivedNew": self.archived_new,
            "changes": dict(self.changes),
            "reason": self.reason,
            "actorId": self.actor_id,
            "actorUsername": self.actor_username,
            "createdAt": _iso(self.created_at),
        }

    def structured_payload(self) -> dict[str, Any]:
        """Legacy payload plus the additive origin/entity/effective metadata."""
        return {
            **self.as_payload(),
            "source": self.source,
            "entityType": self.entity_type,
            "entityId": self.entity_id,
            "effectiveAt": None if self.effective_at is None else _iso(self.effective_at),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class HistoryPage:
    """One bounded page of the append-only history of one asset id."""

    asset_id: str
    items: tuple[HistoryView, ...]
    total: int
    limit: int
    offset: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "assetId": self.asset_id,
            "items": [item.as_payload() for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class PurgeResult:
    """The durable end of one asset; the id remains reserved by a tombstone."""

    asset_id: str
    quick_code: str
    purged_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.asset_id,
            "quickCode": self.quick_code,
            "purgedAt": _iso(self.purged_at),
        }


@dataclass(frozen=True)
class ImageContent:
    """Raw bytes of one stored image; adapters stream it, they never inline it."""

    role: str
    content_type: str
    data: bytes


@dataclass(frozen=True)
class ImageView:
    """Metadata of one stored image; the payload carries a URL, never bytes."""

    role: str
    content_type: str
    size: int
    url: str
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "contentType": self.content_type,
            "size": self.size,
            "url": self.url,
            "updatedAt": _iso(self.updated_at),
        }


class InventoryService:
    """The single implementation of inventory rules for every front door."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        source: str = DEFAULT_HISTORY_SOURCE,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._source = _history_source(source)
        self._catalog = InventoryCatalog(session, settings, identity=self._identity)
        self._pending_sequences: dict[str, int] = {}
        self._reserved_codes: set[str] = set()

    # ------------------------------------------------------------------ views
    def _image_url(self, asset_id: str, role: str) -> str:
        return f"{self._settings.api_prefix}/assets/{asset_id}/images/{role}"

    def _image_urls(self, asset_ids: Sequence[str]) -> dict[str, dict[str, str]]:
        if not asset_ids:
            return {}
        rows = self._session.execute(
            select(AssetMedia.asset_id, AssetMedia.role)
            .where(AssetMedia.asset_id.in_(list(asset_ids)))
            .order_by(AssetMedia.role)
        ).all()
        urls: dict[str, dict[str, str]] = {}
        for asset_id, role in rows:
            urls.setdefault(asset_id, {})[role] = self._image_url(asset_id, role)
        return urls

    def _view(
        self,
        asset: Asset,
        images: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        places: Mapping[str, str] | None = None,
    ) -> AssetView:
        stored_images = self._image_urls([asset.id]).get(asset.id, {}) if images is None else images
        label = None
        if asset.responsible_person_id is not None:
            if labels is None:
                labels = self._person_labels([asset.responsible_person_id])
            label = labels.get(asset.responsible_person_id)
        if places is None:
            places = self._place_names(
                [item for item in (asset.site_id, asset.location_id) if item]
            )
        site = asset.site if asset.site_id is None else places.get(asset.site_id, asset.site)
        location = (
            asset.location
            if asset.location_id is None
            else places.get(asset.location_id, asset.location)
        )
        responsible = asset.responsible
        if asset.responsible_person_id is not None and label is not None:
            responsible = label
        return AssetView(
            id=asset.id,
            quick_code=asset.quick_code,
            name=asset.name,
            category=asset.category,
            type=asset.type,
            brand=asset.brand,
            model=asset.model,
            serial=asset.serial,
            ip=asset.ip,
            site=site,
            location=location,
            responsible=responsible,
            site_id=asset.site_id,
            location_id=asset.location_id,
            responsible_person_id=asset.responsible_person_id,
            responsible_label=label,
            position_x=asset.position_x,
            position_y=asset.position_y,
            status=asset.status,
            description=asset.description,
            cost=None if asset.cost is None else Decimal(asset.cost),
            technical=asset.technical,
            archived=asset.archived_at is not None,
            archived_at=asset.archived_at,
            archived_by=asset.archived_by,
            images=dict(stored_images),
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )

    def _person_labels(self, person_ids: Sequence[str]) -> dict[str, str]:
        """Batched canonical labels; the stored text is never the label authority."""
        optional = [person_id for person_id in dict.fromkeys(person_ids) if person_id]
        if not optional:
            return {}
        from itsm.directory.models import DirectoryPerson
        from itsm.directory.service import format_person_label

        rows = self._session.execute(
            select(DirectoryPerson.id, DirectoryPerson.name, DirectoryPerson.job_title).where(
                DirectoryPerson.id.in_(optional)
            )
        ).all()
        return {row.id: format_person_label(row.name, row.job_title) for row in rows}

    def _place_names(self, location_ids: Sequence[str]) -> dict[str, str]:
        """Batched current directory names; a read never depends on the active flag."""
        optional = [location_id for location_id in dict.fromkeys(location_ids) if location_id]
        if not optional:
            return {}
        from itsm.directory.models import DirectoryLocation

        rows = self._session.execute(
            select(DirectoryLocation.id, DirectoryLocation.name).where(
                DirectoryLocation.id.in_(optional)
            )
        ).all()
        return {row.id: row.name for row in rows}

    def _views(self, assets: Iterable[Asset]) -> tuple[AssetView, ...]:
        stored = list(assets)
        urls = self._image_urls([asset.id for asset in stored])
        labels = self._person_labels(
            [asset.responsible_person_id for asset in stored if asset.responsible_person_id]
        )
        places = self._place_names(
            [item for asset in stored for item in (asset.site_id, asset.location_id) if item]
        )
        return tuple(self._view(asset, urls.get(asset.id, {}), labels, places) for asset in stored)

    def _views_by_ids(self, asset_ids: Sequence[str]) -> dict[str, AssetView]:
        """Batched projection for bounded graph queries; never one lookup per id."""
        unique_ids = list(dict.fromkeys(asset_ids))
        if not unique_ids:
            return {}
        stored = list(
            self._session.execute(select(Asset).where(Asset.id.in_(unique_ids))).scalars()
        )
        return {asset.id: view for asset, view in zip(stored, self._views(stored), strict=True)}

    # ------------------------------------------------------------ validation
    def _prepare_create(
        self, values: Mapping[str, Any], *, principal: Principal | None = None
    ) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("asset payload must be an object")
        unknown = sorted(set(values) - set(ASSET_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported asset fields: {', '.join(unknown)}")
        prepared: dict[str, Any] = {"name": _text(values.get("name"), "name", required=True)}
        for field in ASSET_FIELDS:
            if field == "name" or field not in values or values[field] is None:
                continue
            prepared[field] = (
                self._catalog.validate_status(values[field])
                if field == "status"
                else _normalize(field, values[field])
            )
        if principal is not None:
            self._organize(prepared, stored={}, principal=principal)
        requested = prepared.get("quick_code")
        prepared["quick_code"] = (
            allocate(self, prepared, requested=requested) or self._generate_quick_code()
        )
        prepared["status"] = self._catalog.validate_status(prepared.get("status", DEFAULT_STATUS))
        if self._catalog.category(prepared.get("category")) is not None:
            validated = self._catalog.validate_technical(
                prepared.get("category"), prepared.get("technical") or {}
            )
            if validated or "technical" in prepared:
                prepared["technical"] = validated
        return prepared

    def _prepare_changes(
        self,
        asset: Asset,
        changes: Mapping[str, Any],
        *,
        principal: Principal | None = None,
    ) -> dict[str, Any]:
        if not isinstance(changes, Mapping):
            raise ValidationFailed("asset payload must be an object")
        if "id" in changes:
            raise ValidationFailed("asset id is immutable")
        unknown = sorted(set(changes) - set(ASSET_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported asset fields: {', '.join(unknown)}")
        prepared: dict[str, Any] = {}
        for field, value in changes.items():
            if field == "name":
                prepared["name"] = _text(value, "name", required=True)
            elif field == "status":
                prepared["status"] = self._catalog.validate_status(value)
            elif field == "quick_code":
                quick_code = _quick_code(value)
                assert quick_code is not None
                prepared["quick_code"] = quick_code
            else:
                prepared[field] = _normalize(field, value)
        if not prepared:
            raise ValidationFailed("at least one field must be provided")
        if principal is not None:
            self._organize(prepared, stored=self._snapshot(asset), principal=principal)
        return prepared

    def _directory(self) -> Any:
        """One DirectoryService over the same session/identity; it never commits here."""
        from itsm.directory.service import DirectoryService

        return DirectoryService(self._session, self._settings, identity=self._identity)

    def _organize(
        self,
        prepared: dict[str, Any],
        *,
        stored: Mapping[str, Any],
        principal: Principal,
    ) -> None:
        """Resolve canonical references, mirrored labels and the optional position."""
        if not any(field in prepared for field in organization.RESOLVED_FIELDS):
            return
        resolved = organization.resolve(
            prepared,
            stored=stored,
            directory=self._directory(),
            principal=principal,
        )
        prepared.update(resolved)
        effective_location = prepared.get("location_id", stored.get("location_id"))
        if effective_location is None and stored.get("position_x") is not None:
            prepared.setdefault("position_x", None)
            prepared.setdefault("position_y", None)
        organization.check_position(prepared, location_id=effective_location)

    def _assert_quick_code_free(self, quick_code: str, *, exclude_id: str | None) -> None:
        statement = select(Asset.id).where(Asset.quick_code_key == quick_code.strip().lower())
        if exclude_id is not None:
            statement = statement.where(Asset.id != exclude_id)
        if self._session.execute(statement).first() is not None:
            raise Conflict("quickCode already exists")

    def _generate_quick_code(self) -> str:
        for _ in range(5):
            candidate = f"A-{uuid4().hex[:8]}"
            if (
                self._session.execute(
                    select(Asset.id).where(Asset.quick_code_key == candidate.lower())
                ).first()
                is None
            ):
                return candidate
        raise Conflict("could not allocate a unique quickCode")

    def _asset(self, asset_id: Any) -> Asset:
        if not isinstance(asset_id, str):
            raise ValidationFailed("asset id is required")
        try:
            UUID(asset_id)
        except ValueError:
            raise NotFound("asset not found") from None
        asset = self._session.get(Asset, asset_id)
        if asset is None:
            raise NotFound("asset not found")
        return asset

    # ------------------------------------------------------------ operations
    @serialized
    def create(self, principal: Principal, values: Mapping[str, Any]) -> AssetView:
        """Register one asset; a colliding numeric quick code advances, never a merge."""
        self._identity.authorize(principal, "assets.edit", resource="inventory:assets")
        prepared = self._prepare_create(values, principal=principal)
        if "responsible" in prepared or "responsible_person_id" in prepared:
            self._identity.authorize(
                principal, "assets.assign", resource=f"asset:{prepared['quick_code']}"
            )
        asset = self._new_asset(prepared)
        self._session.add(asset)
        self._flush_or_conflict()
        self._record_history(principal, asset, "created")
        self._identity.record_operation(
            principal, action="inventory.asset_created", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def update(self, principal: Principal, asset_id: Any, changes: Mapping[str, Any]) -> AssetView:
        """Apply an explicit field patch; the asset id never changes."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        prepared = self._prepare_changes(asset, changes, principal=principal)
        self._catalog_changes(asset, prepared)
        if "quick_code" in prepared:
            self._assert_quick_code_free(prepared["quick_code"], exclude_id=asset.id)
        if any(
            field in prepared and prepared[field] != getattr(asset, field)
            for field in ("responsible", "responsible_person_id")
        ):
            self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")
        before = self._snapshot(asset)
        self._apply(asset, prepared)
        self._flush_or_conflict()
        self._record_history(principal, asset, "updated", before=before)
        self._identity.record_operation(
            principal, action="inventory.asset_updated", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def assign_responsible(
        self,
        principal: Principal,
        asset_id: Any,
        person_id: Any,
        *,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> AssetView:
        """Assign one active directory person; asset, label, history and audit commit once."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")
        _assert_not_archived(asset)
        checked = organization.reference(person_id, "personId")
        if checked is None:
            raise ValidationFailed("personId is required")
        try:
            label = self._directory().person_label(principal, checked, require_active=True)
        except Conflict as error:
            raise ValidationFailed(str(error)) from None
        note = _reason(reason, required=False)
        observations = _notes(notes)
        effective = _effective_at(effective_at)
        if asset.responsible_person_id == checked and asset.responsible == label:
            raise Conflict("the person is already responsible for this asset")
        before = self._snapshot(asset)
        asset.responsible_person_id = checked
        asset.responsible = label
        asset.updated_at = utcnow()
        self._flush_or_conflict()
        self._record_history(
            principal,
            asset,
            "assigned",
            before=before,
            reason=note,
            notes=observations,
            effective_at=effective,
        )
        self._identity.record_operation(
            principal, action="inventory.responsible_assigned", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def return_responsible(
        self,
        principal: Principal,
        asset_id: Any,
        *,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> AssetView:
        """Return the asset: both the reference and its mirrored legacy text are cleared."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")
        if asset.responsible_person_id is None and asset.responsible is None:
            raise Conflict("asset has no responsible person")
        note = _reason(reason, required=False)
        observations = _notes(notes)
        effective = _effective_at(effective_at)
        before = self._snapshot(asset)
        asset.responsible_person_id = None
        asset.responsible = None
        asset.updated_at = utcnow()
        self._flush_or_conflict()
        self._record_history(
            principal,
            asset,
            "returned",
            before=before,
            reason=note,
            notes=observations,
            effective_at=effective,
        )
        self._identity.record_operation(
            principal, action="inventory.responsible_returned", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def transfer(
        self,
        principal: Principal,
        asset_id: Any,
        *,
        site_id: Any = None,
        location_id: Any = _UNSET,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> AssetView:
        """Move an asset to another site/location; the UUID and technical data stay."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        _assert_not_archived(asset)
        if site_id is None and location_id is _UNSET:
            raise ValidationFailed("siteId or locationId is required")
        changes: dict[str, Any] = {}
        if site_id is not None:
            changes["site_id"] = site_id
        if location_id is not _UNSET:
            changes["location_id"] = location_id
        prepared = self._prepare_changes(asset, changes, principal=principal)
        if not any(
            prepared[field] != getattr(asset, field)
            for field in prepared
            if field in _HISTORY_FIELDS
        ):
            raise Conflict("asset is already in that location")
        note = _reason(reason, required=False)
        observations = _notes(notes)
        effective = _effective_at(effective_at)
        self._catalog_changes(asset, prepared)
        before = self._snapshot(asset)
        self._apply(asset, prepared)
        self._flush_or_conflict()
        self._record_history(
            principal,
            asset,
            "transferred",
            before=before,
            reason=note,
            notes=observations,
            effective_at=effective,
        )
        self._identity.record_operation(
            principal, action="inventory.asset_transferred", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    def get(self, principal: Principal, asset_id: Any) -> AssetView:
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.view", resource=f"asset:{asset.id}")
        return self._view(asset)

    def search(
        self,
        principal: Principal,
        *,
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: str | None = None,
        asset_id: str | None = None,
        site_id: str | None = None,
        location_id: str | None = None,
        responsible_person_id: str | None = None,
        archived: bool | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> InventoryPage:
        """Bounded SQL search; the same interface can later be backed by Meilisearch."""
        self._identity.authorize(principal, "assets.view", resource="inventory:assets")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
            raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationFailed("offset must be zero or greater")
        if archived is not None and not isinstance(archived, bool):
            raise ValidationFailed("archived must be a boolean")

        filters: list[ColumnElement[bool]] = []
        text_query = _text(query, "query")
        if text_query:
            pattern = f"%{_escape_like(text_query)}%"
            filters.append(
                or_(
                    *(
                        getattr(Asset, column).ilike(pattern, escape="\\")
                        for column in _SEARCH_COLUMNS
                    )
                )
            )
        category_value = _text(category, "category")
        if category_value:
            filters.append(Asset.category.ilike(_escape_like(category_value), escape="\\"))
        site_value = _text(site, "site")
        if site_value:
            filters.append(Asset.site.ilike(_escape_like(site_value), escape="\\"))
        site_reference = organization.reference(site_id, "siteId")
        if site_reference is not None:
            filters.append(Asset.site_id == site_reference)
        location_reference = organization.reference(location_id, "locationId")
        if location_reference is not None:
            subtree = organization.descendant_ids(self._session, location_reference)
            filters.append(Asset.location_id.in_(subtree))
        person_reference = organization.reference(responsible_person_id, "responsiblePersonId")
        if person_reference is not None:
            filters.append(Asset.responsible_person_id == person_reference)
        if status is not None:
            filters.append(Asset.status == _status(status))
        quick_code_value = _quick_code(quick_code, required=False)
        if quick_code_value:
            filters.append(Asset.quick_code_key == quick_code_value.lower())
        if asset_id is not None:
            filters.append(Asset.id == self._asset(asset_id).id)
        if archived is True:
            filters.append(Asset.archived_at.is_not(None))
        elif archived is False:
            filters.append(Asset.archived_at.is_(None))

        total = self._session.execute(
            select(func.count(Asset.id)).select_from(Asset).where(*filters)
        ).scalar_one()
        rows = self._session.execute(
            select(Asset)
            .where(*filters)
            .order_by(Asset.updated_at.desc(), Asset.id.asc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return InventoryPage(
            items=self._views(rows),
            total=int(total),
            limit=limit,
            offset=offset,
        )

    def map(
        self,
        principal: Principal,
        *,
        site_id: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> AssetMap:
        """Bounded organizational map: sites plus the assets that declare a position."""
        self._identity.authorize(principal, "assets.view", resource="inventory:assets")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
            raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationFailed("offset must be zero or greater")
        directory = self._directory()
        checked = organization.reference(site_id, "siteId")
        site_total = 0
        if checked is not None:
            view = directory.get_location(principal, checked)
            if view.level != "site":
                raise ValidationFailed("siteId must reference a site")
            sites: tuple[Any, ...] = (view,)
            site_total = 1
        else:
            page = directory.list_locations(
                principal, level="site", active=True, limit=MAX_LIMIT, offset=0
            )
            sites = page.items
            site_total = page.total

        filters: list[ColumnElement[bool]] = [Asset.position_x.is_not(None)]
        if checked is not None:
            filters.append(Asset.site_id == checked)
        rows = list(
            self._session.execute(
                select(Asset)
                .where(*filters)
                .order_by(Asset.updated_at.desc(), Asset.id.asc())
                .limit(limit + 1)
                .offset(offset)
            ).scalars()
        )
        positions = tuple(
            MapPosition(
                asset_id=asset.id,
                quick_code=asset.quick_code,
                name=asset.name,
                site_id=asset.site_id or "",
                location_id=asset.location_id or "",
                x=organization.number(asset.position_x),
                y=organization.number(asset.position_y),
            )
            for asset in rows[:limit]
        )
        return AssetMap(
            sites=tuple(
                MapSite(
                    id=view.id,
                    name=view.name,
                    latitude=view.latitude,
                    longitude=view.longitude,
                )
                for view in sites
            ),
            positions=positions,
            limit=limit,
            offset=offset,
            truncated=len(rows) > limit or site_total > len(sites),
        )

    @serialized
    def batch(
        self,
        principal: Principal,
        *,
        create: Sequence[Mapping[str, Any]] = (),
        update: Sequence[Mapping[str, Any]] = (),
    ) -> BatchResult:
        """Atomic bounded batch; a conflict or validation failure changes nothing."""
        creates = list(create)
        updates = list(update)
        total = len(creates) + len(updates)
        if total == 0:
            raise ValidationFailed("batch requires at least one operation")
        if total > BATCH_LIMIT:
            raise ValidationFailed(f"batch is limited to {BATCH_LIMIT} operations")

        for _ in creates:
            self._identity.authorize(principal, "assets.edit", resource="inventory:assets")
        for changes in updates:
            if not isinstance(changes, Mapping):
                raise ValidationFailed("each update must be an object")
            asset = self._asset(changes.get("id"))
            self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
            if "responsible" in changes or "responsible_person_id" in changes:
                self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")

        prepared_creates: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        for values in creates:
            prepared = self._prepare_create(values, principal=principal)
            if "responsible" in prepared or "responsible_person_id" in prepared:
                self._identity.authorize(
                    principal, "assets.assign", resource=f"asset:{prepared['quick_code']}"
                )
            key = prepared["quick_code"].lower()
            if key in seen_keys:
                raise Conflict("quickCode already exists")
            seen_keys.add(key)
            prepared_creates.append(prepared)

        prepared_updates: list[tuple[Asset, dict[str, Any], dict[str, Any]]] = []
        update_keys: set[str] = set()
        for changes in updates:
            asset = self._asset(changes.get("id"))
            prepared = self._prepare_changes(
                asset,
                {key: value for key, value in changes.items() if key != "id"},
                principal=principal,
            )
            self._catalog_changes(asset, prepared)
            if "quick_code" in prepared:
                key = prepared["quick_code"].lower()
                if key in update_keys:
                    raise Conflict("quickCode already exists")
                update_keys.add(key)
                self._assert_quick_code_free(prepared["quick_code"], exclude_id=asset.id)
            prepared_updates.append((asset, prepared, self._snapshot(asset)))

        created: list[Asset] = []
        for prepared in prepared_creates:
            asset = self._new_asset(prepared)
            self._session.add(asset)
            created.append(asset)
        for asset, prepared, _ in prepared_updates:
            self._apply(asset, prepared)
        self._flush_or_conflict()

        for asset in created:
            self._record_history(principal, asset, "created")
        for asset, _, before in prepared_updates:
            self._record_history(principal, asset, "updated", before=before)
        self._session.flush()

        if created:
            self._identity.record_operation(
                principal,
                action="inventory.assets_batch_created",
                resource=f"inventory:assets:created:{len(created)}",
            )
        if prepared_updates:
            self._identity.record_operation(
                principal,
                action="inventory.assets_batch_updated",
                resource=f"inventory:assets:updated:{len(prepared_updates)}",
            )
        return BatchResult(
            created=self._views(created),
            updated=self._views(asset for asset, _, _ in prepared_updates),
        )

    @serialized
    def clone(
        self,
        principal: Principal,
        asset_id: Any,
        changes: Mapping[str, Any] | None = None,
    ) -> AssetView:
        """Duplicate one asset under a new permanent UUID; the source is untouched."""
        source = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{source.id}")
        values: dict[str, Any] = {
            field: getattr(source, field)
            for field in _HISTORY_FIELDS
            if getattr(source, field) is not None
            and not (
                field in organization.LEGACY_FIELDS
                and getattr(source, organization.MIRROR_IDS[field]) is not None
            )
        }
        if changes is not None:
            if not isinstance(changes, Mapping):
                raise ValidationFailed("asset payload must be an object")
            if "id" in changes:
                raise ValidationFailed("asset id is immutable")
            unknown = sorted(set(changes) - set(ASSET_FIELDS))
            if unknown:
                raise ValidationFailed(f"unsupported asset fields: {', '.join(unknown)}")
            values.update(changes)
        prepared = self._prepare_create(values, principal=principal)
        if "responsible" in prepared or "responsible_person_id" in prepared:
            self._identity.authorize(
                principal, "assets.assign", resource=f"asset:{prepared['quick_code']}"
            )
        asset = self._new_asset(prepared)
        self._session.add(asset)
        self._flush_or_conflict()
        self._record_history(principal, asset, "cloned", reason=f"source:{source.id}")
        self._identity.record_operation(
            principal, action="inventory.asset_cloned", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def archive(self, principal: Principal, asset_id: Any, *, reason: Any = None) -> AssetView:
        """Flag the asset as archived without touching status, owner or location."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        if asset.archived_at is not None:
            raise Conflict("asset is already archived")
        note = _reason(reason, required=False)
        before = self._snapshot(asset)
        now = utcnow()
        asset.archived_at = now
        asset.archived_by = principal.username
        asset.updated_at = now
        self._flush_or_conflict()
        self._record_history(principal, asset, "archived", before=before, reason=note)
        self._identity.record_operation(
            principal, action="inventory.asset_archived", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def restore(self, principal: Principal, asset_id: Any) -> AssetView:
        """Clear the archive flag after revalidating every effective reference."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        if asset.archived_at is None:
            raise Conflict("asset is not archived")
        before = self._snapshot(asset)
        organization.validate_stored(before, directory=self._directory(), principal=principal)
        asset.archived_at = None
        asset.archived_by = None
        asset.updated_at = utcnow()
        self._flush_or_conflict()
        self._record_history(principal, asset, "restored", before=before)
        self._identity.record_operation(
            principal, action="inventory.asset_restored", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def retire(self, principal: Principal, asset_id: Any, *, reason: Any) -> AssetView:
        """Retire with a reason; the responsible is cleared as the prototype did."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        note = _reason(reason, required=True)
        assert note is not None
        if asset.status == "retired":
            raise Conflict("asset is already retired")
        if asset.responsible is not None or asset.responsible_person_id is not None:
            self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")
        before = self._snapshot(asset)
        self._catalog.validate_transition(asset.category, asset.status, "retired")
        asset.status = "retired"
        asset.responsible = None
        asset.responsible_person_id = None
        asset.updated_at = utcnow()
        self._flush_or_conflict()
        self._record_history(principal, asset, "retired", before=before, reason=note)
        self._identity.record_operation(
            principal, action="inventory.asset_retired", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    @serialized
    def purge(
        self,
        principal: Principal,
        asset_id: Any,
        *,
        confirm: bool = False,
        typed_id: str | None = None,
        reason: Any = None,
    ) -> PurgeResult:
        """Permanently remove one asset under the rules of the current environment.

        A machine actor is always refused. In ``production`` the caller needs the
        distinct ``assets.purge`` privilege, an archived asset, the exact UUID
        typed and a reason. In ``development``/``test`` an explicit confirmation
        plus ``assets.edit`` is enough. History rows and a tombstone survive.
        """
        asset = self._asset(asset_id)
        if principal.kind != HUMAN_ACTOR_KIND:
            self._identity.record_operation(
                principal,
                action="assets.purge",
                resource=f"asset:{asset.id}",
                outcome="denied",
            )
            raise PermissionDenied("only a human identity may purge an asset")
        production = self._settings.environment == "production"
        if production:
            self._identity.authorize(principal, "assets.purge", resource=f"asset:{asset.id}")
            if asset.archived_at is None:
                raise Conflict("only an archived asset can be purged")
        else:
            self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        if confirm is not True:
            raise ValidationFailed("permanent purge requires explicit confirmation")
        note: str | None
        if production:
            if not isinstance(typed_id, str) or typed_id.strip() != asset.id:
                raise ValidationFailed("permanent purge requires the asset id to be typed exactly")
            note = _reason(reason, required=True)
        else:
            note = _reason(reason, required=False)

        purged_at = utcnow()
        quick_code = asset.quick_code
        self._assert_no_relationships(asset.id)
        self._session.execute(delete(AssetMedia).where(AssetMedia.asset_id == asset.id))
        self._session.add(
            AssetTombstone(
                id=asset.id,
                quick_code=quick_code,
                purged_at=purged_at,
                purged_by=principal.username,
                reason=note or "permanent purge",
            )
        )
        self._record_history(principal, asset, "purged", reason=note, cleared=True)
        self._session.delete(asset)
        self._flush_or_conflict()
        self._identity.record_operation(
            principal, action="inventory.asset_purged", resource=f"asset:{quick_code}"
        )
        return PurgeResult(asset_id=asset.id, quick_code=quick_code, purged_at=purged_at)

    def history(
        self,
        principal: Principal,
        asset_id: Any,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> HistoryPage:
        """Read the append-only history of an asset id, including a purged one."""
        if not isinstance(asset_id, str):
            raise ValidationFailed("asset id is required")
        try:
            UUID(asset_id)
        except ValueError:
            raise NotFound("asset not found") from None
        self._identity.authorize(principal, "assets.view", resource=f"asset:{asset_id}")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= HISTORY_LIMIT:
            raise ValidationFailed(f"limit must be between 1 and {HISTORY_LIMIT}")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationFailed("offset must be zero or greater")
        total = int(
            self._session.execute(
                select(func.count(AssetHistory.id)).where(AssetHistory.asset_id == asset_id)
            ).scalar_one()
        )
        if total == 0 and self._session.get(Asset, asset_id) is None:
            raise NotFound("asset not found")
        rows = self._session.execute(
            select(AssetHistory)
            .where(AssetHistory.asset_id == asset_id)
            .order_by(AssetHistory.sequence.asc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return HistoryPage(
            asset_id=asset_id,
            items=tuple(self._history_view(entry) for entry in rows),
            total=total,
            limit=limit,
            offset=offset,
        )

    # ------------------------------------------------------------------ media
    def image(self, principal: Principal, asset_id: Any, role: Any) -> ImageContent:
        """Read one stored image with ``assets.view``; bytes never enter the DTO."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.view", resource=f"asset:{asset.id}")
        checked_role = validate_role(role)
        media = self._media(asset.id, checked_role)
        if media is None:
            raise NotFound("image not found")
        return ImageContent(
            role=checked_role, content_type=media.content_type, data=bytes(media.data)
        )

    @serialized
    def set_image(self, principal: Principal, asset_id: Any, role: Any, data: Any) -> ImageView:
        """Create or replace one validated image; ``photo`` and ``fov`` are independent."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        checked_role = validate_role(role)
        upload = validate_image(role=checked_role, category=asset.category, data=data)
        now = utcnow()
        media = self._media(asset.id, checked_role)
        if media is None:
            media = AssetMedia(
                id=str(uuid4()),
                asset_id=asset.id,
                role=checked_role,
                content_type=upload.content_type,
                size=upload.size,
                data=upload.data,
                updated_by=principal.username,
                created_at=now,
                updated_at=now,
            )
            self._session.add(media)
        else:
            media.content_type = upload.content_type
            media.size = upload.size
            media.data = upload.data
            media.updated_by = principal.username
            media.updated_at = now
        self._flush_or_conflict()
        self._identity.record_operation(
            principal,
            action="inventory.asset_image_updated",
            resource=f"asset:{asset.id}:{checked_role}",
        )
        return self._image_view(asset.id, checked_role, media)

    @serialized
    def remove_image(self, principal: Principal, asset_id: Any, role: Any) -> None:
        """Remove one image role; the other role and the asset are untouched."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        checked_role = validate_role(role)
        media = self._media(asset.id, checked_role)
        if media is None:
            raise NotFound("image not found")
        self._session.delete(media)
        self._flush_or_conflict()
        self._identity.record_operation(
            principal,
            action="inventory.asset_image_removed",
            resource=f"asset:{asset.id}:{checked_role}",
        )

    # --------------------------------------------------------------- helpers
    def _media(self, asset_id: str, role: str) -> AssetMedia | None:
        return self._session.execute(
            select(AssetMedia).where(AssetMedia.asset_id == asset_id, AssetMedia.role == role)
        ).scalar_one_or_none()

    def _image_view(self, asset_id: str, role: str, media: AssetMedia) -> ImageView:
        return ImageView(
            role=role,
            content_type=media.content_type,
            size=int(media.size),
            url=self._image_url(asset_id, role),
            updated_at=media.updated_at,
        )

    def _history_view(self, entry: AssetHistory) -> HistoryView:
        return HistoryView(
            id=entry.id,
            sequence=int(entry.sequence),
            asset_id=entry.asset_id,
            action=entry.action,
            quick_code_old=entry.quick_code_old,
            quick_code_new=entry.quick_code_new,
            status_old=entry.status_old,
            status_new=entry.status_new,
            archived_old=entry.archived_old,
            archived_new=entry.archived_new,
            changes=entry.changes or {},
            reason=entry.reason,
            actor_id=entry.actor_id,
            actor_username=entry.actor_username,
            source=entry.source,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            effective_at=None if entry.effective_at is None else as_utc(entry.effective_at),
            notes=entry.notes,
            created_at=entry.created_at,
        )

    def _snapshot(self, asset: Asset) -> dict[str, Any]:
        snapshot: dict[str, Any] = {field: getattr(asset, field) for field in _HISTORY_FIELDS}
        snapshot["quick_code"] = asset.quick_code
        snapshot["archived"] = asset.archived_at is not None
        return snapshot

    def _diff(self, before: Mapping[str, Any] | None, after: Mapping[str, Any]) -> dict[str, Any]:
        changes: dict[str, Any] = {}
        for field in sorted(after):
            old = None if before is None else before.get(field)
            new = after[field]
            if new is None and old is None:
                continue
            if before is not None and old == new:
                continue
            changes[field] = {"old": _json_value(old), "new": _json_value(new)}
        return changes

    def _next_sequence(self) -> int:
        current = self._session.execute(
            select(func.coalesce(func.max(AssetHistory.sequence), 0))
        ).scalar_one()
        return int(current) + 1

    def _record_history(
        self,
        principal: Principal,
        asset: Asset,
        action: str,
        *,
        before: Mapping[str, Any] | None = None,
        reason: str | None = None,
        cleared: bool = False,
        changes: Mapping[str, Any] | None = None,
        notes: Any = None,
        effective_at: Any = None,
        source: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
    ) -> None:
        """Append one structured event; relation code calls this instead of copying rules.

        Asset lifecycle callers keep the previous behavior. Relationship callers
        pass an explicit ``changes`` object plus the trusted origin/entity and the
        optional effective time, reason and observations. The row shares the same
        transaction as the business write.
        """
        snapshot = self._snapshot(asset)
        old_state: Mapping[str, Any]
        new_state: Mapping[str, Any]
        if changes is not None:
            old_state = snapshot
            new_state = snapshot
            prepared_changes = dict(changes)
        elif cleared:
            old_state = snapshot
            new_state = dict.fromkeys(snapshot)
            prepared_changes = {
                field: {"old": _json_value(value), "new": None}
                for field, value in snapshot.items()
                if value is not None
            }
        else:
            old_state = before or {}
            new_state = snapshot
            prepared_changes = self._diff(before, snapshot)
        metadata_source = self._source if source is None else _history_source(source)
        metadata_entity_type = "asset" if entity_type is None else _entity_type(entity_type)
        metadata_entity_id = asset.id if entity_id is None else _entity_id(entity_id)
        sequence = self._next_sequence()
        self._session.add(
            AssetHistory(
                id=str(uuid4()),
                sequence=sequence,
                asset_id=asset.id,
                action=action,
                quick_code_old=old_state.get("quick_code"),
                quick_code_new=new_state.get("quick_code"),
                status_old=old_state.get("status"),
                status_new=new_state.get("status"),
                archived_old=old_state.get("archived"),
                archived_new=new_state.get("archived"),
                changes=prepared_changes,
                reason=reason,
                actor_id=principal.actor_id,
                actor_username=principal.username,
                source=metadata_source,
                entity_type=metadata_entity_type,
                entity_id=metadata_entity_id,
                effective_at=_effective_at(effective_at),
                notes=_notes(notes),
                created_at=utcnow(),
            )
        )

    def _assert_no_relationships(self, asset_id: str) -> None:
        """Purge guard: an asset with edges cannot be permanently removed."""
        from itsm.relationships.models import Relationship

        related = self._session.execute(
            select(Relationship.id)
            .where(or_(Relationship.source_id == asset_id, Relationship.target_id == asset_id))
            .limit(1)
        ).first()
        if related is not None:
            raise Conflict("asset has relationships; remove them before a permanent purge")

    def _new_asset(self, prepared: Mapping[str, Any]) -> Asset:
        now = utcnow()
        asset = Asset(
            id=self._new_asset_id(),
            quick_code=prepared["quick_code"],
            quick_code_key=prepared["quick_code"].lower(),
            created_at=now,
            updated_at=now,
        )
        self._apply(asset, prepared)
        return asset

    def _new_asset_id(self) -> str:
        for _ in range(5):
            candidate = str(uuid4())
            if self._session.get(AssetTombstone, candidate) is None:
                return candidate
        raise Conflict("could not allocate a unique asset id")

    def _apply(self, asset: Asset, prepared: Mapping[str, Any]) -> None:
        for field, value in prepared.items():
            if field == "quick_code":
                asset.quick_code = value
                asset.quick_code_key = value.lower()
            elif field == "cost":
                asset.cost = _stored_cost(value)
            elif field == "technical":
                asset.technical = dict(value) if value is not None else None
            else:
                setattr(asset, field, value)
        asset.updated_at = utcnow()

    def _catalog_changes(self, asset: Asset, prepared: dict[str, Any]) -> None:
        category = prepared.get("category", asset.category)
        if "status" in prepared:
            self._catalog.validate_transition(category, asset.status, prepared["status"])
        if self._catalog.category(category) is not None and (
            "technical" in prepared or "category" in prepared
        ):
            prepared["technical"] = self._catalog.validate_technical(
                category, prepared.get("technical") or {}, previous=asset.technical or {}
            )
        if "quick_code" in prepared:
            prepared["quick_code"] = allocate(
                self,
                {**self._snapshot(asset), **prepared},
                requested=prepared["quick_code"],
                exclude_id=asset.id,
            )
        elif any(
            field in prepared and prepared[field] != getattr(asset, field)
            for field in ("category", "type", "site", "location")
        ):
            code = allocate(self, {**self._snapshot(asset), **prepared}, exclude_id=asset.id)
            if code is not None:
                prepared["quick_code"] = code

    def _flush_or_conflict(self) -> None:
        try:
            for key, next_value in self._pending_sequences.items():
                sequence = self._session.get(InventoryCodeSequence, key)
                if sequence is None:
                    self._session.add(InventoryCodeSequence(key=key, next_value=next_value))
                else:
                    sequence.next_value = max(sequence.next_value, next_value)
            self._pending_sequences.clear()
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            raise Conflict("quickCode already exists") from None


__all__ = [
    "ASSET_FIELDS",
    "BATCH_LIMIT",
    "DEFAULT_LIMIT",
    "HISTORY_LIMIT",
    "MAX_LIMIT",
    "MEDIA_ROLES",
    "REASON_MAX",
    "REASON_MIN",
    "STATUSES",
    "AssetMap",
    "AssetView",
    "BatchResult",
    "HistoryPage",
    "HistoryView",
    "ImageContent",
    "ImageView",
    "InventoryPage",
    "InventoryService",
    "PermissionDenied",
    "PurgeResult",
    "ValidationFailed",
    "iter_statuses",
]


def iter_statuses() -> Iterable[str]:
    """Expose the bounded status values for adapters and documentation."""
    return iter(STATUSES)
