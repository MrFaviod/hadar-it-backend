"""Canonical inventory service: validation, authorization, SQL access and audit.

REST handlers, the Pydantic AI tools and the FastMCP tools are thin adapters over
this module. Nothing here trusts a caller-supplied identity, permission or
database handle: every operation resolves a ``Principal`` through the identity
service and asks it to authorize the concrete permission it needs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from itsm.inventory.models import Asset

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
BATCH_LIMIT = 50
SEARCH_TEXT_LIMIT = 120

STATUSES: tuple[str, ...] = ("in_use", "in_storage", "maintenance", "retired")
DEFAULT_STATUS = STATUSES[0]

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

_QUICK_CODE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,31}$")
_SEARCH_COLUMNS = ("name", "quick_code", "serial", "brand", "model", "responsible", "ip")


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


def _normalize(field: str, value: Any) -> str | None:
    if field == "quick_code":
        return _quick_code(value)
    if field == "status":
        return _status(value)
    return _text(value, field)


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
    status: str
    description: str | None
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
            "status": self.status,
            "description": self.description,
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


class InventoryService:
    """The single implementation of inventory rules for every front door."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)

    # ------------------------------------------------------------------ views
    def _view(self, asset: Asset) -> AssetView:
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
            site=asset.site,
            location=asset.location,
            responsible=asset.responsible,
            status=asset.status,
            description=asset.description,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )

    # ------------------------------------------------------------ validation
    def _prepare_create(self, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("asset payload must be an object")
        unknown = sorted(set(values) - set(FIELD_LIMITS))
        if unknown:
            raise ValidationFailed(f"unsupported asset fields: {', '.join(unknown)}")
        prepared: dict[str, Any] = {"name": _text(values.get("name"), "name", required=True)}
        for field in FIELD_LIMITS:
            if field == "name" or field not in values or values[field] is None:
                continue
            prepared[field] = _normalize(field, values[field])
        if prepared.get("quick_code") is None:
            prepared["quick_code"] = self._generate_quick_code()
        else:
            self._assert_quick_code_free(prepared["quick_code"], exclude_id=None)
        if prepared.get("status") is None:
            prepared["status"] = DEFAULT_STATUS
        return prepared

    def _prepare_changes(self, changes: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(changes, Mapping):
            raise ValidationFailed("asset payload must be an object")
        if "id" in changes:
            raise ValidationFailed("asset id is immutable")
        unknown = sorted(set(changes) - set(FIELD_LIMITS))
        if unknown:
            raise ValidationFailed(f"unsupported asset fields: {', '.join(unknown)}")
        prepared: dict[str, Any] = {}
        for field, value in changes.items():
            if field == "name":
                prepared["name"] = _text(value, "name", required=True)
            elif field == "status":
                prepared["status"] = _status(value)
            elif field == "quick_code":
                quick_code = _quick_code(value)
                assert quick_code is not None
                prepared["quick_code"] = quick_code
            else:
                prepared[field] = _normalize(field, value)
        if not prepared:
            raise ValidationFailed("at least one field must be provided")
        return prepared

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
    def create(self, principal: Principal, values: Mapping[str, Any]) -> AssetView:
        """Register one asset; a duplicate quick code is a conflict, never a merge."""
        self._identity.authorize(principal, "assets.edit", resource="inventory:assets")
        prepared = self._prepare_create(values)
        if "responsible" in prepared:
            self._identity.authorize(
                principal, "assets.assign", resource=f"asset:{prepared['quick_code']}"
            )
        asset = self._new_asset(prepared)
        self._session.add(asset)
        self._flush_or_conflict()
        self._identity.record_operation(
            principal, action="inventory.asset_created", resource=f"asset:{asset.id}"
        )
        return self._view(asset)

    def update(self, principal: Principal, asset_id: Any, changes: Mapping[str, Any]) -> AssetView:
        """Apply an explicit field patch; the asset id never changes."""
        asset = self._asset(asset_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset.id}")
        prepared = self._prepare_changes(changes)
        if "quick_code" in prepared:
            self._assert_quick_code_free(prepared["quick_code"], exclude_id=asset.id)
        if "responsible" in prepared and prepared["responsible"] != asset.responsible:
            self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")
        self._apply(asset, prepared)
        self._flush_or_conflict()
        self._identity.record_operation(
            principal, action="inventory.asset_updated", resource=f"asset:{asset.id}"
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
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> InventoryPage:
        """Bounded SQL search; the same interface can later be backed by Meilisearch."""
        self._identity.authorize(principal, "assets.view", resource="inventory:assets")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
            raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValidationFailed("offset must be zero or greater")

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
        if status is not None:
            filters.append(Asset.status == _status(status))
        quick_code_value = _quick_code(quick_code, required=False)
        if quick_code_value:
            filters.append(Asset.quick_code_key == quick_code_value.lower())
        if asset_id is not None:
            filters.append(Asset.id == self._asset(asset_id).id)

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
            items=tuple(self._view(asset) for asset in rows),
            total=int(total),
            limit=limit,
            offset=offset,
        )

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
            if "responsible" in changes:
                self._identity.authorize(principal, "assets.assign", resource=f"asset:{asset.id}")

        prepared_creates: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        for values in creates:
            prepared = self._prepare_create(values)
            if "responsible" in prepared:
                self._identity.authorize(
                    principal, "assets.assign", resource=f"asset:{prepared['quick_code']}"
                )
            key = prepared["quick_code"].lower()
            if key in seen_keys:
                raise Conflict("quickCode already exists")
            seen_keys.add(key)
            prepared_creates.append(prepared)

        prepared_updates: list[tuple[Asset, dict[str, Any]]] = []
        update_keys: set[str] = set()
        for changes in updates:
            asset = self._asset(changes.get("id"))
            prepared = self._prepare_changes(
                {key: value for key, value in changes.items() if key != "id"}
            )
            if "quick_code" in prepared:
                key = prepared["quick_code"].lower()
                if key in update_keys:
                    raise Conflict("quickCode already exists")
                update_keys.add(key)
                self._assert_quick_code_free(prepared["quick_code"], exclude_id=asset.id)
            prepared_updates.append((asset, prepared))

        created: list[Asset] = []
        for prepared in prepared_creates:
            asset = self._new_asset(prepared)
            self._session.add(asset)
            created.append(asset)
        for asset, prepared in prepared_updates:
            self._apply(asset, prepared)
        self._flush_or_conflict()

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
            created=tuple(self._view(asset) for asset in created),
            updated=tuple(self._view(asset) for asset, _ in prepared_updates),
        )

    # --------------------------------------------------------------- helpers
    def _new_asset(self, prepared: Mapping[str, Any]) -> Asset:
        now = utcnow()
        asset = Asset(
            id=str(uuid4()),
            quick_code=prepared["quick_code"],
            quick_code_key=prepared["quick_code"].lower(),
            created_at=now,
            updated_at=now,
        )
        self._apply(asset, prepared)
        return asset

    def _apply(self, asset: Asset, prepared: Mapping[str, Any]) -> None:
        for field, value in prepared.items():
            if field == "quick_code":
                asset.quick_code = value
                asset.quick_code_key = value.lower()
            else:
                setattr(asset, field, value)
        asset.updated_at = utcnow()

    def _flush_or_conflict(self) -> None:
        try:
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            raise Conflict("quickCode already exists") from None


__all__ = [
    "BATCH_LIMIT",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "STATUSES",
    "AssetView",
    "BatchResult",
    "InventoryPage",
    "InventoryService",
    "PermissionDenied",
    "ValidationFailed",
]


def iter_statuses() -> Iterable[str]:
    """Expose the bounded status values for adapters and documentation."""
    return iter(STATUSES)
