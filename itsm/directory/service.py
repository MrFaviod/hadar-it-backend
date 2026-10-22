"""Canonical directory service: people, departments and hierarchical locations.

An inventory person is a responsibility record, never an access account: this
module creates no credential, session or identity, and it never matches the
legacy free-text ``Asset.responsible`` or ``Identity.person_id`` values to a
person. REST, the Pydantic AI tools and the FastMCP tools are thin adapters over
this service; validation, SQL and authorization live here only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.directory.models import (
    DirectoryDepartment,
    DirectoryEvent,
    DirectoryLocation,
    DirectoryPerson,
)
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    Principal,
    ValidationFailed,
)
from itsm.inventory.codes import serialized

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
HISTORY_LIMIT = MAX_LIMIT

DEFAULT_TREE_DEPTH = 2
MAX_TREE_DEPTH = 4
DEFAULT_TREE_NODES = 200
MAX_TREE_NODES = 500

LEVELS: tuple[str, ...] = ("site", "building", "floor", "room_zone")
LEVEL_PARENT: dict[str, str | None] = {
    "site": None,
    "building": "site",
    "floor": "building",
    "room_zone": "floor",
}
LEVEL_DEPTH: dict[str, int] = {"site": 1, "building": 2, "floor": 3, "room_zone": 4}

PERSON_STATUSES: tuple[str, ...] = ("active", "inactive")
DEFAULT_PERSON_STATUS = PERSON_STATUSES[0]

SOURCES: tuple[str, ...] = ("rest", "agent", "mcp", "internal")
DEFAULT_SOURCE = "internal"
DirectorySource = Literal["rest", "agent", "mcp", "internal"]

ENTITIES: tuple[str, ...] = ("person", "department", "location")

DEPARTMENT_NAME_MAX = 120
PERSON_NAME_MAX = 160
PERSON_JOB_TITLE_MAX = 120
CONTACT_EMAIL_MAX = 254
CONTACT_PHONE_MAX = 40
LOCATION_NAME_MAX = 120
LOCATION_DESCRIPTION_MAX = 1000
PLAN_REF_MAX = 64
PLAN_PAGE_MAX = 32
SEARCH_TEXT_LIMIT = 120
REASON_MAX = 500
NOTES_MAX = 1000

COORDINATE_MAX_DECIMALS = 9

LATITUDE_BOUND = Decimal("90")
LONGITUDE_BOUND = Decimal("180")

PERSON_FIELDS: tuple[str, ...] = (
    "name",
    "job_title",
    "department_id",
    "site_id",
    "contact_email",
    "contact_phone",
    "status",
)
DEPARTMENT_CHANGE_FIELDS: tuple[str, ...] = ("name", "active")
LOCATION_FIELDS: tuple[str, ...] = (
    "level",
    "parent_id",
    "name",
    "description",
    "latitude",
    "longitude",
    "plan_ref",
    "plan_page",
)
LOCATION_CHANGE_FIELDS: tuple[str, ...] = (
    "parent_id",
    "name",
    "description",
    "latitude",
    "longitude",
    "plan_ref",
    "plan_page",
    "active",
)


def _iso(value: datetime) -> str:
    return as_utc(value).isoformat()


@dataclass(frozen=True)
class DepartmentView:
    id: str
    name: str
    active: bool
    created_at: datetime
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "active": self.active,
            "createdAt": _iso(self.created_at),
            "updatedAt": _iso(self.updated_at),
        }


@dataclass(frozen=True)
class PersonView:
    id: str
    name: str
    job_title: str | None
    department_id: str | None
    site_id: str | None
    contact_email: str | None
    contact_phone: str | None
    status: str
    created_at: datetime
    updated_at: datetime

    @property
    def label(self) -> str:
        """Canonical label the parent uses instead of legacy free-text matching."""
        return self.name if not self.job_title else f"{self.name} ({self.job_title})"

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "label": self.label,
            "jobTitle": self.job_title,
            "departmentId": self.department_id,
            "siteId": self.site_id,
            "contactEmail": self.contact_email,
            "contactPhone": self.contact_phone,
            "status": self.status,
            "createdAt": _iso(self.created_at),
            "updatedAt": _iso(self.updated_at),
        }


@dataclass(frozen=True)
class LocationView:
    id: str
    level: str
    parent_id: str | None
    name: str
    description: str | None
    latitude: float | None
    longitude: float | None
    plan_ref: str | None
    plan_page: str | None
    active: bool
    created_at: datetime
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "level": self.level,
            "parentId": self.parent_id,
            "name": self.name,
            "description": self.description,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "planRef": self.plan_ref,
            "planPage": self.plan_page,
            "active": self.active,
            "createdAt": _iso(self.created_at),
            "updatedAt": _iso(self.updated_at),
        }


@dataclass(frozen=True)
class LocationNode:
    location: LocationView
    children: tuple[LocationNode, ...] = ()

    def as_payload(self) -> dict[str, Any]:
        payload = self.location.as_payload()
        payload["children"] = [child.as_payload() for child in self.children]
        return payload


@dataclass(frozen=True)
class LocationTree:
    roots: tuple[LocationNode, ...]
    node_count: int
    depth: int
    truncated: bool

    def as_payload(self) -> dict[str, Any]:
        return {
            "roots": [root.as_payload() for root in self.roots],
            "nodeCount": self.node_count,
            "depth": self.depth,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class DirectoryEventView:
    id: str
    entity: str
    entity_id: str
    action: str
    actor_id: str | None
    actor_username: str | None
    source: str
    recorded_at: datetime
    effective_at: datetime
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None
    reason: str | None
    notes: str | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity": self.entity,
            "entityId": self.entity_id,
            "action": self.action,
            "actorId": self.actor_id,
            "actorUsername": self.actor_username,
            "source": self.source,
            "recordedAt": _iso(self.recorded_at),
            "effectiveAt": _iso(self.effective_at),
            "before": None if self.before is None else dict(self.before),
            "after": None if self.after is None else dict(self.after),
            "reason": self.reason,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class DirectoryPage[T]:
    items: tuple[T, ...]
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
class DirectoryHistoryPage:
    entity: str
    entity_id: str
    items: tuple[DirectoryEventView, ...]
    total: int
    limit: int
    offset: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "entityId": self.entity_id,
            "items": [item.as_payload() for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
        }


class DirectoryService:
    """The single implementation of people, department and location rules."""

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
        # Attributes owned by the shared serialized inventory write mutex.
        self._inventory_write_depth = 0
        self._reserved_codes: set[str] = set()
        self._pending_sequences: dict[str, int] = {}

    # ------------------------------------------------------------------ views
    def _department_view(self, department: DirectoryDepartment) -> DepartmentView:
        return DepartmentView(
            id=department.id,
            name=department.name,
            active=department.active,
            created_at=as_utc(department.created_at),
            updated_at=as_utc(department.updated_at),
        )

    def _person_view(self, person: DirectoryPerson) -> PersonView:
        return PersonView(
            id=person.id,
            name=person.name,
            job_title=person.job_title,
            department_id=person.department_id,
            site_id=person.site_id,
            contact_email=person.contact_email,
            contact_phone=person.contact_phone,
            status=person.status,
            created_at=as_utc(person.created_at),
            updated_at=as_utc(person.updated_at),
        )

    def _location_view(self, location: DirectoryLocation) -> LocationView:
        return LocationView(
            id=location.id,
            level=location.level,
            parent_id=location.parent_id,
            name=location.name,
            description=location.description,
            latitude=_stored_coordinate(location.latitude),
            longitude=_stored_coordinate(location.longitude),
            plan_ref=location.plan_ref,
            plan_page=location.plan_page,
            active=location.active,
            created_at=as_utc(location.created_at),
            updated_at=as_utc(location.updated_at),
        )

    def _event_view(self, event: DirectoryEvent) -> DirectoryEventView:
        return DirectoryEventView(
            id=event.id,
            entity=event.entity,
            entity_id=event.entity_id,
            action=event.action,
            actor_id=event.actor_id,
            actor_username=event.actor_username,
            source=event.source,
            recorded_at=as_utc(event.recorded_at),
            effective_at=as_utc(event.effective_at),
            before=event.before_snapshot,
            after=event.after_snapshot,
            reason=event.reason,
            notes=event.notes,
        )

    def _department_snapshot(self, department: DirectoryDepartment) -> dict[str, Any]:
        return {"name": department.name, "active": department.active}

    def _person_snapshot(self, person: DirectoryPerson) -> dict[str, Any]:
        return {
            "name": person.name,
            "jobTitle": person.job_title,
            "departmentId": person.department_id,
            "siteId": person.site_id,
            "contactEmail": person.contact_email,
            "contactPhone": person.contact_phone,
            "status": person.status,
        }

    def _location_snapshot(self, location: DirectoryLocation) -> dict[str, Any]:
        return {
            "level": location.level,
            "parentId": location.parent_id,
            "name": location.name,
            "description": location.description,
            "latitude": _stored_coordinate(location.latitude),
            "longitude": _stored_coordinate(location.longitude),
            "planRef": location.plan_ref,
            "planPage": location.plan_page,
            "active": location.active,
        }

    # ------------------------------------------------------------- lookups
    def _row(self, model: Any, value: Any, label: str) -> Any:
        """Resolve a permanent id from the URL; a bad or missing id is a 404."""
        if not isinstance(value, str) or not value.strip():
            raise NotFound(f"{label} not found")
        try:
            key = str(UUID(value.strip()))
        except ValueError:
            raise NotFound(f"{label} not found") from None
        row = self._session.get(model, key)
        if row is None:
            raise NotFound(f"{label} not found")
        return row

    def _department_reference(self, value: Any) -> str | None:
        if value is None:
            return None
        key = _uuid_text(value, "departmentId")
        department = self._session.get(DirectoryDepartment, key)
        if department is None:
            raise ValidationFailed("departmentId must reference an existing department")
        if not department.active:
            raise ValidationFailed("departmentId must reference an active department")
        return department.id

    def _site_reference(self, value: Any) -> str | None:
        if value is None:
            return None
        key = _uuid_text(value, "siteId")
        site = self._session.get(DirectoryLocation, key)
        if site is None:
            raise ValidationFailed("siteId must reference an existing site")
        if site.level != "site":
            raise ValidationFailed("siteId must reference a location of level site")
        if not site.active:
            raise ValidationFailed("siteId must reference an active site")
        return site.id

    def _parent_reference(self, level: str, value: Any) -> str | None:
        expected = LEVEL_PARENT[level]
        if expected is None:
            if value is not None:
                raise ValidationFailed("a site cannot have a parent location")
            return None
        if value is None:
            raise ValidationFailed(f"a {level} requires a parent {expected}")
        parent = self._session.get(DirectoryLocation, _uuid_text(value, "parentId"))
        if parent is None:
            raise ValidationFailed(f"parentId must reference an existing {expected}")
        if parent.level != expected:
            raise ValidationFailed(
                f"the parent of a {level} must be a location of level {expected}"
            )
        if not parent.active:
            raise ValidationFailed("parentId must reference an active location")
        return parent.id

    # ---------------------------------------------------------- transactions
    def _now(self) -> datetime:
        return utcnow()

    def _flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError as exc:
            raise Conflict("another directory record already uses that value") from exc

    def _record_event(
        self,
        principal: Principal,
        *,
        entity: str,
        entity_id: str,
        action: str,
        before: Mapping[str, Any] | None,
        after: Mapping[str, Any] | None,
        source: str,
        recorded_at: datetime,
        effective_at: datetime | None,
        reason: str | None,
        notes: str | None,
    ) -> None:
        self._session.add(
            DirectoryEvent(
                id=str(uuid4()),
                entity=entity,
                entity_id=entity_id,
                action=action,
                actor_id=principal.actor_id,
                actor_username=principal.username,
                source=source,
                recorded_at=recorded_at,
                effective_at=effective_at or recorded_at,
                before_snapshot=None if before is None else dict(before),
                after_snapshot=None if after is None else dict(after),
                reason=reason,
                notes=notes,
            )
        )

    @staticmethod
    def _change_snapshots(
        before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        changed_before: dict[str, Any] = {}
        changed_after: dict[str, Any] = {}
        for field, value in after.items():
            if before[field] != value:
                changed_before[field] = before[field]
                changed_after[field] = value
        if not changed_after:
            raise ValidationFailed("patch does not change any field")
        return changed_before, changed_after

    @staticmethod
    def _transition(before: Mapping[str, Any], after: Mapping[str, Any]) -> str:
        if "status" in after:
            return "activated" if after["status"] == "active" else "deactivated"
        if "active" in after:
            return "activated" if after["active"] else "deactivated"
        return "updated"

    # ------------------------------------------------------------- departments
    @serialized
    def create_department(
        self,
        principal: Principal,
        values: Mapping[str, Any],
        *,
        source: DirectorySource = DEFAULT_SOURCE,
        effective_at: datetime | None = None,
        notes: str | None = None,
    ) -> DepartmentView:
        """Create one configurable department; the id is permanent and never reused."""
        self._identity.authorize(principal, "config.departments", resource="directory:departments")
        prepared = self._prepare_department_create(values)
        audit_source = _source(source)
        effective = _effective_at(effective_at)
        note = _text(notes, "notes", NOTES_MAX)
        timestamp = self._now()
        department = DirectoryDepartment(
            id=str(uuid4()),
            name=prepared["name"],
            name_key=_name_key(prepared["name"]),
            active=True,
            created_at=timestamp,
            updated_at=timestamp,
        )
        self._assert_department_name_free(department.name_key)
        self._session.add(department)
        self._flush()
        self._record_event(
            principal,
            entity="department",
            entity_id=department.id,
            action="created",
            before=None,
            after=self._department_snapshot(department),
            source=audit_source,
            recorded_at=timestamp,
            effective_at=effective,
            reason=None,
            notes=note,
        )
        self._identity.record_operation(
            principal, action="directory.department_created", resource=f"department:{department.id}"
        )
        return self._department_view(department)

    @serialized
    def update_department(
        self,
        principal: Principal,
        department_id: Any,
        changes: Mapping[str, Any],
        *,
        source: DirectorySource = DEFAULT_SOURCE,
        effective_at: datetime | None = None,
        reason: str | None = None,
        notes: str | None = None,
    ) -> DepartmentView:
        """Rename or deactivate a department; deactivation keeps the row and its history."""
        department = self._row(DirectoryDepartment, department_id, "department")
        self._identity.authorize(
            principal, "config.departments", resource=f"department:{department.id}"
        )
        prepared = self._prepare_department_changes(changes)
        if "name" in prepared:
            name_key = _name_key(prepared["name"])
            self._assert_department_name_free(name_key, exclude_id=department.id)
            prepared["name_key"] = name_key
        if prepared.get("active") is False and department.active:
            self._assert_department_unused(department.id)
        audit_source = _source(source)
        effective = _effective_at(effective_at)
        reason_text = _text(reason, "reason", REASON_MAX)
        note = _text(notes, "notes", NOTES_MAX)
        before = self._department_snapshot(department)
        timestamp = self._now()
        for field, value in prepared.items():
            setattr(department, field, value)
        department.updated_at = timestamp
        self._flush()
        changed_before, changed_after = self._change_snapshots(
            before, self._department_snapshot(department)
        )
        self._record_event(
            principal,
            entity="department",
            entity_id=department.id,
            action=self._transition(changed_before, changed_after),
            before=changed_before,
            after=changed_after,
            source=audit_source,
            recorded_at=timestamp,
            effective_at=effective,
            reason=reason_text,
            notes=note,
        )
        self._identity.record_operation(
            principal, action="directory.department_updated", resource=f"department:{department.id}"
        )
        return self._department_view(department)

    def get_department(self, principal: Principal, department_id: Any) -> DepartmentView:
        department = self._row(DirectoryDepartment, department_id, "department")
        self._identity.authorize(principal, "people.view", resource=f"department:{department.id}")
        return self._department_view(department)

    def list_departments(
        self,
        principal: Principal,
        *,
        query: str | None = None,
        active: bool | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> DirectoryPage[DepartmentView]:
        """Bounded SQL search over department names."""
        self._identity.authorize(principal, "people.view", resource="directory:departments")
        _page_bounds(limit, offset)
        filters: list[ColumnElement[bool]] = []
        text_query = _text(query, "query", SEARCH_TEXT_LIMIT)
        if text_query:
            filters.append(
                DirectoryDepartment.name.ilike(f"%{_escape_like(text_query)}%", escape="\\")
            )
        if active is not None:
            if not isinstance(active, bool):
                raise ValidationFailed("active must be a boolean")
            filters.append(DirectoryDepartment.active.is_(active))
        total = int(
            self._session.execute(
                select(func.count(DirectoryDepartment.id)).where(*filters)
            ).scalar_one()
        )
        rows = self._session.execute(
            select(DirectoryDepartment)
            .where(*filters)
            .order_by(DirectoryDepartment.name.asc(), DirectoryDepartment.id.asc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return DirectoryPage(
            items=tuple(self._department_view(row) for row in rows),
            total=total,
            limit=limit,
            offset=offset,
        )

    # ----------------------------------------------------------------- people
    @serialized
    def create_person(
        self,
        principal: Principal,
        values: Mapping[str, Any],
        *,
        source: DirectorySource = DEFAULT_SOURCE,
        effective_at: datetime | None = None,
        notes: str | None = None,
    ) -> PersonView:
        """Register a person as a responsibility record; no account is created."""
        self._identity.authorize(principal, "people.create", resource="directory:people")
        prepared = self._prepare_person_create(values)
        audit_source = _source(source)
        effective = _effective_at(effective_at)
        note = _text(notes, "notes", NOTES_MAX)
        timestamp = self._now()
        person = DirectoryPerson(
            id=str(uuid4()),
            created_at=timestamp,
            updated_at=timestamp,
            **prepared,
        )
        self._session.add(person)
        self._flush()
        self._record_event(
            principal,
            entity="person",
            entity_id=person.id,
            action="created",
            before=None,
            after=self._person_snapshot(person),
            source=audit_source,
            recorded_at=timestamp,
            effective_at=effective,
            reason=None,
            notes=note,
        )
        self._identity.record_operation(
            principal, action="directory.person_created", resource=f"person:{person.id}"
        )
        return self._person_view(person)

    @serialized
    def update_person(
        self,
        principal: Principal,
        person_id: Any,
        changes: Mapping[str, Any],
        *,
        source: DirectorySource = DEFAULT_SOURCE,
        effective_at: datetime | None = None,
        reason: str | None = None,
        notes: str | None = None,
    ) -> PersonView:
        """Apply an explicit patch; the person id never changes and nothing is deleted."""
        person = self._row(DirectoryPerson, person_id, "person")
        self._identity.authorize(principal, "people.edit", resource=f"person:{person.id}")
        prepared = self._prepare_person_changes(person, changes)
        audit_source = _source(source)
        effective = _effective_at(effective_at)
        reason_text = _text(reason, "reason", REASON_MAX)
        note = _text(notes, "notes", NOTES_MAX)
        before = self._person_snapshot(person)
        timestamp = self._now()
        for field, value in prepared.items():
            setattr(person, field, value)
        person.updated_at = timestamp
        self._flush()
        changed_before, changed_after = self._change_snapshots(
            before, self._person_snapshot(person)
        )
        self._record_event(
            principal,
            entity="person",
            entity_id=person.id,
            action=self._transition(changed_before, changed_after),
            before=changed_before,
            after=changed_after,
            source=audit_source,
            recorded_at=timestamp,
            effective_at=effective,
            reason=reason_text,
            notes=note,
        )
        self._identity.record_operation(
            principal, action="directory.person_updated", resource=f"person:{person.id}"
        )
        return self._person_view(person)

    def get_person(self, principal: Principal, person_id: Any) -> PersonView:
        person = self._row(DirectoryPerson, person_id, "person")
        self._identity.authorize(principal, "people.view", resource=f"person:{person.id}")
        return self._person_view(person)

    def person_label(
        self, principal: Principal, person_id: Any, *, require_active: bool = True
    ) -> str:
        """Canonical label for another module; never derived from legacy free text."""
        view = self.get_person(principal, person_id)
        if require_active and view.status != "active":
            raise Conflict("person is not active")
        return view.label

    def list_people(
        self,
        principal: Principal,
        *,
        query: str | None = None,
        status: str | None = None,
        department_id: str | None = None,
        site_id: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> DirectoryPage[PersonView]:
        """Bounded SQL search over people, filtered by status and references."""
        self._identity.authorize(principal, "people.view", resource="directory:people")
        _page_bounds(limit, offset)
        filters: list[ColumnElement[bool]] = []
        text_query = _text(query, "query", SEARCH_TEXT_LIMIT)
        if text_query:
            pattern = f"%{_escape_like(text_query)}%"
            filters.append(
                or_(
                    DirectoryPerson.name.ilike(pattern, escape="\\"),
                    DirectoryPerson.job_title.ilike(pattern, escape="\\"),
                )
            )
        if status is not None:
            filters.append(DirectoryPerson.status == _person_status(status))
        department = _optional_uuid(department_id, "departmentId")
        if department:
            filters.append(DirectoryPerson.department_id == department)
        site = _optional_uuid(site_id, "siteId")
        if site:
            filters.append(DirectoryPerson.site_id == site)
        total = int(
            self._session.execute(
                select(func.count(DirectoryPerson.id)).where(*filters)
            ).scalar_one()
        )
        rows = self._session.execute(
            select(DirectoryPerson)
            .where(*filters)
            .order_by(DirectoryPerson.name.asc(), DirectoryPerson.id.asc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return DirectoryPage(
            items=tuple(self._person_view(row) for row in rows),
            total=total,
            limit=limit,
            offset=offset,
        )

    # -------------------------------------------------------------- locations
    @serialized
    def create_location(
        self,
        principal: Principal,
        values: Mapping[str, Any],
        *,
        source: DirectorySource = DEFAULT_SOURCE,
        effective_at: datetime | None = None,
        notes: str | None = None,
    ) -> LocationView:
        """Create one hierarchy node; the level decides the exact parent level."""
        self._identity.authorize(principal, "config.sites", resource="directory:locations")
        prepared = self._prepare_location_create(values)
        audit_source = _source(source)
        effective = _effective_at(effective_at)
        note = _text(notes, "notes", NOTES_MAX)
        timestamp = self._now()
        location = DirectoryLocation(
            id=str(uuid4()),
            active=True,
            created_at=timestamp,
            updated_at=timestamp,
            **prepared,
        )
        self._assert_location_name_free(location.parent_id, location.name_key)
        self._session.add(location)
        self._flush()
        self._record_event(
            principal,
            entity="location",
            entity_id=location.id,
            action="created",
            before=None,
            after=self._location_snapshot(location),
            source=audit_source,
            recorded_at=timestamp,
            effective_at=effective,
            reason=None,
            notes=note,
        )
        self._identity.record_operation(
            principal, action="directory.location_created", resource=f"location:{location.id}"
        )
        return self._location_view(location)

    @serialized
    def update_location(
        self,
        principal: Principal,
        location_id: Any,
        changes: Mapping[str, Any],
        *,
        source: DirectorySource = DEFAULT_SOURCE,
        effective_at: datetime | None = None,
        reason: str | None = None,
        notes: str | None = None,
    ) -> LocationView:
        """Rename, reparent, locate or deactivate one node; the level never changes."""
        location = self._row(DirectoryLocation, location_id, "location")
        self._identity.authorize(principal, "config.sites", resource=f"location:{location.id}")
        prepared = self._prepare_location_changes(location, changes)
        audit_source = _source(source)
        effective = _effective_at(effective_at)
        reason_text = _text(reason, "reason", REASON_MAX)
        note = _text(notes, "notes", NOTES_MAX)
        if "name" in prepared:
            name_key = _name_key(prepared["name"])
            parent_id = prepared.get("parent_id", location.parent_id)
            self._assert_location_name_free(parent_id, name_key, exclude_id=location.id)
            prepared["name_key"] = name_key
        if prepared.get("active") is False and location.active:
            self._assert_location_unused(location.id)
        before = self._location_snapshot(location)
        timestamp = self._now()
        for field, value in prepared.items():
            setattr(location, field, value)
        location.updated_at = timestamp
        self._flush()
        changed_before, changed_after = self._change_snapshots(
            before, self._location_snapshot(location)
        )
        self._record_event(
            principal,
            entity="location",
            entity_id=location.id,
            action=self._transition(changed_before, changed_after),
            before=changed_before,
            after=changed_after,
            source=audit_source,
            recorded_at=timestamp,
            effective_at=effective,
            reason=reason_text,
            notes=note,
        )
        self._identity.record_operation(
            principal, action="directory.location_updated", resource=f"location:{location.id}"
        )
        return self._location_view(location)

    def get_location(self, principal: Principal, location_id: Any) -> LocationView:
        location = self._row(DirectoryLocation, location_id, "location")
        self._identity.authorize(principal, "assets.view", resource=f"location:{location.id}")
        return self._location_view(location)

    def list_locations(
        self,
        principal: Principal,
        *,
        query: str | None = None,
        level: str | None = None,
        parent_id: str | None = None,
        active: bool | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> DirectoryPage[LocationView]:
        """Bounded SQL search over the hierarchy; the whole inventory is never loaded."""
        self._identity.authorize(principal, "assets.view", resource="directory:locations")
        _page_bounds(limit, offset)
        filters: list[ColumnElement[bool]] = []
        text_query = _text(query, "query", SEARCH_TEXT_LIMIT)
        if text_query:
            pattern = f"%{_escape_like(text_query)}%"
            filters.append(
                or_(
                    DirectoryLocation.name.ilike(pattern, escape="\\"),
                    DirectoryLocation.description.ilike(pattern, escape="\\"),
                )
            )
        if level is not None:
            filters.append(DirectoryLocation.level == _level(level))
        parent = _optional_uuid(parent_id, "parentId")
        if parent:
            filters.append(DirectoryLocation.parent_id == parent)
        if active is not None:
            if not isinstance(active, bool):
                raise ValidationFailed("active must be a boolean")
            filters.append(DirectoryLocation.active.is_(active))
        total = int(
            self._session.execute(
                select(func.count(DirectoryLocation.id)).where(*filters)
            ).scalar_one()
        )
        rows = self._session.execute(
            select(DirectoryLocation)
            .where(*filters)
            .order_by(DirectoryLocation.name.asc(), DirectoryLocation.id.asc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return DirectoryPage(
            items=tuple(self._location_view(row) for row in rows),
            total=total,
            limit=limit,
            offset=offset,
        )

    def location_tree(
        self,
        principal: Principal,
        *,
        root_id: str | None = None,
        depth: int = DEFAULT_TREE_DEPTH,
        max_nodes: int = DEFAULT_TREE_NODES,
    ) -> LocationTree:
        """Bounded nested metadata (depth and node count) for the later map API."""
        self._identity.authorize(principal, "assets.view", resource="directory:locations")
        if (
            not isinstance(depth, int)
            or isinstance(depth, bool)
            or not 1 <= depth <= MAX_TREE_DEPTH
        ):
            raise ValidationFailed(f"depth must be between 1 and {MAX_TREE_DEPTH}")
        if (
            not isinstance(max_nodes, int)
            or isinstance(max_nodes, bool)
            or not 1 <= max_nodes <= MAX_TREE_NODES
        ):
            raise ValidationFailed(f"maxNodes must be between 1 and {MAX_TREE_NODES}")

        roots: tuple[DirectoryLocation, ...]
        if root_id is not None:
            roots = (self._row(DirectoryLocation, root_id, "location"),)
        else:
            roots = tuple(
                self._session.execute(
                    select(DirectoryLocation)
                    .where(DirectoryLocation.parent_id.is_(None))
                    .order_by(DirectoryLocation.name.asc(), DirectoryLocation.id.asc())
                    .limit(max_nodes + 1)
                ).scalars()
            )
        truncated = len(roots) > max_nodes
        if truncated:
            roots = roots[:max_nodes]
        node_count = len(roots)

        children: dict[str, list[DirectoryLocation]] = {}
        frontier = list(roots)
        level = 1
        while level < depth and frontier and not truncated:
            remaining = max_nodes - node_count
            if remaining <= 0:
                truncated = True
                break
            rows = list(
                self._session.execute(
                    select(DirectoryLocation)
                    .where(
                        DirectoryLocation.parent_id.in_([row.id for row in frontier]),
                    )
                    .order_by(DirectoryLocation.name.asc(), DirectoryLocation.id.asc())
                    .limit(remaining + 1)
                ).scalars()
            )
            if len(rows) > remaining:
                truncated = True
                rows = rows[:remaining]
            for row in rows:
                children.setdefault(str(row.parent_id), []).append(row)
            node_count += len(rows)
            frontier = rows
            level += 1

        def build(location: DirectoryLocation, levels: int) -> LocationNode:
            view = self._location_view(location)
            if levels <= 1:
                return LocationNode(location=view)
            return LocationNode(
                location=view,
                children=tuple(build(child, levels - 1) for child in children.get(location.id, ())),
            )

        return LocationTree(
            roots=tuple(build(root, depth) for root in roots),
            node_count=node_count,
            depth=depth,
            truncated=truncated,
        )

    # ----------------------------------------------------------------- history
    def history(
        self,
        principal: Principal,
        *,
        entity: str,
        entity_id: Any,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> DirectoryHistoryPage:
        """Bounded append-only event history of one directory record."""
        if entity not in ENTITIES:
            raise ValidationFailed(f"entity must be one of {', '.join(ENTITIES)}")
        permission = "assets.view" if entity == "location" else "people.view"
        self._identity.authorize(principal, permission, resource=f"{entity}:{entity_id}")
        _page_bounds(limit, offset, maximum=HISTORY_LIMIT)
        model = {
            "person": DirectoryPerson,
            "department": DirectoryDepartment,
            "location": DirectoryLocation,
        }[entity]
        row = self._row(model, entity_id, entity)
        filters = (
            DirectoryEvent.entity == entity,
            DirectoryEvent.entity_id == row.id,
        )
        total = int(
            self._session.execute(
                select(func.count(DirectoryEvent.id)).where(*filters)
            ).scalar_one()
        )
        rows = self._session.execute(
            select(DirectoryEvent)
            .where(*filters)
            .order_by(DirectoryEvent.recorded_at.desc(), DirectoryEvent.id.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return DirectoryHistoryPage(
            entity=entity,
            entity_id=row.id,
            items=tuple(self._event_view(event) for event in rows),
            total=total,
            limit=limit,
            offset=offset,
        )

    # ------------------------------------------------------------- validation
    def _prepare_department_create(self, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("department payload must be an object")
        unknown = sorted(set(values) - {"name"})
        if unknown:
            raise ValidationFailed(f"unsupported department fields: {', '.join(unknown)}")
        return {"name": _text(values.get("name"), "name", DEPARTMENT_NAME_MAX, required=True)}

    def _prepare_department_changes(self, changes: Any) -> dict[str, Any]:
        if not isinstance(changes, Mapping):
            raise ValidationFailed("department patch must be an object")
        unknown = sorted(set(changes) - set(DEPARTMENT_CHANGE_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported department fields: {', '.join(unknown)}")
        if not changes:
            raise ValidationFailed("patch requires at least one field")
        prepared: dict[str, Any] = {}
        if "name" in changes:
            prepared["name"] = _text(changes["name"], "name", DEPARTMENT_NAME_MAX, required=True)
        if "active" in changes:
            prepared["active"] = _boolean(changes["active"], "active")
        return prepared

    def _prepare_person_create(self, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("person payload must be an object")
        unknown = sorted(set(values) - set(PERSON_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported person fields: {', '.join(unknown)}")
        return {
            "name": _text(values.get("name"), "name", PERSON_NAME_MAX, required=True),
            "job_title": _text(values.get("job_title"), "jobTitle", PERSON_JOB_TITLE_MAX),
            "department_id": self._department_reference(values.get("department_id")),
            "site_id": self._site_reference(values.get("site_id")),
            "contact_email": _email(values.get("contact_email")),
            "contact_phone": _phone(values.get("contact_phone")),
            "status": _person_status(values.get("status")),
        }

    def _prepare_person_changes(self, person: DirectoryPerson, changes: Any) -> dict[str, Any]:
        if not isinstance(changes, Mapping):
            raise ValidationFailed("person patch must be an object")
        unknown = sorted(set(changes) - set(PERSON_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported person fields: {', '.join(unknown)}")
        if not changes:
            raise ValidationFailed("patch requires at least one field")
        prepared: dict[str, Any] = {}
        if "name" in changes:
            prepared["name"] = _text(changes["name"], "name", PERSON_NAME_MAX, required=True)
        if "job_title" in changes:
            prepared["job_title"] = _text(changes["job_title"], "jobTitle", PERSON_JOB_TITLE_MAX)
        if "department_id" in changes:
            prepared["department_id"] = self._department_reference(changes["department_id"])
        if "site_id" in changes:
            prepared["site_id"] = self._site_reference(changes["site_id"])
        if "contact_email" in changes:
            prepared["contact_email"] = _email(changes["contact_email"])
        if "contact_phone" in changes:
            prepared["contact_phone"] = _phone(changes["contact_phone"])
        if "status" in changes:
            status = _person_status(changes["status"])
            if status == "active" and person.status != "active":
                # Reactivation restores an active person, so the effective
                # references (from this patch or stored) must satisfy the same
                # rules as create/reference updates.
                self._site_reference(prepared.get("site_id", person.site_id))
                self._department_reference(prepared.get("department_id", person.department_id))
            prepared["status"] = status
        return prepared

    def _prepare_location_create(self, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValidationFailed("location payload must be an object")
        unknown = sorted(set(values) - set(LOCATION_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported location fields: {', '.join(unknown)}")
        level = _level(values.get("level"))
        name = _text(values.get("name"), "name", LOCATION_NAME_MAX, required=True)
        coordinates = _new_coordinates(level, values)
        return {
            "level": level,
            "parent_id": self._parent_reference(level, values.get("parent_id")),
            "name": name,
            "name_key": _name_key(name),
            "description": _text(
                values.get("description"), "description", LOCATION_DESCRIPTION_MAX
            ),
            "latitude": coordinates["latitude"],
            "longitude": coordinates["longitude"],
            "plan_ref": _plan_reference(values.get("plan_ref"), "planRef", PLAN_REF_MAX),
            "plan_page": _plan_reference(values.get("plan_page"), "planPage", PLAN_PAGE_MAX),
        }

    def _prepare_location_changes(
        self, location: DirectoryLocation, changes: Any
    ) -> dict[str, Any]:
        if not isinstance(changes, Mapping):
            raise ValidationFailed("location patch must be an object")
        unknown = sorted(set(changes) - set(LOCATION_CHANGE_FIELDS))
        if unknown:
            raise ValidationFailed(f"unsupported location fields: {', '.join(unknown)}")
        if not changes:
            raise ValidationFailed("patch requires at least one field")
        prepared: dict[str, Any] = {}
        if "parent_id" in changes:
            parent_id = self._parent_reference(location.level, changes["parent_id"])
            self._assert_no_cycle(location, parent_id)
            prepared["parent_id"] = parent_id
        if "name" in changes:
            prepared["name"] = _text(changes["name"], "name", LOCATION_NAME_MAX, required=True)
        if "description" in changes:
            prepared["description"] = _text(
                changes["description"], "description", LOCATION_DESCRIPTION_MAX
            )
        prepared.update(_merged_coordinates(location, changes))
        if "plan_ref" in changes:
            prepared["plan_ref"] = _plan_reference(changes["plan_ref"], "planRef", PLAN_REF_MAX)
        if "plan_page" in changes:
            prepared["plan_page"] = _plan_reference(changes["plan_page"], "planPage", PLAN_PAGE_MAX)
        if "active" in changes:
            active = _boolean(changes["active"], "active")
            if active and not location.active:
                # Reactivation restores a reachable node, so the effective
                # parent (from this patch or stored) must satisfy the same rules
                # as creation and reparenting.
                self._parent_reference(
                    location.level,
                    prepared.get("parent_id", location.parent_id),
                )
            prepared["active"] = active
        return prepared

    def _assert_department_name_free(self, name_key: str, *, exclude_id: str | None = None) -> None:
        statement = select(DirectoryDepartment.id).where(DirectoryDepartment.name_key == name_key)
        if exclude_id is not None:
            statement = statement.where(DirectoryDepartment.id != exclude_id)
        if self._session.execute(statement).first() is not None:
            raise Conflict("department name is already in use")

    def _assert_department_unused(self, department_id: str) -> None:
        active_people = int(
            self._session.execute(
                select(func.count(DirectoryPerson.id)).where(
                    DirectoryPerson.department_id == department_id,
                    DirectoryPerson.status == "active",
                )
            ).scalar_one()
        )
        if active_people:
            raise Conflict("department still has active people")

    def _assert_location_name_free(
        self, parent_id: str | None, name_key: str, *, exclude_id: str | None = None
    ) -> None:
        statement = select(DirectoryLocation.id).where(DirectoryLocation.name_key == name_key)
        statement = statement.where(
            DirectoryLocation.parent_id.is_(None)
            if parent_id is None
            else DirectoryLocation.parent_id == parent_id
        )
        if exclude_id is not None:
            statement = statement.where(DirectoryLocation.id != exclude_id)
        if self._session.execute(statement).first() is not None:
            raise Conflict("a sibling location already uses that name")

    def _assert_location_unused(self, location_id: str) -> None:
        active_children = int(
            self._session.execute(
                select(func.count(DirectoryLocation.id)).where(
                    DirectoryLocation.parent_id == location_id,
                    DirectoryLocation.active.is_(True),
                )
            ).scalar_one()
        )
        active_people = int(
            self._session.execute(
                select(func.count(DirectoryPerson.id)).where(
                    DirectoryPerson.site_id == location_id,
                    DirectoryPerson.status == "active",
                )
            ).scalar_one()
        )
        if active_children or active_people:
            raise Conflict("location still has active children or people")

    def _assert_no_cycle(self, location: DirectoryLocation, parent_id: str | None) -> None:
        seen = {location.id}
        current = parent_id
        for _ in range(MAX_TREE_DEPTH + 1):
            if current is None:
                return
            if current in seen:
                raise Conflict("a location cannot move into its own subtree")
            seen.add(current)
            row = self._session.get(DirectoryLocation, current)
            if row is None:
                return
            current = row.parent_id
        raise Conflict("location hierarchy is deeper than the supported depth")


def _text(value: Any, field: str, limit: int, *, required: bool = False) -> str | None:
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
    if len(normalized) > limit:
        raise ValidationFailed(f"{field} must be at most {limit} characters")
    return normalized


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationFailed(f"{field} must be a boolean")
    return value


def _name_key(name: str) -> str:
    return name.casefold()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _uuid_text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationFailed(f"{field} must be a UUID")
    try:
        return str(UUID(value.strip()))
    except ValueError:
        raise ValidationFailed(f"{field} must be a UUID") from None


def _optional_uuid(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _uuid_text(value, field)


def _page_bounds(limit: Any, offset: Any, *, maximum: int = MAX_LIMIT) -> None:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= maximum:
        raise ValidationFailed(f"limit must be between 1 and {maximum}")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValidationFailed("offset must be zero or greater")


def _person_status(value: Any) -> str:
    if value is None:
        return DEFAULT_PERSON_STATUS
    if not isinstance(value, str) or value.strip().lower() not in PERSON_STATUSES:
        raise ValidationFailed(f"status must be one of {', '.join(PERSON_STATUSES)}")
    return value.strip().lower()


def _level(value: Any) -> str:
    if not isinstance(value, str) or value.strip().lower() not in LEVELS:
        raise ValidationFailed(f"level must be one of {', '.join(LEVELS)}")
    return value.strip().lower()


def _email(value: Any) -> str | None:
    normalized = _text(value, "contactEmail", CONTACT_EMAIL_MAX)
    if normalized is None:
        return None
    if "@" not in normalized or any(character.isspace() for character in normalized):
        raise ValidationFailed("contactEmail must be an email address")
    return normalized


_PHONE_PATTERN = re.compile(r"^[+0-9][0-9 ()+-]{2,39}$")


def _phone(value: Any) -> str | None:
    normalized = _text(value, "contactPhone", CONTACT_PHONE_MAX)
    if normalized is None:
        return None
    if not _PHONE_PATTERN.match(normalized) or not any(
        character.isdigit() for character in normalized
    ):
        raise ValidationFailed("contactPhone must be a phone number")
    return normalized


def _coordinate(value: Any, field: str, bound: Decimal) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValidationFailed(f"{field} must be a number")
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        raise ValidationFailed(f"{field} must be a number") from None
    if not number.is_finite():
        raise ValidationFailed(f"{field} must be finite")
    if abs(number) > bound:
        raise ValidationFailed(f"{field} must be between -{bound} and {bound}")
    exponent = number.as_tuple().exponent
    if isinstance(exponent, int) and -exponent > COORDINATE_MAX_DECIMALS:
        raise ValidationFailed(f"{field} supports at most {COORDINATE_MAX_DECIMALS} decimal places")
    return number


def _stored_value(number: Decimal | None) -> str | None:
    return None if number is None else format(number, "f")


def _current_coordinate(value: str | None) -> Decimal | None:
    return None if value is None else Decimal(value)


def _stored_coordinate(value: str | None) -> float | None:
    return None if value is None else float(Decimal(value))


def _new_coordinates(level: str, values: Mapping[str, Any]) -> dict[str, str | None]:
    latitude = _coordinate(values.get("latitude"), "latitude", LATITUDE_BOUND)
    longitude = _coordinate(values.get("longitude"), "longitude", LONGITUDE_BOUND)
    if level != "site":
        if latitude is not None or longitude is not None:
            raise ValidationFailed("geographic coordinates are only allowed on a site")
        return {"latitude": None, "longitude": None}
    if (latitude is None) != (longitude is None):
        raise ValidationFailed("latitude and longitude must be provided together")
    return {"latitude": _stored_value(latitude), "longitude": _stored_value(longitude)}


def _merged_coordinates(
    location: DirectoryLocation, changes: Mapping[str, Any]
) -> dict[str, str | None]:
    if "latitude" not in changes and "longitude" not in changes:
        return {}
    if location.level != "site":
        raise ValidationFailed("geographic coordinates are only allowed on a site")
    latitude = (
        _coordinate(changes["latitude"], "latitude", LATITUDE_BOUND)
        if "latitude" in changes
        else _current_coordinate(location.latitude)
    )
    longitude = (
        _coordinate(changes["longitude"], "longitude", LONGITUDE_BOUND)
        if "longitude" in changes
        else _current_coordinate(location.longitude)
    )
    if (latitude is None) != (longitude is None):
        raise ValidationFailed("latitude and longitude must be provided together")
    return {"latitude": _stored_value(latitude), "longitude": _stored_value(longitude)}


def _plan_reference(value: Any, field: str, limit: int) -> str | None:
    normalized = _text(value, field, limit)
    if normalized is None:
        return None
    if any(marker in normalized for marker in ("/", "\\", "..", "://")):
        raise ValidationFailed(f"{field} must be an opaque plan identifier, not a path or URL")
    return normalized


def _source(value: Any) -> str:
    if value not in SOURCES:
        raise ValidationFailed(f"source must be one of {', '.join(SOURCES)}")
    return value


def _effective_at(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ValidationFailed("effectiveAt must be a timestamp")
    if value.tzinfo is None:
        raise ValidationFailed("effectiveAt must include a timezone")
    return as_utc(value)


__all__ = [
    "CONTACT_EMAIL_MAX",
    "CONTACT_PHONE_MAX",
    "DEFAULT_LIMIT",
    "DEFAULT_PERSON_STATUS",
    "DEFAULT_SOURCE",
    "DEFAULT_TREE_DEPTH",
    "DEFAULT_TREE_NODES",
    "DEPARTMENT_NAME_MAX",
    "ENTITIES",
    "HISTORY_LIMIT",
    "LEVELS",
    "LEVEL_DEPTH",
    "LEVEL_PARENT",
    "LOCATION_DESCRIPTION_MAX",
    "LOCATION_NAME_MAX",
    "MAX_LIMIT",
    "MAX_TREE_DEPTH",
    "MAX_TREE_NODES",
    "NOTES_MAX",
    "PERSON_JOB_TITLE_MAX",
    "PERSON_NAME_MAX",
    "PERSON_STATUSES",
    "PLAN_PAGE_MAX",
    "PLAN_REF_MAX",
    "REASON_MAX",
    "SEARCH_TEXT_LIMIT",
    "SOURCES",
    "DepartmentView",
    "DirectoryEventView",
    "DirectoryHistoryPage",
    "DirectoryPage",
    "DirectoryService",
    "LocationNode",
    "LocationTree",
    "LocationView",
    "PersonView",
]
