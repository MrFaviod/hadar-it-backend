"""Canonical relationship service: typed edges, containment, hosts and bounded graphs.

Every adapter (REST, Pydantic AI, FastMCP) calls this module. Authorization is
the identity service's Casbin decision; no adapter asserts a role, permission or
origin by itself. ``source`` is a trusted constructor context, never a request
field, and it is written to the affected assets' structured history.

The service never composes committed ``InventoryService`` public operations.
Reads use narrow inventory projections; multi-write relations call the
documented private history helper so all edges, history rows and the identity
audit entry commit once, through ``IdentityService.record_operation``.
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
from itsm.i18n.labels import LabelError, label_view, validate_label
from itsm.identity.clock import as_utc, utcnow
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
    _effective_at,
    _history_source,
    _notes,
    _reason,
)
from itsm.relationships.models import Relationship, RelationshipType

BULK_LIMIT = 50
LABEL_MAX = 80
DEFAULT_GRAPH_DEPTH = 2
MAX_GRAPH_DEPTH = 5
MAX_GRAPH_NODES = 200
MAX_GRAPH_EDGES = 400

DIRECTIONS: frozenset[str] = frozenset({"out", "in", "both"})
CONTAINMENT_TYPES: tuple[str, ...] = ("installed_in", "hosted_in")
KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,31}$")

_UNSET = object()


def _key(value: Any) -> str:
    if not isinstance(value, str) or not KEY_PATTERN.match(value):
        raise ValidationFailed(
            "type key must be 2-32 lowercase letters, digits or underscore",
            key="api.relationships.type_key_format",
        )
    return value


def _label(value: Any, mapping: Any, field: str) -> tuple[str, dict[str, str] | None]:
    """Accept legacy text or a locale map; ids and keys never change (S4/D9)."""
    try:
        return validate_label(value, mapping, field=field, limit=LABEL_MAX)
    except LabelError as exc:
        raise ValidationFailed(
            str(exc), key="api.relationships.label_invalid", params={"field": field}
        ) from None


def _patched_label(
    stored: str, value: Any, mapping: Any, field: str
) -> tuple[str, dict[str, str] | None]:
    """Merge a patch into the stored label; text wins for the source locale."""
    if value is _UNSET and mapping is _UNSET:
        return stored, None
    return _label(
        stored if value is _UNSET else value,
        None if mapping is _UNSET else mapping,
        field,
    )


def _direction(value: Any) -> str:
    if not isinstance(value, str) or value not in DIRECTIONS:
        raise ValidationFailed(
            "direction must be one of both, in, out",
            key="api.relationships.direction_allowed",
            params={"allowed": "both, in, out"},
        )
    return value


def _bounded(limit: Any, offset: Any) -> tuple[int, int]:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValidationFailed(
            f"limit must be between 1 and {MAX_LIMIT}",
            key="api.validation.limit_range",
            params={"maximum": MAX_LIMIT},
        )
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValidationFailed(
            "offset must be zero or greater", key="api.validation.offset_non_negative"
        )
    return limit, offset


def _depth(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_GRAPH_DEPTH:
        raise ValidationFailed(
            f"depth must be between 1 and {MAX_GRAPH_DEPTH}",
            key="api.relationships.depth_range",
            params={"maximum": MAX_GRAPH_DEPTH},
        )
    return value


def _asset_ids(value: Any) -> list[str]:
    if value is None:
        return []
    entries = list(value)
    if len(entries) > BULK_LIMIT:
        raise ValidationFailed(
            f"at most {BULK_LIMIT} asset ids are accepted",
            key="api.relationships.ids_limit",
            params={"limit": BULK_LIMIT},
        )
    unique: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValidationFailed("asset ids must be text", key="api.relationships.ids_text")
        try:
            UUID(entry)
        except ValueError:
            raise NotFound("asset not found", key="api.relationships.asset_not_found") from None
        if entry not in unique:
            unique.append(entry)
    return unique


def _descriptor(row: Relationship) -> dict[str, Any]:
    return {
        "id": row.id,
        "type": row.type_key,
        "sourceId": row.source_id,
        "targetId": row.target_id,
    }


@dataclass(frozen=True)
class RelationshipTypeView:
    """One configurable type with its forward and inverse display labels."""

    key: str
    forward_label: str
    inverse_label: str
    forward_labels: dict[str, str]
    inverse_labels: dict[str, str]
    containment: bool
    active: bool
    created_at: datetime
    updated_at: datetime

    def as_payload(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "forwardLabel": self.forward_label,
            "inverseLabel": self.inverse_label,
            "forwardLabels": dict(self.forward_labels),
            "inverseLabels": dict(self.inverse_labels),
            "containment": self.containment,
            "active": self.active,
            "createdAt": as_utc(self.created_at).isoformat(),
            "updatedAt": as_utc(self.updated_at).isoformat(),
        }


@dataclass(frozen=True)
class RelationshipView:
    """One directed edge; ``direction``/``label`` are relative to the queried asset."""

    id: str
    type_key: str
    forward_label: str
    inverse_label: str
    forward_labels: dict[str, str]
    inverse_labels: dict[str, str]
    containment: bool
    active: bool
    source_id: str
    target_id: str
    reason: str | None
    notes: str | None
    effective_at: datetime | None
    created_at: datetime
    updated_at: datetime
    direction: str
    label: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "typeKey": self.type_key,
            "forwardLabel": self.forward_label,
            "inverseLabel": self.inverse_label,
            "forwardLabels": dict(self.forward_labels),
            "inverseLabels": dict(self.inverse_labels),
            "containment": self.containment,
            "typeActive": self.active,
            "sourceId": self.source_id,
            "targetId": self.target_id,
            "reason": self.reason,
            "notes": self.notes,
            "effectiveAt": None
            if self.effective_at is None
            else as_utc(self.effective_at).isoformat(),
            "createdAt": as_utc(self.created_at).isoformat(),
            "updatedAt": as_utc(self.updated_at).isoformat(),
            "direction": self.direction,
            "label": self.label,
        }


@dataclass(frozen=True)
class RelationshipPage:
    items: tuple[RelationshipView, ...]
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
class HostMoveResult:
    """Atomic replacement of the single ``hosted_in`` parent of one child."""

    child_id: str
    old_relationship: RelationshipView
    new_relationship: RelationshipView
    effective_at: datetime | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "childId": self.child_id,
            "oldRelationship": self.old_relationship.as_payload(),
            "newRelationship": self.new_relationship.as_payload(),
            "effectiveAt": None
            if self.effective_at is None
            else as_utc(self.effective_at).isoformat(),
        }


@dataclass(frozen=True)
class GraphNode:
    """Bounded asset summary used by the infrastructure graph."""

    id: str
    quick_code: str
    name: str
    category: str | None
    type: str | None
    status: str
    archived: bool

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "quickCode": self.quick_code,
            "name": self.name,
            "category": self.category,
            "type": self.type,
            "status": self.status,
            "archived": self.archived,
        }


@dataclass(frozen=True)
class GraphView:
    root_id: str | None
    depth: int
    direction: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[RelationshipView, ...]
    nodes_truncated: bool
    edges_truncated: bool
    depth_truncated: bool
    limit: int
    offset: int
    total: int | None

    @property
    def truncated(self) -> bool:
        return self.nodes_truncated or self.edges_truncated or self.depth_truncated

    def as_payload(self) -> dict[str, Any]:
        return {
            "rootId": self.root_id,
            "depth": self.depth,
            "direction": self.direction,
            "nodes": [node.as_payload() for node in self.nodes],
            "edges": [edge.as_payload() for edge in self.edges],
            "truncated": self.truncated,
            "nodesTruncated": self.nodes_truncated,
            "edgesTruncated": self.edges_truncated,
            "depthTruncated": self.depth_truncated,
            "limit": self.limit,
            "offset": self.offset,
            "total": self.total,
        }


class RelationshipService:
    """The single implementation of relationship rules for every front door."""

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
        self._source = _history_source(source)
        self._locale = locale
        self._inventory = inventory or InventoryService(
            session,
            settings,
            identity=self._identity,
            source=self._source,
        )
        self._pending_sequences: dict[str, int] = {}
        self._reserved_codes: set[str] = set()
        self._inventory_write_depth = 0

    # ------------------------------------------------------------------- views
    @property
    def label_locale(self) -> str:
        """Request locale for label rendering; agents and workers get the default."""
        if self._locale is None:
            from itsm.i18n.settings import read_installation_settings

            self._locale = read_installation_settings(self._session).default_locale
        return self._locale

    def _type_view(self, row: RelationshipType) -> RelationshipTypeView:
        forward = label_view(row.forward_label, row.forward_labels, self.label_locale)
        inverse = label_view(row.inverse_label, row.inverse_labels, self.label_locale)
        return RelationshipTypeView(
            key=row.key,
            forward_label=forward["label"],
            inverse_label=inverse["label"],
            forward_labels=forward["labels"],
            inverse_labels=inverse["labels"],
            containment=bool(row.containment),
            active=bool(row.active),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _view(
        self, row: Relationship, type_row: RelationshipType, *, direction: str
    ) -> RelationshipView:
        forward = label_view(type_row.forward_label, type_row.forward_labels, self.label_locale)
        inverse = label_view(type_row.inverse_label, type_row.inverse_labels, self.label_locale)
        return RelationshipView(
            id=row.id,
            type_key=row.type_key,
            forward_label=forward["label"],
            inverse_label=inverse["label"],
            forward_labels=forward["labels"],
            inverse_labels=inverse["labels"],
            containment=bool(type_row.containment),
            active=bool(type_row.active),
            source_id=row.source_id,
            target_id=row.target_id,
            reason=row.reason,
            notes=row.notes,
            effective_at=None if row.effective_at is None else as_utc(row.effective_at),
            created_at=row.created_at,
            updated_at=row.updated_at,
            direction=direction,
            label=forward["label"] if direction == "outgoing" else inverse["label"],
        )

    def _type_map(self, rows: Iterable[Relationship]) -> dict[str, RelationshipType]:
        keys = {row.type_key for row in rows}
        if not keys:
            return {}
        stored = self._session.execute(
            select(RelationshipType).where(RelationshipType.key.in_(keys))
        ).scalars()
        return {type_row.key: type_row for type_row in stored}

    def _views(
        self,
        rows: Iterable[Relationship],
        *,
        scope_ids: set[str] | None = None,
        global_direction: str = "both",
    ) -> tuple[RelationshipView, ...]:
        stored = list(rows)
        types = self._type_map(stored)
        views: list[RelationshipView] = []
        for row in stored:
            type_row = types.get(row.type_key)
            if type_row is None:
                raise Conflict("relationship type is missing", key="api.relationships.type_missing")
            if scope_ids is not None:
                direction = "outgoing" if row.source_id in scope_ids else "incoming"
            else:
                direction = "incoming" if global_direction == "in" else "outgoing"
            views.append(self._view(row, type_row, direction=direction))
        return tuple(views)

    def _nodes(self, asset_ids: Iterable[str]) -> tuple[GraphNode, ...]:
        views = self._inventory._views_by_ids(list(asset_ids))
        return tuple(
            GraphNode(
                id=view.id,
                quick_code=view.quick_code,
                name=view.name,
                category=view.category,
                type=view.type,
                status=view.status,
                archived=view.archived,
            )
            for view in sorted(views.values(), key=lambda item: item.id)
        )

    # --------------------------------------------------------------- metadata
    def _type(self, key: Any, *, require_active: bool = False) -> RelationshipType:
        checked = _key(key)
        type_row = self._session.get(RelationshipType, checked)
        if type_row is None:
            raise NotFound("relationship type not found", key="api.relationships.type_not_found")
        if require_active and not type_row.active:
            raise Conflict("relationship type is inactive", key="api.relationships.type_inactive")
        return type_row

    def _relationship(self, relationship_id: Any) -> Relationship:
        if not isinstance(relationship_id, str):
            raise ValidationFailed(
                "relationship id is required",
                key="api.relationships.relationship_id_required",
            )
        try:
            UUID(relationship_id)
        except ValueError:
            raise NotFound(
                "relationship not found", key="api.relationships.relationship_not_found"
            ) from None
        row = self._session.get(Relationship, relationship_id)
        if row is None:
            raise NotFound("relationship not found", key="api.relationships.relationship_not_found")
        return row

    def _existing_assets(self, asset_ids: Sequence[str]) -> None:
        if not asset_ids:
            return
        found = {
            value
            for value in self._session.execute(
                select(Asset.id).where(Asset.id.in_(list(asset_ids)))
            ).scalars()
        }
        missing = [asset_id for asset_id in asset_ids if asset_id not in found]
        if missing:
            raise NotFound("asset not found", key="api.relationships.asset_not_found")

    def _assert_no_duplicate(
        self, source_id: str, target_id: str, type_key: str, *, exclude_id: str | None = None
    ) -> None:
        statement = select(Relationship.id).where(
            Relationship.source_id == source_id,
            Relationship.target_id == target_id,
            Relationship.type_key == type_key,
        )
        if exclude_id is not None:
            statement = statement.where(Relationship.id != exclude_id)
        if self._session.execute(statement).first() is not None:
            raise Conflict("relationship already exists", key="api.relationships.already_exists")

    def _assert_single_host(self, child_id: str, *, exclude_id: str | None = None) -> None:
        statement = select(Relationship.id).where(
            Relationship.source_id == child_id,
            Relationship.type_key == "hosted_in",
        )
        if exclude_id is not None:
            statement = statement.where(Relationship.id != exclude_id)
        if self._session.execute(statement).first() is not None:
            raise Conflict(
                "asset already has a hosting relation; use the host move operation",
                key="api.relationships.hosting_exists",
            )

    def _containment_keys(self) -> set[str]:
        return {
            key
            for key in self._session.execute(
                select(RelationshipType.key).where(RelationshipType.containment.is_(True))
            ).scalars()
        }

    def _assert_containment_edge(
        self,
        source_id: str,
        target_id: str,
        *,
        exclude_edge_id: str | None = None,
    ) -> None:
        """Reject a containment edge that would close a cycle, mixing edge types."""
        if source_id == target_id:
            raise ValidationFailed(
                "an asset cannot relate to itself", key="api.relationships.self_relation"
            )
        containment = self._containment_keys()
        if not containment:
            return
        visited = {target_id}
        frontier = {target_id}
        while frontier:
            statement = select(Relationship.target_id).where(
                Relationship.source_id.in_(frontier),
                Relationship.type_key.in_(containment),
            )
            if exclude_edge_id is not None:
                statement = statement.where(Relationship.id != exclude_edge_id)
            reached = set(self._session.execute(statement).scalars())
            if source_id in reached:
                raise Conflict(
                    "containment relation would create a cycle",
                    key="api.relationships.containment_cycle",
                )
            frontier = reached - visited
            visited |= reached

    def _assert_type_change_safe(self, key: str) -> None:
        """A type that becomes containment must not already close a cycle."""
        containment = self._containment_keys() | {key}
        edges = list(
            self._session.execute(
                select(Relationship.source_id, Relationship.target_id).where(
                    Relationship.type_key.in_(containment)
                )
            ).all()
        )
        adjacency: dict[str, set[str]] = {}
        for source_id, target_id in edges:
            adjacency.setdefault(source_id, set()).add(target_id)
        visiting: set[str] = set()
        visited: set[str] = set()

        def walk(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            if any(walk(child) for child in adjacency.get(node, ())):
                return True
            visiting.remove(node)
            visited.add(node)
            return False

        if any(walk(node) for node in adjacency):
            raise Conflict(
                "containment relation would create a cycle",
                key="api.relationships.containment_cycle",
            )

    # ------------------------------------------------------------ type config
    def list_types(
        self, principal: Principal, *, include_inactive: bool = False
    ) -> tuple[RelationshipTypeView, ...]:
        self._identity.authorize(principal, "assets.view", resource="inventory:relationships")
        statement = select(RelationshipType)
        if not include_inactive:
            statement = statement.where(RelationshipType.active.is_(True))
        rows = self._session.execute(statement.order_by(RelationshipType.key)).scalars()
        return tuple(self._type_view(row) for row in rows)

    @serialized
    def create_type(
        self,
        principal: Principal,
        key: Any,
        *,
        forward_label: Any,
        inverse_label: Any,
        forward_labels: Any = None,
        inverse_labels: Any = None,
        containment: Any = False,
    ) -> RelationshipTypeView:
        self._identity.authorize(principal, "config.general", resource="inventory:relationships")
        checked_key = _key(key)
        if not isinstance(containment, bool):
            raise ValidationFailed(
                "containment must be a boolean", key="api.relationships.containment_boolean"
            )
        if self._session.get(RelationshipType, checked_key) is not None:
            raise Conflict("relationship type already exists", key="api.relationships.type_exists")
        now = utcnow()
        forward_text, forward_map = _label(forward_label, forward_labels, "forwardLabel")
        inverse_text, inverse_map = _label(inverse_label, inverse_labels, "inverseLabel")
        row = RelationshipType(
            key=checked_key,
            forward_label=forward_text,
            inverse_label=inverse_text,
            forward_labels=forward_map,
            inverse_labels=inverse_map,
            containment=containment,
            active=True,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        self._flush_graph()
        self._identity.record_operation(
            principal,
            action="relationships.type_created",
            resource=f"relationship-type:{checked_key}",
        )
        return self._type_view(row)

    @serialized
    def update_type(
        self,
        principal: Principal,
        key: Any,
        *,
        forward_label: Any = _UNSET,
        inverse_label: Any = _UNSET,
        forward_labels: Any = _UNSET,
        inverse_labels: Any = _UNSET,
        containment: Any = _UNSET,
        active: Any = _UNSET,
    ) -> RelationshipTypeView:
        self._identity.authorize(principal, "config.general", resource="inventory:relationships")
        row = self._type(key)
        if forward_label is not _UNSET or forward_labels is not _UNSET:
            row.forward_label, row.forward_labels = _patched_label(
                row.forward_label,
                forward_label,
                forward_labels,
                "forwardLabel",
            )
        if inverse_label is not _UNSET or inverse_labels is not _UNSET:
            row.inverse_label, row.inverse_labels = _patched_label(
                row.inverse_label,
                inverse_label,
                inverse_labels,
                "inverseLabel",
            )
        if containment is not _UNSET:
            if not isinstance(containment, bool):
                raise ValidationFailed(
                    "containment must be a boolean", key="api.relationships.containment_boolean"
                )
            if containment and not row.containment:
                self._assert_type_change_safe(row.key)
            row.containment = containment
        if active is not _UNSET:
            if not isinstance(active, bool):
                raise ValidationFailed(
                    "active must be a boolean", key="api.relationships.active_boolean"
                )
            row.active = active
        row.updated_at = utcnow()
        self._flush_graph()
        self._identity.record_operation(
            principal,
            action="relationships.type_updated",
            resource=f"relationship-type:{row.key}",
        )
        return self._type_view(row)

    # -------------------------------------------------------------- relations
    def list(
        self,
        principal: Principal,
        *,
        asset_id: Any = None,
        asset_ids: Any = (),
        type_key: Any = None,
        direction: Any = "both",
        limit: Any = DEFAULT_LIMIT,
        offset: Any = 0,
    ) -> RelationshipPage:
        self._identity.authorize(principal, "assets.view", resource="inventory:relationships")
        checked_direction = _direction(direction)
        checked_limit, checked_offset = _bounded(limit, offset)
        scope: list[str] = []
        if asset_id is not None:
            scope.append(self._inventory._asset(asset_id).id)
        scope.extend(_asset_ids(asset_ids))
        self._existing_assets(scope)
        scope = list(dict.fromkeys(scope))

        filters: list[ColumnElement[bool]] = []
        if scope:
            if checked_direction == "out":
                filters.append(Relationship.source_id.in_(scope))
            elif checked_direction == "in":
                filters.append(Relationship.target_id.in_(scope))
            else:
                filters.append(
                    or_(
                        Relationship.source_id.in_(scope),
                        Relationship.target_id.in_(scope),
                    )
                )
        if type_key is not None:
            filters.append(Relationship.type_key == self._type(type_key).key)

        total = int(
            self._session.execute(select(func.count(Relationship.id)).where(*filters)).scalar_one()
        )
        rows = self._session.execute(
            select(Relationship)
            .where(*filters)
            .order_by(Relationship.created_at.desc(), Relationship.id.asc())
            .limit(checked_limit)
            .offset(checked_offset)
        ).scalars()
        return RelationshipPage(
            items=self._views(
                rows,
                scope_ids=set(scope) if scope else None,
                global_direction=checked_direction,
            ),
            total=total,
            limit=checked_limit,
            offset=checked_offset,
        )

    @serialized
    def create(
        self,
        principal: Principal,
        *,
        source_id: Any,
        target_id: Any,
        type_key: Any,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> RelationshipView:
        source = self._inventory._asset(source_id)
        target = self._inventory._asset(target_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{source.id}")
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{target.id}")
        type_row = self._type(type_key, require_active=True)
        note = _reason(reason, required=False)
        observations = _notes(notes)
        effective = _effective_at(effective_at)
        if source.id == target.id:
            raise ValidationFailed(
                "an asset cannot relate to itself", key="api.relationships.self_relation"
            )
        if source.archived_at is not None or target.archived_at is not None:
            raise Conflict(
                "archived assets cannot gain relationships",
                key="api.relationships.archived_cannot_relate",
            )
        self._assert_no_duplicate(source.id, target.id, type_row.key)
        if type_row.containment:
            self._assert_containment_edge(source.id, target.id)
        if type_row.key == "hosted_in":
            self._assert_single_host(source.id)

        now = utcnow()
        row = Relationship(
            id=str(uuid4()),
            type_key=type_row.key,
            source_id=source.id,
            target_id=target.id,
            reason=note,
            notes=observations,
            effective_at=effective,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        self._flush_graph()
        self._record_relation_history(
            principal,
            source,
            target,
            action="relationship_created",
            old=None,
            new=_descriptor(row),
            relationship_id=row.id,
            reason=note,
            notes=observations,
            effective_at=effective,
        )
        self._identity.record_operation(
            principal, action="relationships.created", resource=f"relationship:{row.id}"
        )
        return self._view(row, type_row, direction="outgoing")

    @serialized
    def update(
        self,
        principal: Principal,
        relationship_id: Any,
        *,
        type_key: Any = None,
        reason: Any = _UNSET,
        notes: Any = _UNSET,
        effective_at: Any = _UNSET,
    ) -> RelationshipView:
        row = self._relationship(relationship_id)
        source = self._inventory._asset(row.source_id)
        target = self._inventory._asset(row.target_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{source.id}")
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{target.id}")
        old_type = self._type(row.type_key)
        new_type = old_type if type_key is None else self._type(type_key, require_active=True)
        note = row.reason if reason is _UNSET else _reason(reason, required=False)
        observations = row.notes if notes is _UNSET else _notes(notes)
        effective = row.effective_at if effective_at is _UNSET else _effective_at(effective_at)
        old_descriptor = _descriptor(row)
        if new_type.key != row.type_key:
            if new_type.containment:
                self._assert_containment_edge(
                    row.source_id,
                    row.target_id,
                    exclude_edge_id=row.id,
                )
            if new_type.key == "hosted_in":
                self._assert_single_host(row.source_id, exclude_id=row.id)
            row.type_key = new_type.key
        row.reason = note
        row.notes = observations
        row.effective_at = effective
        row.updated_at = utcnow()
        self._flush_graph()
        self._record_relation_history(
            principal,
            source,
            target,
            action="relationship_updated",
            old=old_descriptor,
            new=_descriptor(row),
            relationship_id=row.id,
            reason=note,
            notes=observations,
            effective_at=effective,
        )
        self._identity.record_operation(
            principal, action="relationships.updated", resource=f"relationship:{row.id}"
        )
        return self._view(row, new_type, direction="outgoing")

    @serialized
    def remove(
        self,
        principal: Principal,
        relationship_id: Any,
        *,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> RelationshipView:
        row = self._relationship(relationship_id)
        source = self._inventory._asset(row.source_id)
        target = self._inventory._asset(row.target_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{source.id}")
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{target.id}")
        type_row = self._type(row.type_key)
        note = _reason(reason, required=False)
        observations = _notes(notes)
        effective = _effective_at(effective_at)
        view = self._view(row, type_row, direction="outgoing")
        old_descriptor = _descriptor(row)
        self._session.delete(row)
        self._flush_graph()
        self._record_relation_history(
            principal,
            source,
            target,
            action="relationship_removed",
            old=old_descriptor,
            new=None,
            relationship_id=view.id,
            reason=note,
            notes=observations,
            effective_at=effective,
        )
        self._identity.record_operation(
            principal, action="relationships.removed", resource=f"relationship:{view.id}"
        )
        return view

    @serialized
    def move_host(
        self,
        principal: Principal,
        child_id: Any,
        new_host_id: Any,
        *,
        reason: Any,
        notes: Any = None,
        effective_at: Any = None,
    ) -> HostMoveResult:
        child = self._inventory._asset(child_id)
        new_host = self._inventory._asset(new_host_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{child.id}")
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{new_host.id}")
        type_row = self._type("hosted_in", require_active=True)
        note = _reason(reason, required=True)
        assert note is not None
        observations = _notes(notes)
        effective = _effective_at(effective_at)
        if child.id == new_host.id:
            raise ValidationFailed(
                "an asset cannot be hosted in itself", key="api.relationships.self_hosting"
            )
        if child.archived_at is not None or new_host.archived_at is not None:
            raise Conflict(
                "archived assets cannot move hosting relations",
                key="api.relationships.archived_cannot_move_hosting",
            )
        current = list(
            self._session.execute(
                select(Relationship).where(
                    Relationship.source_id == child.id,
                    Relationship.type_key == "hosted_in",
                )
            ).scalars()
        )
        if len(current) != 1:
            raise Conflict(
                "asset has no hosting relationship to move",
                key="api.relationships.hosting_missing",
            )
        old = current[0]
        old_host = self._inventory._asset(old.target_id)
        self._identity.authorize(principal, "assets.edit", resource=f"asset:{old_host.id}")
        self._assert_containment_edge(child.id, new_host.id, exclude_edge_id=old.id)

        old_id = old.id
        old_host_id = old.target_id
        old_view = self._view(old, type_row, direction="outgoing")
        now = utcnow()
        new = Relationship(
            id=str(uuid4()),
            type_key="hosted_in",
            source_id=child.id,
            target_id=new_host.id,
            reason=note,
            notes=observations,
            effective_at=effective,
            created_at=now,
            updated_at=now,
        )
        self._session.add(new)
        self._session.delete(old)
        self._flush_graph()
        relationship_change = {
            "old": old_id,
            "new": new.id,
        }
        self._inventory._record_history(
            principal,
            child,
            "host_moved",
            changes={
                "host": {"old": old_host_id, "new": new_host.id},
                "relationshipId": relationship_change,
            },
            reason=note,
            notes=observations,
            effective_at=effective,
            source=self._source,
            entity_type="relationship",
            entity_id=new.id,
        )
        self._inventory._record_history(
            principal,
            old_host,
            "host_moved",
            changes={
                "hostedChild": {"old": child.id, "new": None},
                "relationshipId": relationship_change,
            },
            reason=note,
            notes=observations,
            effective_at=effective,
            source=self._source,
            entity_type="relationship",
            entity_id=new.id,
        )
        self._inventory._record_history(
            principal,
            new_host,
            "host_moved",
            changes={
                "hostedChild": {"old": None, "new": child.id},
                "relationshipId": relationship_change,
            },
            reason=note,
            notes=observations,
            effective_at=effective,
            source=self._source,
            entity_type="relationship",
            entity_id=new.id,
        )
        self._identity.record_operation(
            principal, action="relationships.host_moved", resource=f"relationship:{new.id}"
        )
        return HostMoveResult(
            child_id=child.id,
            old_relationship=old_view,
            new_relationship=self._view(new, type_row, direction="outgoing"),
            effective_at=effective,
        )

    # ----------------------------------------------------------------- graph
    def graph(
        self,
        principal: Principal,
        *,
        root_id: Any = None,
        asset_ids: Any = (),
        depth: Any = DEFAULT_GRAPH_DEPTH,
        direction: Any = "both",
        type_key: Any = None,
        limit: Any = DEFAULT_LIMIT,
        offset: Any = 0,
    ) -> GraphView:
        self._identity.authorize(principal, "assets.view", resource="inventory:relationships")
        checked_direction = _direction(direction)
        checked_depth = _depth(depth)
        checked_limit, checked_offset = _bounded(limit, offset)
        seeds = _asset_ids(asset_ids)
        if root_id is not None and seeds:
            raise ValidationFailed(
                "use either rootId or assetIds, not both", key="api.relationships.root_or_ids"
            )
        if root_id is not None:
            seeds = [self._inventory._asset(root_id).id]
        self._existing_assets(seeds)
        type_filter = None if type_key is None else self._type(type_key).key
        if seeds:
            return self._traverse(
                seeds,
                depth=checked_depth,
                direction=checked_direction,
                type_key=type_filter,
                limit=checked_limit,
                offset=checked_offset,
            )
        return self._global_graph(
            direction=checked_direction,
            depth=checked_depth,
            type_key=type_filter,
            limit=checked_limit,
            offset=checked_offset,
        )

    def _traverse(
        self,
        seeds: Sequence[str],
        *,
        depth: int,
        direction: str,
        type_key: str | None,
        limit: int,
        offset: int,
    ) -> GraphView:
        visited = set(seeds)
        frontier = set(seeds)
        collected: dict[str, tuple[Relationship, str]] = {}
        nodes_truncated = False
        edges_truncated = False
        depth_truncated = False

        for _ in range(depth):
            if not frontier:
                break
            conditions: list[ColumnElement[bool]] = []
            if direction in {"out", "both"}:
                conditions.append(Relationship.source_id.in_(frontier))
            if direction in {"in", "both"}:
                conditions.append(Relationship.target_id.in_(frontier))
            statement = select(Relationship).where(or_(*conditions))
            if type_key is not None:
                statement = statement.where(Relationship.type_key == type_key)
            if collected:
                statement = statement.where(Relationship.id.not_in(list(collected)))
            remaining = MAX_GRAPH_EDGES - len(collected)
            rows = list(
                self._session.execute(
                    statement.order_by(Relationship.id).limit(remaining + 1)
                ).scalars()
            )
            if len(rows) > remaining:
                edges_truncated = True
                rows = rows[:remaining]
            next_frontier: set[str] = set()
            for row in rows:
                if row.id in collected:
                    continue
                edge_direction = "outgoing" if row.source_id in frontier else "incoming"
                collected[row.id] = (row, edge_direction)
                other = row.target_id if edge_direction == "outgoing" else row.source_id
                if other not in visited:
                    next_frontier.add(other)
            if len(visited) + len(next_frontier) > MAX_GRAPH_NODES:
                nodes_truncated = True
                allowed = max(0, MAX_GRAPH_NODES - len(visited))
                next_frontier = set(sorted(next_frontier)[:allowed])
            visited |= next_frontier
            frontier = next_frontier
            if edges_truncated:
                break
        else:
            depth_truncated = bool(frontier)

        types = self._type_map(row for row, _ in collected.values())
        edges = tuple(
            self._view(row, types[row.type_key], direction=edge_direction)
            for row, edge_direction in collected.values()
        )
        return GraphView(
            root_id=seeds[0] if len(seeds) == 1 else None,
            depth=depth,
            direction=direction,
            nodes=self._nodes(visited),
            edges=edges,
            nodes_truncated=nodes_truncated,
            edges_truncated=edges_truncated,
            depth_truncated=depth_truncated,
            limit=limit,
            offset=offset,
            total=None,
        )

    def _global_graph(
        self,
        *,
        direction: str,
        depth: int,
        type_key: str | None,
        limit: int,
        offset: int,
    ) -> GraphView:
        filters: list[ColumnElement[bool]] = []
        if type_key is not None:
            filters.append(Relationship.type_key == type_key)
        total = int(
            self._session.execute(select(func.count(Relationship.id)).where(*filters)).scalar_one()
        )
        rows = list(
            self._session.execute(
                select(Relationship)
                .where(*filters)
                .order_by(Relationship.created_at.desc(), Relationship.id.asc())
                .limit(limit)
                .offset(offset)
            ).scalars()
        )
        edges = self._views(rows, global_direction=direction)
        node_ids = {row.source_id for row in rows} | {row.target_id for row in rows}
        return GraphView(
            root_id=None,
            depth=depth,
            direction=direction,
            nodes=self._nodes(node_ids),
            edges=edges,
            nodes_truncated=False,
            edges_truncated=False,
            depth_truncated=False,
            limit=limit,
            offset=offset,
            total=total,
        )

    # --------------------------------------------------------------- helpers
    def _flush_graph(self) -> None:
        try:
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            raise Conflict(
                "relationship already exists", key="api.relationships.already_exists"
            ) from None

    def _record_relation_history(
        self,
        principal: Principal,
        source: Asset,
        target: Asset,
        *,
        action: str,
        old: Mapping[str, Any] | None,
        new: Mapping[str, Any] | None,
        relationship_id: str,
        reason: str | None,
        notes: str | None,
        effective_at: datetime | None,
    ) -> None:
        """Record the same meaningful before/after event on both endpoints."""
        changes = {"relationship": {"old": old, "new": new}}
        for asset in (source, target):
            self._inventory._record_history(
                principal,
                asset,
                action,
                changes=changes,
                reason=reason,
                notes=notes,
                effective_at=effective_at,
                source=self._source,
                entity_type="relationship",
                entity_id=relationship_id,
            )


__all__ = [
    "BULK_LIMIT",
    "DEFAULT_GRAPH_DEPTH",
    "MAX_GRAPH_DEPTH",
    "MAX_GRAPH_EDGES",
    "MAX_GRAPH_NODES",
    "GraphNode",
    "GraphView",
    "HostMoveResult",
    "RelationshipPage",
    "RelationshipService",
    "RelationshipTypeView",
    "RelationshipView",
]
