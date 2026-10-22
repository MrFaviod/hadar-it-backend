"""Canonical redundancy-group business layer shared by REST, the agent and MCP.

A group records that several *independently identified* inventory assets are
replicas of the same workload. It never creates a second identity, never moves
or duplicates an asset and never rewrites the single-host ``hosted_in`` rule:
every member keeps its own UUID, quick code and hosting relation.

Rules enforced here, once, for every front door:

* ``active_active`` members carry a finite decimal traffic share between 0 and
  100 with at most two decimals; a complete group (two or more members) totals
  exactly 100.
* ``active_passive`` members carry ``primary``/``backup`` roles and no share at
  all (``NULL``, never a fabricated 0/100 measurement); a complete group has
  exactly one primary and at least one backup.
* An active group has at least two distinct members and refuses archived
  members. A deactivated group keeps its history, can shrink to an incomplete
  member list so stale replicas can be cleaned up, and can be activated again
  once it is valid again.
* One mutation is one transaction: membership replacement, the affected assets'
  structured history and exactly one terminal identity audit commit together.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.config import Settings
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
from itsm.redundancy.models import RedundancyGroup, RedundancyGroupMember
from itsm.relationships.models import Relationship

MODES: tuple[str, ...] = ("active_active", "active_passive")
ROLES: tuple[str, ...] = ("primary", "backup")
MAX_MEMBERS = 50
NAME_MAX = 160
DESCRIPTION_MAX = 1000
QUERY_MAX = 120
SHARE_MAX_DECIMALS = 2
UNSET: Any = object()

CREATE_EVENT = "redundancy.group_created"
UPDATE_EVENT = "redundancy.group_updated"
DEACTIVATE_EVENT = "redundancy.group_deactivated"
CREATED_ACTION = "redundancy_group_created"
UPDATED_ACTION = "redundancy_group_updated"
DEACTIVATED_ACTION = "redundancy_group_deactivated"


@dataclass(frozen=True)
class MemberHostView:
    """The member's existing host, projected without inventing placement."""

    id: str
    name: str | None

    def as_payload(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name}


@dataclass(frozen=True)
class RedundancyMemberView:
    asset_id: str
    name: str
    quick_code: str
    archived: bool
    role: str | None
    share: str | None
    host: MemberHostView | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "assetId": self.asset_id,
            "name": self.name,
            "quickCode": self.quick_code,
            "archived": self.archived,
            "role": self.role,
            "share": self.share,
            "host": None if self.host is None else self.host.as_payload(),
        }


@dataclass(frozen=True)
class RedundancyGroupView:
    id: str
    name: str
    description: str | None
    mode: str
    active: bool
    created_at: datetime
    updated_at: datetime
    members: tuple[RedundancyMemberView, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mode": self.mode,
            "active": bool(self.active),
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
            "memberCount": len(self.members),
            "members": [member.as_payload() for member in self.members],
        }


@dataclass(frozen=True)
class RedundancyGroupPage:
    total: int
    limit: int
    offset: int
    items: tuple[RedundancyGroupView, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "items": [item.as_payload() for item in self.items],
        }


# ------------------------------------------------------------------ validation
def _mode(value: Any) -> str:
    if not isinstance(value, str) or value not in MODES:
        raise ValidationFailed("mode must be active_active or active_passive")
    return value


def _name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationFailed("name must be text")
    normalized = value.strip()
    if not 1 <= len(normalized) <= NAME_MAX:
        raise ValidationFailed(f"name must be between 1 and {NAME_MAX} characters")
    return normalized


def _description(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed("description must be text")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > DESCRIPTION_MAX:
        raise ValidationFailed(f"description must be at most {DESCRIPTION_MAX} characters")
    return normalized


def _active(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValidationFailed("active must be a boolean")
    return value


def _share(value: Any) -> str:
    """Return the canonical decimal string of a finite 0..100 share."""
    if value is None or isinstance(value, bool):
        raise ValidationFailed("every active/active member needs a numeric traffic share")
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation, ValueError, AttributeError:
        raise ValidationFailed("traffic share must be a decimal number") from None
    if not number.is_finite():
        raise ValidationFailed("traffic share must be finite")
    if number < 0 or number > 100:
        raise ValidationFailed("traffic share must be between 0 and 100")
    if -number.as_tuple().exponent > SHARE_MAX_DECIMALS:
        raise ValidationFailed("traffic share allows at most two decimals")
    return format(number.normalize(), "f")


def _limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationFailed("limit must be an integer")
    if not 1 <= value <= MAX_LIMIT:
        raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
    return value


def _offset(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationFailed("offset must be a non-negative integer")
    return value


def _query(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed("query must be text")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > QUERY_MAX:
        raise ValidationFailed(f"query must be at most {QUERY_MAX} characters")
    return normalized


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _asset_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationFailed("assetId must be a UUID")
    try:
        UUID(value)
    except ValueError:
        raise NotFound("asset not found") from None
    return value


def _specs(value: Any) -> list[dict[str, Any]]:
    """Normalize an explicit member list; every entry keeps its raw role/share."""
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Sequence):
        raise ValidationFailed("members must be a list of member objects")
    entries = list(value)
    if len(entries) > MAX_MEMBERS:
        raise ValidationFailed(f"a redundancy group accepts at most {MAX_MEMBERS} members")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValidationFailed("every member must be an object")
        unknown = set(entry) - {"asset_id", "role", "share"}
        if unknown:
            raise ValidationFailed("member fields are assetId, role and share")
        asset_id = _asset_id(entry.get("asset_id"))
        if asset_id in seen:
            raise ValidationFailed("duplicate member asset")
        seen.add(asset_id)
        normalized.append(
            {"asset_id": asset_id, "role": entry.get("role"), "share": entry.get("share")}
        )
    return normalized


def _resolve_specs(
    specs: Sequence[Mapping[str, Any]],
    mode: str,
    *,
    active: bool,
    archived: Mapping[str, bool],
) -> list[dict[str, Any]]:
    """Validate mode-specific roles/shares and the activation invariants."""
    resolved: list[dict[str, Any]] = []
    roles: list[str] = []
    for spec in specs:
        role = spec.get("role")
        share = spec.get("share")
        if mode == "active_active":
            if role is not None:
                raise ValidationFailed("active/active members do not take a role")
            resolved.append({"asset_id": spec["asset_id"], "role": None, "share": _share(share)})
            continue
        if share is not None:
            raise ValidationFailed("active/passive members do not take a traffic share")
        if role not in ROLES:
            raise ValidationFailed("active/passive members need role primary or backup")
        roles.append(role)
        resolved.append({"asset_id": spec["asset_id"], "role": role, "share": None})

    complete = len(resolved) >= 2
    if complete and mode == "active_passive":
        if roles.count("primary") != 1:
            raise ValidationFailed("an active/passive group needs exactly one primary")
        if roles.count("backup") < 1:
            raise ValidationFailed("an active/passive group needs at least one backup")
    if mode == "active_passive" and roles.count("primary") > 1:
        raise ValidationFailed("an active/passive group needs exactly one primary")
    if complete and mode == "active_active":
        total = sum(Decimal(spec["share"]) for spec in resolved)
        if total != Decimal("100"):
            raise ValidationFailed("active/active traffic shares must total exactly 100")
    if active:
        if len(resolved) < 2:
            raise ValidationFailed("an active redundancy group needs at least two members")
        archived_ids = [spec["asset_id"] for spec in resolved if archived[spec["asset_id"]]]
        if archived_ids:
            raise Conflict("an active redundancy group cannot include archived assets")
    return resolved


def _member_state(
    group_id: str,
    name: str,
    mode: str,
    active: bool,
    role: str | None,
    share: str | None,
) -> dict[str, Any]:
    return {
        "groupId": group_id,
        "name": name,
        "mode": mode,
        "active": bool(active),
        "role": role,
        "share": share,
    }


def _sort_key(member: RedundancyMemberView) -> tuple[int, str, str]:
    order = 0 if member.role == "primary" else 1 if member.role == "backup" else 2
    return (order, member.name.lower(), member.asset_id)


class RedundancyService:
    """The single implementation of redundancy rules for every front door."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        inventory: InventoryService | None = None,
        source: str = "internal",
    ) -> None:
        self._session = session
        self._settings = settings
        self._identity = identity or IdentityService(session, settings)
        self._source = _history_source(source)
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
    def _group(self, group_id: Any) -> RedundancyGroup:
        if not isinstance(group_id, str):
            raise ValidationFailed("group id is required")
        try:
            UUID(group_id)
        except ValueError:
            raise NotFound("redundancy group not found") from None
        row = self._session.get(RedundancyGroup, group_id)
        if row is None:
            raise NotFound("redundancy group not found")
        return row

    def _rows(self, group_id: str) -> list[RedundancyGroupMember]:
        return list(
            self._session.execute(
                select(RedundancyGroupMember)
                .where(RedundancyGroupMember.group_id == group_id)
                .order_by(RedundancyGroupMember.asset_id)
            ).scalars()
        )

    def _facts(self, asset_ids: Iterable[str]) -> dict[str, Asset]:
        ids = list(dict.fromkeys(asset_ids))
        if not ids:
            return {}
        rows = self._session.execute(select(Asset).where(Asset.id.in_(ids))).scalars()
        found = {asset.id: asset for asset in rows}
        missing = [asset_id for asset_id in ids if asset_id not in found]
        if missing:
            raise NotFound("asset not found")
        return found

    def _hosts(self, asset_ids: Iterable[str]) -> dict[str, str]:
        ids = list(dict.fromkeys(asset_ids))
        if not ids:
            return {}
        rows = self._session.execute(
            select(Relationship.source_id, Relationship.target_id)
            .where(
                Relationship.type_key == "hosted_in",
                Relationship.source_id.in_(ids),
            )
            .order_by(Relationship.source_id, Relationship.id)
        ).all()
        hosts: dict[str, str] = {}
        for source_id, target_id in rows:
            hosts.setdefault(source_id, target_id)
        return hosts

    def _members(self, group_ids: Sequence[str]) -> dict[str, tuple[RedundancyMemberView, ...]]:
        if not group_ids:
            return {}
        rows = list(
            self._session.execute(
                select(RedundancyGroupMember)
                .where(RedundancyGroupMember.group_id.in_(list(group_ids)))
                .order_by(RedundancyGroupMember.group_id, RedundancyGroupMember.asset_id)
            ).scalars()
        )
        if not rows:
            return {}
        asset_ids = [row.asset_id for row in rows]
        hosts = self._hosts(asset_ids)
        facts = self._facts(list(asset_ids) + list(hosts.values()))
        grouped: dict[str, list[RedundancyMemberView]] = {}
        for row in rows:
            asset = facts[row.asset_id]
            host_id = hosts.get(row.asset_id)
            host = None
            if host_id is not None:
                host_asset = facts.get(host_id)
                host = MemberHostView(
                    id=host_id,
                    name=None if host_asset is None else host_asset.name,
                )
            grouped.setdefault(row.group_id, []).append(
                RedundancyMemberView(
                    asset_id=asset.id,
                    name=asset.name,
                    quick_code=asset.quick_code,
                    archived=asset.archived_at is not None,
                    role=row.role,
                    share=row.share,
                    host=host,
                )
            )
        return {
            group_id: tuple(sorted(members, key=_sort_key)) for group_id, members in grouped.items()
        }

    def _views(self, groups: Iterable[RedundancyGroup]) -> tuple[RedundancyGroupView, ...]:
        stored = list(groups)
        members = self._members([group.id for group in stored])
        return tuple(
            RedundancyGroupView(
                id=group.id,
                name=group.name,
                description=group.description,
                mode=group.mode,
                active=bool(group.active),
                created_at=as_utc(group.created_at),
                updated_at=as_utc(group.updated_at),
                members=members.get(group.id, ()),
            )
            for group in stored
        )

    # ------------------------------------------------------------------- reads
    def list(
        self,
        principal: Principal,
        *,
        query: Any = None,
        active: Any = None,
        mode: Any = None,
        limit: Any = DEFAULT_LIMIT,
        offset: Any = 0,
    ) -> RedundancyGroupPage:
        self._identity.authorize(principal, "assets.view", resource="inventory:redundancy")
        bounded_limit = _limit(limit)
        bounded_offset = _offset(offset)
        text = _query(query)
        if active is not None and not isinstance(active, bool):
            raise ValidationFailed("active must be a boolean")
        checked_mode = None if mode is None else _mode(mode)

        filters = []
        if text is not None:
            pattern = f"%{_escape_like(text)}%"
            filters.append(
                or_(
                    RedundancyGroup.name.ilike(pattern, escape="\\"),
                    RedundancyGroup.description.ilike(pattern, escape="\\"),
                )
            )
        if active is not None:
            filters.append(RedundancyGroup.active.is_(active))
        if checked_mode is not None:
            filters.append(RedundancyGroup.mode == checked_mode)

        total = int(
            self._session.execute(
                select(func.count()).select_from(RedundancyGroup).where(*filters)
            ).scalar_one()
        )
        rows = list(
            self._session.execute(
                select(RedundancyGroup)
                .where(*filters)
                .order_by(
                    func.lower(RedundancyGroup.name),
                    RedundancyGroup.created_at,
                    RedundancyGroup.id,
                )
                .limit(bounded_limit)
                .offset(bounded_offset)
            ).scalars()
        )
        return RedundancyGroupPage(
            total=total,
            limit=bounded_limit,
            offset=bounded_offset,
            items=self._views(rows),
        )

    def get(self, principal: Principal, group_id: Any) -> RedundancyGroupView:
        self._identity.authorize(principal, "assets.view", resource="inventory:redundancy")
        group = self._group(group_id)
        return self._views([group])[0]

    # -------------------------------------------------------------- mutations
    def _authorize(self, principal: Principal, asset_ids: Iterable[str], group_id: str) -> None:
        self._identity.authorize(principal, "assets.edit", resource=f"redundancy-group:{group_id}")
        for asset_id in dict.fromkeys(asset_ids):
            self._identity.authorize(principal, "assets.edit", resource=f"asset:{asset_id}")

    def _record_event(
        self,
        principal: Principal,
        facts: Mapping[str, Asset],
        old_states: Mapping[str, Any],
        new_states: Mapping[str, Any],
        *,
        action: str,
        group_id: str,
        reason: str | None,
        notes: str | None,
        effective_at: datetime | None,
    ) -> int:
        written = 0
        for asset_id in dict.fromkeys([*old_states, *new_states]):
            old = old_states.get(asset_id)
            new = new_states.get(asset_id)
            if old == new:
                continue
            self._inventory._record_history(
                principal,
                facts[asset_id],
                action,
                changes={"redundancyGroup": {"old": old, "new": new}},
                reason=reason,
                notes=notes,
                effective_at=effective_at,
                source=self._source,
                entity_type="redundancy_group",
                entity_id=group_id,
            )
            written += 1
        return written

    @serialized
    def create(
        self,
        principal: Principal,
        *,
        name: Any,
        mode: Any,
        members: Any,
        description: Any = None,
        active: Any = True,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> RedundancyGroupView:
        """Create one group and its complete member list in a single transaction."""
        checked_name = _name(name)
        checked_mode = _mode(mode)
        checked_active = _active(active)
        checked_description = _description(description)
        checked_reason = _reason(reason, required=False)
        checked_notes = _notes(notes)
        checked_effective = _effective_at(effective_at)
        specs = _specs(members)
        if len(specs) < 2:
            raise ValidationFailed("a redundancy group needs at least two members")

        facts = self._facts([spec["asset_id"] for spec in specs])
        group_id = str(uuid4())
        self._authorize(principal, facts, group_id)
        resolved = _resolve_specs(
            specs,
            checked_mode,
            active=checked_active,
            archived={asset_id: asset.archived_at is not None for asset_id, asset in facts.items()},
        )

        now = utcnow()
        group = RedundancyGroup(
            id=group_id,
            name=checked_name,
            description=checked_description,
            mode=checked_mode,
            active=checked_active,
            created_at=now,
            updated_at=now,
        )
        self._session.add(group)
        for spec in resolved:
            self._session.add(
                RedundancyGroupMember(
                    id=str(uuid4()),
                    group_id=group_id,
                    asset_id=spec["asset_id"],
                    role=spec["role"],
                    share=spec["share"],
                    created_at=now,
                    updated_at=now,
                )
            )
        self._flush()
        new_states = {
            spec["asset_id"]: _member_state(
                group_id, checked_name, checked_mode, checked_active, spec["role"], spec["share"]
            )
            for spec in resolved
        }
        self._record_event(
            principal,
            facts,
            {},
            new_states,
            action=CREATED_ACTION,
            group_id=group_id,
            reason=checked_reason,
            notes=checked_notes,
            effective_at=checked_effective,
        )
        self._identity.record_operation(
            principal,
            action=CREATE_EVENT,
            resource=f"redundancy-group:{group_id}",
        )
        return self._views([group])[0]

    @serialized
    def update(
        self,
        principal: Principal,
        group_id: Any,
        *,
        name: Any = UNSET,
        description: Any = UNSET,
        mode: Any = UNSET,
        active: Any = UNSET,
        members: Any = UNSET,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> RedundancyGroupView:
        """Replace fields and/or the complete member list; validate before writing."""
        group = self._group(group_id)
        current = self._rows(group.id)
        current_ids = [row.asset_id for row in current]
        explicit = members is not UNSET
        specs: list[dict[str, Any]] | None = None
        if explicit:
            specs = _specs(members)
        proposed_ids = (
            [spec["asset_id"] for spec in specs] if specs is not None else list(current_ids)
        )
        facts = self._facts([*current_ids, *proposed_ids])
        self._authorize(principal, list(facts), group.id)

        new_name = group.name if name is UNSET else _name(name)
        new_description = group.description if description is UNSET else _description(description)
        new_mode = group.mode if mode is UNSET else _mode(mode)
        new_active = bool(group.active) if active is UNSET else _active(active)
        if mode is not UNSET and new_mode != group.mode and specs is None:
            raise ValidationFailed("changing mode requires the complete member list")
        if specs is None:
            specs = [
                {"asset_id": row.asset_id, "role": row.role, "share": row.share} for row in current
            ]
        checked_reason = _reason(reason, required=False)
        checked_notes = _notes(notes)
        checked_effective = _effective_at(effective_at)
        resolved = _resolve_specs(
            specs,
            new_mode,
            active=new_active,
            archived={asset_id: asset.archived_at is not None for asset_id, asset in facts.items()},
        )

        old_states = {
            row.asset_id: _member_state(
                group.id, group.name, group.mode, bool(group.active), row.role, row.share
            )
            for row in current
        }
        new_states = {
            spec["asset_id"]: _member_state(
                group.id, new_name, new_mode, new_active, spec["role"], spec["share"]
            )
            for spec in resolved
        }
        changed_members = {
            asset_id
            for asset_id in set(old_states) | set(new_states)
            if old_states.get(asset_id) != new_states.get(asset_id)
        }
        changed_group = (
            new_name != group.name
            or new_description != group.description
            or new_mode != group.mode
            or new_active != bool(group.active)
        )
        if not changed_group and not changed_members:
            return self._views([group])[0]

        retained = {row.asset_id: row for row in current}
        resolved_ids = {spec["asset_id"] for spec in resolved}
        now = utcnow()
        for row in current:
            if row.asset_id not in resolved_ids:
                self._session.delete(row)
        for spec in resolved:
            row = retained.get(spec["asset_id"])
            if row is None:
                self._session.add(
                    RedundancyGroupMember(
                        id=str(uuid4()),
                        group_id=group.id,
                        asset_id=spec["asset_id"],
                        role=spec["role"],
                        share=spec["share"],
                        created_at=now,
                        updated_at=now,
                    )
                )
                continue
            if (row.role, row.share) != (spec["role"], spec["share"]):
                row.role = spec["role"]
                row.share = spec["share"]
                row.updated_at = now
        if changed_group:
            group.name = new_name
            group.description = new_description
            group.mode = new_mode
            group.active = new_active
        group.updated_at = now
        self._flush()
        self._record_event(
            principal,
            facts,
            old_states,
            new_states,
            action=UPDATED_ACTION,
            group_id=group.id,
            reason=checked_reason,
            notes=checked_notes,
            effective_at=checked_effective,
        )
        self._identity.record_operation(
            principal,
            action=UPDATE_EVENT,
            resource=f"redundancy-group:{group.id}",
        )
        return self._views([group])[0]

    @serialized
    def deactivate(
        self,
        principal: Principal,
        group_id: Any,
        *,
        reason: Any = None,
        notes: Any = None,
        effective_at: Any = None,
    ) -> RedundancyGroupView:
        """Deactivate a group without deleting it, its members or its history."""
        group = self._group(group_id)
        current = self._rows(group.id)
        facts = self._facts([row.asset_id for row in current])
        self._authorize(principal, list(facts), group.id)
        if not group.active:
            raise Conflict("redundancy group is already inactive")
        checked_reason = _reason(reason, required=False)
        checked_notes = _notes(notes)
        checked_effective = _effective_at(effective_at)

        old_states = {
            row.asset_id: _member_state(group.id, group.name, group.mode, True, row.role, row.share)
            for row in current
        }
        new_states = {
            row.asset_id: _member_state(
                group.id, group.name, group.mode, False, row.role, row.share
            )
            for row in current
        }
        group.active = False
        group.updated_at = utcnow()
        self._flush()
        self._record_event(
            principal,
            facts,
            old_states,
            new_states,
            action=DEACTIVATED_ACTION,
            group_id=group.id,
            reason=checked_reason,
            notes=checked_notes,
            effective_at=checked_effective,
        )
        self._identity.record_operation(
            principal,
            action=DEACTIVATE_EVENT,
            resource=f"redundancy-group:{group.id}",
        )
        return self._views([group])[0]

    def _flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            raise Conflict("redundancy group conflicts with stored data") from None


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_MEMBERS",
    "MODES",
    "MemberHostView",
    "RedundancyGroupPage",
    "RedundancyGroupView",
    "RedundancyMemberView",
    "RedundancyService",
]
