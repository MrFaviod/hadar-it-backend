"""HTTP adapter for redundancy groups: bounded DTOs over the canonical service."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService
from itsm.redundancy.service import DEFAULT_LIMIT, MAX_MEMBERS, RedundancyService


class GroupMemberInput(BaseModel):
    """One member reference; the field names are camelCase on the wire."""

    model_config = ConfigDict(extra="forbid")

    assetId: str = Field(min_length=1, max_length=36)
    role: str | None = Field(default=None, max_length=16)
    share: Any = None


class GroupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    mode: str = Field(min_length=1, max_length=16)
    active: bool = True
    members: list[GroupMemberInput] = Field(min_length=2, max_length=MAX_MEMBERS)
    reason: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


class GroupPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    mode: str | None = Field(default=None, min_length=1, max_length=16)
    active: bool | None = None
    members: list[GroupMemberInput] | None = Field(default=None, max_length=MAX_MEMBERS)
    reason: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


class GroupDeactivateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


def get_redundancy_service(request: Request) -> Iterator[RedundancyService]:
    """One session, one identity service and one redundancy service per request."""
    session = request.app.state.session_factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield RedundancyService(
            session,
            request.app.state.settings,
            identity=identity,
            source="rest",
        )
    finally:
        session.close()


RedundancyDependency = Annotated[RedundancyService, Depends(get_redundancy_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]

_ALIASES = {"effectiveAt": "effective_at"}


def _members(payload: list[GroupMemberInput] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    return [
        {"asset_id": member.assetId, "role": member.role, "share": member.share}
        for member in payload
    ]


def _changes(payload: BaseModel) -> dict[str, Any]:
    """Forward only explicitly provided fields so ``null`` clears a description."""
    changes: dict[str, Any] = {}
    for name in payload.model_fields_set:
        if name == "members":
            changes["members"] = _members(payload.members)  # type: ignore[attr-defined]
            continue
        changes[_ALIASES.get(name, name)] = getattr(payload, name)
    return changes


def create_redundancy_router() -> APIRouter:
    """Redundancy routes, mounted under the versioned API prefix before MCP."""
    router = APIRouter()

    @router.get("/redundancy-groups")
    def list_redundancy_groups(
        service: RedundancyDependency,
        context: AuthDependency,
        query: str | None = Query(default=None, max_length=120),
        active: bool | None = Query(default=None),
        mode: str | None = Query(default=None, max_length=16),
        limit: int = Query(default=DEFAULT_LIMIT),
        offset: int = Query(default=0),
    ) -> dict[str, Any]:
        return service.list(
            context.principal,
            query=query,
            active=active,
            mode=mode,
            limit=limit,
            offset=offset,
        ).as_payload()

    @router.post("/redundancy-groups", status_code=201)
    def create_redundancy_group(
        payload: GroupInput,
        service: RedundancyDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.create(
            context.principal,
            name=payload.name,
            mode=payload.mode,
            members=_members(payload.members),
            description=payload.description,
            active=payload.active,
            reason=payload.reason,
            notes=payload.notes,
            effective_at=payload.effectiveAt,
        ).as_payload()

    @router.get("/redundancy-groups/{group_id}")
    def get_redundancy_group(
        group_id: str,
        service: RedundancyDependency,
        context: AuthDependency,
    ) -> dict[str, Any]:
        return service.get(context.principal, group_id).as_payload()

    @router.patch("/redundancy-groups/{group_id}")
    def update_redundancy_group(
        group_id: str,
        payload: GroupPatch,
        service: RedundancyDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.update(context.principal, group_id, **_changes(payload)).as_payload()

    @router.post("/redundancy-groups/{group_id}/deactivate")
    def deactivate_redundancy_group(
        group_id: str,
        service: RedundancyDependency,
        context: MutationDependency,
        payload: GroupDeactivateInput | None = Body(default=None),
    ) -> dict[str, Any]:
        values = (
            {}
            if payload is None
            else {
                _ALIASES.get(name, name): getattr(payload, name)
                for name in payload.model_fields_set
            }
        )
        return service.deactivate(context.principal, group_id, **values).as_payload()

    return router


__all__ = ["create_redundancy_router", "get_redundancy_service"]
