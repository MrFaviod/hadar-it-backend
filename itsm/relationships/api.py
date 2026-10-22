"""HTTP adapter for relationships: bounded DTOs over the canonical service."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService
from itsm.relationships.service import (
    DEFAULT_GRAPH_DEPTH,
    DEFAULT_LIMIT,
    RelationshipService,
)


class RelationshipTypeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=2, max_length=32)
    forwardLabel: str = Field(min_length=1, max_length=80)
    inverseLabel: str = Field(min_length=1, max_length=80)
    containment: bool = False


class RelationshipTypePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    forwardLabel: str | None = Field(default=None, min_length=1, max_length=80)
    inverseLabel: str | None = Field(default=None, min_length=1, max_length=80)
    containment: bool | None = None
    active: bool | None = None


class RelationshipInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sourceId: str = Field(min_length=1, max_length=36)
    targetId: str = Field(min_length=1, max_length=36)
    typeKey: str = Field(min_length=2, max_length=32)
    reason: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


class RelationshipPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    typeKey: str | None = Field(default=None, min_length=2, max_length=32)
    reason: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


class RelationshipRemoveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


class HostMoveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    childId: str = Field(min_length=1, max_length=36)
    newHostId: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=4, max_length=500)
    notes: str | None = Field(default=None, max_length=500)
    effectiveAt: datetime | None = None


def get_relationship_service(request: Request) -> Iterator[RelationshipService]:
    """One session, one identity service and one relationship service per request."""
    session = request.app.state.session_factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield RelationshipService(
            session,
            request.app.state.settings,
            identity=identity,
            source="rest",
        )
    finally:
        session.close()


RelationshipDependency = Annotated[RelationshipService, Depends(get_relationship_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]

_TYPE_ALIASES = {
    "forwardLabel": "forward_label",
    "inverseLabel": "inverse_label",
}
_RELATION_ALIASES = {"typeKey": "type_key", "effectiveAt": "effective_at"}


def _changes(payload: BaseModel, aliases: dict[str, str]) -> dict[str, Any]:
    return {aliases.get(name, name): getattr(payload, name) for name in payload.model_fields_set}


def create_relationship_router() -> APIRouter:
    """Relationship and graph routes, mounted under the versioned API prefix."""
    router = APIRouter()

    @router.get("/relationship-types")
    def list_relationship_types(
        service: RelationshipDependency,
        context: AuthDependency,
        includeInactive: bool = False,
    ) -> list[dict[str, Any]]:
        return [
            view.as_payload()
            for view in service.list_types(context.principal, include_inactive=includeInactive)
        ]

    @router.post("/relationship-types", status_code=201)
    def create_relationship_type(
        payload: RelationshipTypeInput,
        service: RelationshipDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.create_type(
            context.principal,
            payload.key,
            forward_label=payload.forwardLabel,
            inverse_label=payload.inverseLabel,
            containment=payload.containment,
        ).as_payload()

    @router.patch("/relationship-types/{key}")
    def update_relationship_type(
        key: str,
        payload: RelationshipTypePatch,
        service: RelationshipDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.update_type(
            context.principal, key, **_changes(payload, _TYPE_ALIASES)
        ).as_payload()

    @router.get("/relationships")
    def list_relationships(
        service: RelationshipDependency,
        context: AuthDependency,
        assetId: str | None = None,
        assetIds: Annotated[list[str] | None, Query()] = None,
        typeKey: str | None = None,
        direction: str = "both",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        page = service.list(
            context.principal,
            asset_id=assetId,
            asset_ids=assetIds or (),
            type_key=typeKey,
            direction=direction,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    @router.post("/relationships", status_code=201)
    def create_relationship(
        payload: RelationshipInput,
        service: RelationshipDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.create(
            context.principal,
            source_id=payload.sourceId,
            target_id=payload.targetId,
            type_key=payload.typeKey,
            reason=payload.reason,
            notes=payload.notes,
            effective_at=payload.effectiveAt,
        ).as_payload()

    @router.post("/relationships/host-move")
    def move_relationship_host(
        payload: HostMoveInput,
        service: RelationshipDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.move_host(
            context.principal,
            payload.childId,
            payload.newHostId,
            reason=payload.reason,
            notes=payload.notes,
            effective_at=payload.effectiveAt,
        ).as_payload()

    @router.patch("/relationships/{relationship_id}")
    def update_relationship(
        relationship_id: str,
        payload: RelationshipPatch,
        service: RelationshipDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.update(
            context.principal,
            relationship_id,
            **_changes(payload, _RELATION_ALIASES),
        ).as_payload()

    @router.delete("/relationships/{relationship_id}")
    def remove_relationship(
        relationship_id: str,
        service: RelationshipDependency,
        context: MutationDependency,
        payload: RelationshipRemoveInput | None = Body(default=None),
    ) -> dict[str, Any]:
        values = {} if payload is None else _changes(payload, _RELATION_ALIASES)
        return service.remove(context.principal, relationship_id, **values).as_payload()

    @router.get("/infrastructure/graph")
    def read_infrastructure_graph(
        service: RelationshipDependency,
        context: AuthDependency,
        rootId: str | None = None,
        assetIds: Annotated[list[str] | None, Query()] = None,
        depth: int = DEFAULT_GRAPH_DEPTH,
        direction: str = "both",
        typeKey: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        return service.graph(
            context.principal,
            root_id=rootId,
            asset_ids=assetIds or (),
            depth=depth,
            direction=direction,
            type_key=typeKey,
            limit=limit,
            offset=offset,
        ).as_payload()

    return router


__all__ = [
    "create_relationship_router",
    "get_relationship_service",
]
