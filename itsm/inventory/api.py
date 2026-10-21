"""HTTP adapter for inventory: bounded DTOs over the canonical service."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService
from itsm.inventory.service import (
    BATCH_LIMIT,
    DEFAULT_LIMIT,
    FIELD_LIMITS,
    MAX_LIMIT,
    AssetView,
    InventoryService,
)

_ASSET_ALIASES = {"quickCode": "quick_code"}


class AssetInput(BaseModel):
    """Explicit create payload: bounded fields only, unknown fields rejected."""

    model_config = ConfigDict(extra="forbid")

    quickCode: str | None = Field(default=None, max_length=FIELD_LIMITS["quick_code"])
    name: str = Field(min_length=1, max_length=FIELD_LIMITS["name"])
    category: str | None = Field(default=None, max_length=FIELD_LIMITS["category"])
    type: str | None = Field(default=None, max_length=FIELD_LIMITS["type"])
    brand: str | None = Field(default=None, max_length=FIELD_LIMITS["brand"])
    model: str | None = Field(default=None, max_length=FIELD_LIMITS["model"])
    serial: str | None = Field(default=None, max_length=FIELD_LIMITS["serial"])
    ip: str | None = Field(default=None, max_length=FIELD_LIMITS["ip"])
    site: str | None = Field(default=None, max_length=FIELD_LIMITS["site"])
    location: str | None = Field(default=None, max_length=FIELD_LIMITS["location"])
    responsible: str | None = Field(default=None, max_length=FIELD_LIMITS["responsible"])
    status: str | None = Field(default=None, max_length=FIELD_LIMITS["status"])
    description: str | None = Field(default=None, max_length=FIELD_LIMITS["description"])


class AssetUpdate(BaseModel):
    """Explicit patch payload; ``None`` clears an optional field."""

    model_config = ConfigDict(extra="forbid")

    quickCode: str | None = Field(default=None, max_length=FIELD_LIMITS["quick_code"])
    name: str | None = Field(default=None, max_length=FIELD_LIMITS["name"])
    category: str | None = Field(default=None, max_length=FIELD_LIMITS["category"])
    type: str | None = Field(default=None, max_length=FIELD_LIMITS["type"])
    brand: str | None = Field(default=None, max_length=FIELD_LIMITS["brand"])
    model: str | None = Field(default=None, max_length=FIELD_LIMITS["model"])
    serial: str | None = Field(default=None, max_length=FIELD_LIMITS["serial"])
    ip: str | None = Field(default=None, max_length=FIELD_LIMITS["ip"])
    site: str | None = Field(default=None, max_length=FIELD_LIMITS["site"])
    location: str | None = Field(default=None, max_length=FIELD_LIMITS["location"])
    responsible: str | None = Field(default=None, max_length=FIELD_LIMITS["responsible"])
    status: str | None = Field(default=None, max_length=FIELD_LIMITS["status"])
    description: str | None = Field(default=None, max_length=FIELD_LIMITS["description"])


class AssetBatchInput(AssetUpdate):
    """Batch updates identify the target by permanent id."""

    id: str = Field(min_length=1, max_length=36)


class AssetBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    create: list[AssetInput] = Field(default_factory=list, max_length=BATCH_LIMIT)
    update: list[AssetBatchInput] = Field(default_factory=list, max_length=BATCH_LIMIT)


class AssetPayload(BaseModel):
    """Stable camelCase projection shared by REST, the agent and MCP."""

    model_config = ConfigDict(extra="forbid")

    id: str
    quickCode: str
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
    createdAt: str
    updatedAt: str


class AssetPagePayload(BaseModel):
    items: list[AssetPayload]
    total: int
    limit: int
    offset: int


class AssetBatchPayload(BaseModel):
    created: list[AssetPayload]
    updated: list[AssetPayload]


def asset_payload(view: AssetView) -> dict[str, Any]:
    """Serialize one service view into the announced public DTO."""
    return view.as_payload()


def _create_values(payload: AssetInput) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name in payload.model_fields_set:
        value = getattr(payload, name)
        values[_ASSET_ALIASES.get(name, name)] = value
    if "name" not in values:
        values["name"] = payload.name
    return values


def _change_values(payload: BaseModel, *, skip: tuple[str, ...] = ()) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for name in payload.model_fields_set:
        if name in skip:
            continue
        changes[_ASSET_ALIASES.get(name, name)] = getattr(payload, name)
    return changes


def get_inventory_service(request: Request) -> Iterator[InventoryService]:
    """One session, one identity service and one inventory service per request."""
    session = request.app.state.session_factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield InventoryService(session, request.app.state.settings, identity=identity)
    finally:
        session.close()


InventoryDependency = Annotated[InventoryService, Depends(get_inventory_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]


def _search(
    service: InventoryService,
    context: AuthContext,
    *,
    query: str | None,
    category: str | None,
    site: str | None,
    status: str | None,
    quick_code: str | None,
    asset_id: str | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    page = service.search(
        context.principal,
        query=query,
        category=category,
        site=site,
        status=status,
        quick_code=quick_code,
        asset_id=asset_id,
        limit=limit,
        offset=offset,
    )
    return AssetPagePayload.model_validate(page.as_payload()).model_dump()


def create_inventory_router() -> APIRouter:
    """Inventory routes; the search route is declared before ``/{asset_id}``."""
    router = APIRouter()

    @router.get("/assets/search")
    def search_assets(
        service: InventoryDependency,
        context: AuthDependency,
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: Annotated[str | None, Query(alias="quickCode")] = None,
        asset_id: Annotated[str | None, Query(alias="id")] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return _search(
            service,
            context,
            query=query,
            category=category,
            site=site,
            status=status,
            quick_code=quick_code,
            asset_id=asset_id,
            limit=limit,
            offset=offset,
        )

    @router.get("/assets")
    def list_assets(
        service: InventoryDependency,
        context: AuthDependency,
        query: str | None = None,
        category: str | None = None,
        site: str | None = None,
        status: str | None = None,
        quick_code: Annotated[str | None, Query(alias="quickCode")] = None,
        asset_id: Annotated[str | None, Query(alias="id")] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return _search(
            service,
            context,
            query=query,
            category=category,
            site=site,
            status=status,
            quick_code=quick_code,
            asset_id=asset_id,
            limit=limit,
            offset=offset,
        )

    @router.post("/assets", status_code=201)
    def create_asset(
        payload: AssetInput,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        created = service.create(context.principal, _create_values(payload))
        return asset_payload(created)

    @router.post("/assets/batch")
    def batch_assets(
        payload: AssetBatchRequest,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        result = service.batch(
            context.principal,
            create=[_create_values(item) for item in payload.create],
            update=[
                {"id": item.id, **_change_values(item, skip=("id",))} for item in payload.update
            ],
        )
        return AssetBatchPayload.model_validate(result.as_payload()).model_dump()

    @router.get("/assets/{asset_id}")
    def read_asset(
        asset_id: str,
        service: InventoryDependency,
        context: AuthDependency,
    ) -> dict[str, Any]:
        return asset_payload(service.get(context.principal, asset_id))

    @router.patch("/assets/{asset_id}")
    def update_asset(
        asset_id: str,
        payload: AssetUpdate,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        updated = service.update(context.principal, asset_id, _change_values(payload))
        return asset_payload(updated)

    return router


__all__ = [
    "AssetBatchPayload",
    "AssetBatchRequest",
    "AssetInput",
    "AssetPagePayload",
    "AssetPayload",
    "AssetUpdate",
    "asset_payload",
    "create_inventory_router",
    "get_inventory_service",
]
