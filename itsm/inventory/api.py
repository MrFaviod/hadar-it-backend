"""HTTP adapter for inventory: bounded DTOs over the canonical service."""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService
from itsm.inventory.media import MAX_IMAGE_BYTES
from itsm.inventory.service import (
    BATCH_LIMIT,
    DEFAULT_LIMIT,
    FIELD_LIMITS,
    MAX_LIMIT,
    REASON_MAX,
    REASON_MIN,
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
    cost: Decimal | None = None
    technical: dict[str, Any] | None = None


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
    cost: Decimal | None = None
    technical: dict[str, Any] | None = None


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
    cost: str | None
    technical: dict[str, Any] | None
    archived: bool
    archivedAt: str | None
    archivedBy: str | None
    images: dict[str, str]
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


class AssetHistoryPayload(BaseModel):
    """One immutable history entry; old/new values are explicit and bounded."""

    model_config = ConfigDict(extra="forbid")

    id: str
    sequence: int
    assetId: str
    action: str
    quickCodeOld: str | None
    quickCodeNew: str | None
    statusOld: str | None
    statusNew: str | None
    archivedOld: bool | None
    archivedNew: bool | None
    changes: dict[str, Any]
    reason: str | None
    actorId: str | None
    actorUsername: str | None
    createdAt: str


class AssetHistoryPagePayload(BaseModel):
    assetId: str
    items: list[AssetHistoryPayload]
    total: int
    limit: int
    offset: int


class AssetImagePayload(BaseModel):
    """Image metadata; bytes are served only by the image URL."""

    model_config = ConfigDict(extra="forbid")

    role: str
    contentType: str
    size: int
    url: str
    updatedAt: str


class AssetCloneInput(BaseModel):
    """A duplicate gets its own UUID; an explicit quick code stays optional."""

    model_config = ConfigDict(extra="forbid")

    quickCode: str | None = Field(default=None, max_length=FIELD_LIMITS["quick_code"])


class AssetArchiveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=REASON_MAX)


class AssetRetireInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=REASON_MIN, max_length=REASON_MAX)


class AssetPurgeInput(BaseModel):
    """Explicit permanent purge request; the service applies the environment rules."""

    model_config = ConfigDict(extra="forbid")

    confirm: bool = False
    typedId: str | None = Field(default=None, max_length=36)
    reason: str | None = Field(default=None, max_length=REASON_MAX)


class AssetImageRemovedPayload(BaseModel):
    removed: bool
    role: str


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
    archived: bool | None,
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
        archived=archived,
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
        archived: bool | None = None,
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
            archived=archived,
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
        archived: bool | None = None,
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
            archived=archived,
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

    @router.post("/assets/{asset_id}/clone", status_code=201)
    def clone_asset(
        asset_id: str,
        service: InventoryDependency,
        context: MutationDependency,
        payload: AssetCloneInput | None = None,
    ) -> dict[str, Any]:
        changes = None if payload is None else _change_values(payload)
        return asset_payload(service.clone(context.principal, asset_id, changes))

    @router.post("/assets/{asset_id}/archive")
    def archive_asset(
        asset_id: str,
        service: InventoryDependency,
        context: MutationDependency,
        payload: AssetArchiveInput | None = None,
    ) -> dict[str, Any]:
        reason = None if payload is None else payload.reason
        return asset_payload(service.archive(context.principal, asset_id, reason=reason))

    @router.post("/assets/{asset_id}/restore")
    def restore_asset(
        asset_id: str,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return asset_payload(service.restore(context.principal, asset_id))

    @router.post("/assets/{asset_id}/retire")
    def retire_asset(
        asset_id: str,
        payload: AssetRetireInput,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return asset_payload(service.retire(context.principal, asset_id, reason=payload.reason))

    @router.post("/assets/{asset_id}/purge")
    def purge_asset(
        asset_id: str,
        payload: AssetPurgeInput,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        result = service.purge(
            context.principal,
            asset_id,
            confirm=payload.confirm,
            typed_id=payload.typedId,
            reason=payload.reason,
        )
        return result.as_payload()

    @router.get("/assets/{asset_id}/history")
    def read_asset_history(
        asset_id: str,
        service: InventoryDependency,
        context: AuthDependency,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.history(context.principal, asset_id, limit=limit, offset=offset)
        return AssetHistoryPagePayload.model_validate(page.as_payload()).model_dump()

    @router.get("/assets/{asset_id}/images/{role}")
    def read_asset_image(
        asset_id: str,
        role: str,
        service: InventoryDependency,
        context: AuthDependency,
    ) -> Response:
        image = service.image(context.principal, asset_id, role)
        return Response(
            content=image.data,
            media_type=image.content_type,
            headers={
                "Cache-Control": "private, no-store",
                "Content-Length": str(len(image.data)),
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.put("/assets/{asset_id}/images/{role}")
    def upload_asset_image(
        asset_id: str,
        role: str,
        payload: Annotated[bytes, Body(max_length=MAX_IMAGE_BYTES)],
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        image = service.set_image(context.principal, asset_id, role, payload)
        return AssetImagePayload.model_validate(image.as_payload()).model_dump()

    @router.delete("/assets/{asset_id}/images/{role}")
    def delete_asset_image(
        asset_id: str,
        role: str,
        service: InventoryDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        service.remove_image(context.principal, asset_id, role)
        return AssetImageRemovedPayload(removed=True, role=role).model_dump()

    return router


__all__ = [
    "AssetArchiveInput",
    "AssetBatchPayload",
    "AssetBatchRequest",
    "AssetCloneInput",
    "AssetHistoryPagePayload",
    "AssetHistoryPayload",
    "AssetImagePayload",
    "AssetImageRemovedPayload",
    "AssetInput",
    "AssetPagePayload",
    "AssetPayload",
    "AssetPurgeInput",
    "AssetRetireInput",
    "AssetUpdate",
    "asset_payload",
    "create_inventory_router",
    "get_inventory_service",
]
