"""Authenticated workflow HTTP adapters, sharing the canonical business service."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import ValidationFailed
from itsm.tasks import TaskStorageUnavailable
from itsm.workflows.parsing import MAX_BYTES
from itsm.workflows.service import WorkflowService, export_options
from itsm.workflows.warranties import WarrantyService


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PreviewInput(Input):
    assetIds: list[str] | None = Field(default=None, max_length=5000)
    filters: dict[str, Any] | None = None
    changes: dict[str, Any] = Field(default_factory=dict)
    action: str = Field(default="update", max_length=20)
    reason: str | None = Field(default=None, max_length=500)


class ExportInput(Input):
    assetIds: list[str] | None = Field(default=None, max_length=5000)
    filters: dict[str, Any] | None = None
    fields: list[str] | None = Field(default=None, max_length=100)
    options: dict[str, Any] | None = None


class ResolveInput(Input):
    row: int = Field(ge=0, lt=5000)
    action: str = Field(max_length=20)
    assetId: str | None = Field(default=None, max_length=36)
    values: dict[str, Any] | None = None


class WarrantyInput(Input):
    supplier: str | None = Field(default=None, max_length=160)
    purchaseDate: str | None = Field(default=None, max_length=10)
    durationMonths: int | None = Field(default=None, ge=1, le=1200)
    expiresOn: str | None = Field(default=None, max_length=10)
    status: str = Field(default="active", max_length=20)
    receiptId: str | None = Field(default=None, max_length=36)
    notes: str | None = Field(default=None, max_length=2000)


class PreferenceInput(Input):
    # Strict: booleans and numeric strings must never coerce into a saved day count.
    expiringDays: int = Field(ge=1, le=365, strict=True)


class ProfileInput(Input):
    name: str = Field(min_length=1, max_length=100)
    options: dict[str, Any]


def get_workflow_service(request: Request):
    with request.app.state.session_factory() as session:
        yield WorkflowService(session, request.app.state.settings)


Service = Annotated[WorkflowService, Depends(get_workflow_service)]
Auth = Annotated[Any, Depends(authenticated_actor)]
Mutation = Annotated[Any, Depends(mutation_guard)]


def create_workflow_router():
    router = APIRouter()

    @router.post("/imports/analyze")
    async def analyze(
        request: Request,
        service: Service,
        context: Mutation,
        filename: Annotated[str, Query(max_length=180)],
        options: Annotated[str, Query(max_length=20000)] = "{}",
    ):
        try:
            parsed = json.loads(options)
        except ValueError, TypeError:
            raise ValidationFailed(
                "invalid import options JSON", key="api.workflows.invalid_import_options_json"
            ) from None
        await run_in_threadpool(service._auth, context.principal)
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_BYTES:
                raise ValidationFailed(
                    "import exceeds 10 MiB", key="api.workflows.import_exceeds_10_mib"
                )
            data.extend(chunk)
        return await run_in_threadpool(
            service.analyze, context.principal, bytes(data), filename, parsed
        )

    @router.get("/import-profiles")
    def profiles(service: Service, context: Auth):
        return service.profiles(context.principal)

    @router.post("/import-profiles", status_code=201)
    def save_profile(body: ProfileInput, service: Service, context: Mutation):
        return service.save_profile(context.principal, body.name, body.options)

    @router.put("/import-profiles/{profile_id}")
    def update_profile(profile_id: str, body: ProfileInput, service: Service, context: Mutation):
        return service.save_profile(context.principal, body.name, body.options, profile_id)

    @router.delete("/import-profiles/{profile_id}", status_code=204)
    def delete_profile(profile_id: str, service: Service, context: Mutation):
        service.delete_profile(context.principal, profile_id)
        return Response(status_code=204)

    @router.post("/bulk/preview")
    def preview(body: PreviewInput, service: Service, context: Mutation):
        return service.preview(
            context.principal,
            asset_ids=body.assetIds,
            filters=body.filters,
            changes=body.changes,
            action=body.action,
            reason=body.reason,
        )

    @router.get("/operations/{operation_id}")
    def operation(
        operation_id: str,
        service: Service,
        context: Auth,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=5000)] = 100,
    ):
        return service.get(context.principal, operation_id, offset=offset, limit=limit)

    @router.post("/operations/{operation_id}/resolve")
    def resolve(operation_id: str, body: ResolveInput, service: Service, context: Mutation):
        return service.resolve(
            context.principal, operation_id, body.row, body.action, body.assetId, body.values
        )

    @router.post("/operations/{operation_id}/approve")
    def approve(operation_id: str, service: Service, context: Mutation):
        return service.approve(context.principal, operation_id)

    @router.post("/operations/{operation_id}/enqueue", status_code=202)
    def queue_operation(operation_id: str, request: Request, service: Service, context: Mutation):
        from itsm.identity.hashing import hash_token
        from itsm.workflows.jobs import enqueue

        authorization = request.headers.get("Authorization", "")
        digest = (
            hash_token(authorization[7:]) if authorization.lower().startswith("bearer ") else None
        )
        try:
            return enqueue(
                service,
                context.principal,
                operation_id,
                request.app.state.task_queue,
                credential_digest=digest,
            )
        except TaskStorageUnavailable:
            # Storage failures are reported without queue or filesystem details.
            raise HTTPException(status_code=503, detail="task storage unavailable") from None

    @router.post("/operations/{operation_id}/execute")
    def execute(operation_id: str, service: Service, context: Mutation):
        return service.execute(context.principal, operation_id)

    @router.post("/assets/export")
    def export(body: ExportInput, service: Service, context: Mutation):
        controls = export_options(body.options)
        content = service.export(
            context.principal,
            asset_ids=body.assetIds,
            filters=body.filters,
            fields=body.fields,
            options=body.options,
        )
        return Response(
            content.encode("utf-8-sig" if controls["bom"] else "utf-8"),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="assets.csv"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    def warranties(service):
        return WarrantyService(service._session, service.settings, identity=service.identity)

    @router.get("/assets/{asset_id}/warranty")
    def warranty(asset_id: str, service: Service, context: Auth):
        return warranties(service).get(context.principal, asset_id)

    @router.put("/assets/{asset_id}/warranty")
    def save_warranty(asset_id: str, body: WarrantyInput, service: Service, context: Mutation):
        return warranties(service).put(context.principal, asset_id, body.model_dump())

    @router.delete("/assets/{asset_id}/warranty", status_code=204)
    def delete_warranty(asset_id: str, service: Service, context: Mutation):
        warranties(service).delete(context.principal, asset_id)
        return Response(status_code=204)

    @router.get("/warranties")
    def list_warranties(
        service: Service,
        context: Auth,
        coverage: str | None = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
    ):
        return warranties(service).list(
            context.principal, coverage=coverage, offset=offset, limit=limit
        )

    @router.get("/warranty-preferences")
    def warranty_preferences(service: Service, context: Auth):
        return warranties(service).preferences(context.principal)

    @router.put("/warranty-preferences")
    def save_preferences(body: PreferenceInput, service: Service, context: Mutation):
        return warranties(service).set_preferences(context.principal, body.expiringDays)

    return router
