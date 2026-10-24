"""HTTP adapter for the canonical :class:`AppearanceService`.

``GET /appearance/active`` and the two graphic routes are deliberately public:
the login screen needs the installation identity before a session exists. All
mutations use the existing Origin/CSRF guard and ``config.general`` Casbin
capability inside the service; no caller-asserted authority is trusted.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from itsm.appearance.package import MAX_ZIP_BYTES
from itsm.appearance.schemas import ImportRequest, PresetPayload
from itsm.appearance.service import AppearanceService, AppearanceStorageUnavailable
from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import ValidationFailed

AUTH_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}
GRAPHIC_HEADERS = {
    "Cache-Control": "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "Cross-Origin-Resource-Policy": "same-origin",
}
ZIP_TYPES = frozenset({"application/zip", "application/x-zip-compressed"})


def get_appearance_service(request: Request) -> AppearanceService:
    service = getattr(request.app.state, "appearance_service", None)
    if service is None:  # pragma: no cover - wired by the application lifespan
        raise RuntimeError("appearance service is not configured")
    return service


Service = Annotated[AppearanceService, Depends(get_appearance_service)]
Auth = Annotated[Any, Depends(authenticated_actor)]
Mutation = Annotated[Any, Depends(mutation_guard)]


def _storage_down() -> HTTPException:
    return HTTPException(status_code=503, detail="appearance storage is unavailable")


def create_appearance_router() -> APIRouter:
    router = APIRouter()

    @router.get("/appearance/active")
    def active(service: Service, response: Response):
        response.headers.update(AUTH_HEADERS)
        return service.active()

    @router.get("/appearance/presets")
    def presets(service: Service, context: Auth, response: Response):
        response.headers.update(AUTH_HEADERS)
        return service.presets(context.principal)

    @router.post("/appearance/presets", status_code=201)
    def create_preset(body: PresetPayload, service: Service, context: Mutation, response: Response):
        response.headers.update(AUTH_HEADERS)
        try:
            return service.create_preset(context.principal, body.model_dump())
        except AppearanceStorageUnavailable:
            raise _storage_down() from None

    @router.put("/appearance/presets/{preset_id}")
    def update_preset(
        preset_id: str,
        body: PresetPayload,
        service: Service,
        context: Mutation,
        response: Response,
    ):
        response.headers.update(AUTH_HEADERS)
        try:
            return service.update_preset(context.principal, preset_id, body.model_dump())
        except AppearanceStorageUnavailable:
            raise _storage_down() from None

    @router.delete("/appearance/presets/{preset_id}", status_code=204)
    def delete_preset(preset_id: str, service: Service, context: Mutation):
        service.delete_preset(context.principal, preset_id)
        return Response(status_code=204)

    @router.post("/appearance/apply/{preset_id}")
    def apply_preset(preset_id: str, service: Service, context: Mutation, response: Response):
        response.headers.update(AUTH_HEADERS)
        return service.apply_preset(context.principal, preset_id)

    @router.post("/appearance/restore")
    def restore(service: Service, context: Mutation, response: Response):
        response.headers.update(AUTH_HEADERS)
        return service.restore(context.principal)

    @router.post("/appearance/revert")
    def revert(service: Service, context: Mutation, response: Response):
        response.headers.update(AUTH_HEADERS)
        return service.revert(context.principal)

    @router.get("/appearance/presets/{preset_id}/export")
    def export_preset(preset_id: str, service: Service, context: Auth):
        try:
            filename, payload = service.export_preset(context.principal, preset_id)
        except AppearanceStorageUnavailable:
            raise _storage_down() from None
        return Response(
            content=payload,
            media_type="application/zip",
            headers={
                **AUTH_HEADERS,
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    @router.post("/appearance/import/preview")
    async def preview_import(request: Request, service: Service, context: Auth):
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in ZIP_TYPES | {"", "application/octet-stream"}:
            raise ValidationFailed("preview requires an application/zip body")
        length = request.headers.get("content-length")
        if length is not None:
            try:
                declared = int(length)
            except ValueError:
                raise ValidationFailed("content-length is invalid") from None
            if declared > MAX_ZIP_BYTES:
                raise ValidationFailed("ZIP must contain at most 24 MiB")
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_ZIP_BYTES:
                raise ValidationFailed("ZIP must contain at most 24 MiB")
            chunks.append(chunk)
        try:
            return service.preview_import(context.principal, b"".join(chunks))
        except AppearanceStorageUnavailable:
            raise _storage_down() from None

    @router.post("/appearance/import", status_code=201)
    def import_preset(body: ImportRequest, service: Service, context: Mutation, response: Response):
        response.headers.update(AUTH_HEADERS)
        try:
            return service.import_preset(context.principal, body.model_dump())
        except AppearanceStorageUnavailable:
            raise _storage_down() from None

    @router.get("/appearance/resources/{resource_id}")
    def resource(resource_id: str, service: Service):
        try:
            content_type, data = service.resource(resource_id)
        except AppearanceStorageUnavailable:
            raise _storage_down() from None
        return Response(content=data, media_type=content_type, headers=GRAPHIC_HEADERS)

    @router.get("/appearance/assets/{key}")
    def builtin_asset(key: str, service: Service):
        content_type, data = service.builtin_asset(key)
        return Response(content=data, media_type=content_type, headers=GRAPHIC_HEADERS)

    return router
