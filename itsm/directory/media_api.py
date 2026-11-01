"""HTTP adapter for the bounded floor-plan media of directory locations."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from itsm.attachments.service import StorageUnavailable
from itsm.directory.media import (
    MAX_PLAN_BYTES,
    DirectoryMediaService,
    PlanView,
)
from itsm.identity.api import AuthDependency, MutationDependency
from itsm.identity.service import IdentityService, ValidationFailed

_EXTENSIONS = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
}


def get_directory_media_service(request: Request) -> Iterator[DirectoryMediaService]:
    factory = request.app.state.session_factory
    session: Session = factory()
    try:
        yield DirectoryMediaService(
            session,
            request.app.state.settings,
            identity=IdentityService(session, request.app.state.settings),
        )
    finally:
        session.close()


MediaDependency = Annotated[DirectoryMediaService, Depends(get_directory_media_service)]


def _storage_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="plan storage is unavailable",
    )


def create_directory_media_router() -> APIRouter:
    """Canonical plan resource; the parent router only mounts it once."""
    router = APIRouter()

    @router.get("/locations/{location_id}/plan/meta")
    def plan_metadata(
        location_id: str,
        context: AuthDependency,
        service: MediaDependency,
    ) -> dict[str, str | int | None]:
        try:
            return service.meta(context.principal, location_id).as_payload()
        except StorageUnavailable:
            raise _storage_unavailable() from None

    @router.get("/locations/{location_id}/plan")
    def download_plan(
        location_id: str,
        context: AuthDependency,
        service: MediaDependency,
    ) -> Response:
        try:
            image = service.read(context.principal, location_id)
        except StorageUnavailable:
            raise _storage_unavailable() from None
        extension = _EXTENSIONS.get(image.content_type, "bin")
        return Response(
            content=image.data,
            media_type=image.content_type,
            headers={
                "Content-Disposition": f'inline; filename="floor-plan.{extension}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
                "X-Plan-Width": str(image.width),
                "X-Plan-Height": str(image.height),
            },
        )

    @router.put("/locations/{location_id}/plan")
    async def upload_plan(
        location_id: str,
        request: Request,
        context: MutationDependency,
        service: MediaDependency,
    ) -> dict[str, str | int | None]:
        data = bytearray()
        async for chunk in request.stream():
            if not chunk:
                continue
            if len(data) + len(chunk) > MAX_PLAN_BYTES:
                raise ValidationFailed(
                    f"plan image must be at most {MAX_PLAN_BYTES // (1024 * 1024)} MiB",
                    key="api.directory.plan_image_most_maximum_mib",
                    params={"maximum": MAX_PLAN_BYTES // (1024 * 1024)},
                )
            data.extend(chunk)
        try:
            plan: PlanView = service.upload(context.principal, location_id, bytes(data))
        except StorageUnavailable:
            raise _storage_unavailable() from None
        return plan.as_payload()

    @router.delete("/locations/{location_id}/plan", status_code=status.HTTP_204_NO_CONTENT)
    def delete_plan(
        location_id: str,
        context: MutationDependency,
        service: MediaDependency,
    ) -> Response:
        try:
            service.delete(context.principal, location_id)
        except StorageUnavailable:
            raise _storage_unavailable() from None
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router


__all__ = ["create_directory_media_router", "get_directory_media_service"]
