"""Cookie/CSRF and bearer authenticated document transport."""

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from itsm.attachments.models import Attachment
from itsm.attachments.service import AttachmentService, StorageUnavailable
from itsm.identity.api import authenticated_actor, mutation_guard


def service(request: Request):
    with request.app.state.session_factory() as session:
        yield AttachmentService(session, request.app.state.settings)


def _demo_error(
    status_code: int, code: str, message: str, retry_after: int | None = None
) -> JSONResponse:
    """The public demo returns stable error codes instead of validation prose."""
    headers = {} if retry_after is None else {"Retry-After": str(retry_after)}
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
        headers=headers,
    )


def _stored_bytes(request: Request) -> int:
    """Bytes currently occupied by live attachments (shared demo storage)."""
    with request.app.state.session_factory() as session:
        total = session.execute(
            select(func.coalesce(func.sum(Attachment.size), 0)).where(
                Attachment.deleted_at.is_(None)
            )
        ).scalar_one()
    return int(total)


def create_attachment_router():
    router = APIRouter()

    def unavailable():
        return HTTPException(status_code=503, detail="attachment storage unavailable")

    @router.get("/assets/{asset_id}/attachments")
    def list_attachments(
        asset_id: str,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        context=Depends(authenticated_actor),
        documents=Depends(service),
    ):
        return documents.list(context.principal, asset_id, limit=limit, offset=offset)

    @router.post("/assets/{asset_id}/attachments", status_code=201)
    async def upload_attachment(
        asset_id: str,
        request: Request,
        filename: str = Query(min_length=1, max_length=180),
        category: str = Query(default="document", max_length=16),
        context=Depends(mutation_guard),
        documents=Depends(service),
    ):
        documents._authorize(context.principal, asset_id, "assets.edit")
        # The public demo tightens the attachment ceiling and keeps one shared
        # storage quota; every other mode keeps the plain production path.
        limits = getattr(request.app.state, "demo_limits", None)
        maximum = request.app.state.settings.attachment_max_bytes
        if limits is not None:
            maximum = min(maximum, limits.attachment_max_bytes)
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > maximum:
                if limits is not None:
                    return _demo_error(413, "payload_too_large", "request body is too large")
                raise HTTPException(status_code=422, detail=f"file must contain 1-{maximum} bytes")
            data.extend(chunk)
        if limits is not None and _stored_bytes(request) + len(data) > limits.quota_bytes:
            return _demo_error(
                413,
                "storage_quota_exceeded",
                "the demonstration storage quota is used up",
                60,
            )
        try:
            return documents.upload(
                context.principal, asset_id, filename=filename, category=category, data=bytes(data)
            )
        except StorageUnavailable:
            raise unavailable() from None

    @router.get("/assets/{asset_id}/attachments/{attachment_id}/download")
    def download_attachment(
        asset_id: str,
        attachment_id: str,
        context=Depends(authenticated_actor),
        documents=Depends(service),
    ):
        try:
            metadata, data = documents.download(context.principal, asset_id, attachment_id)
        except StorageUnavailable:
            raise unavailable() from None
        return Response(
            content=data,
            headers={
                "Content-Type": metadata["contentType"],
                "Content-Disposition": "attachment; filename*=UTF-8''"
                + quote(metadata["filename"], safe=""),
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    @router.delete("/assets/{asset_id}/attachments/{attachment_id}", status_code=204)
    def delete_attachment(
        asset_id: str,
        attachment_id: str,
        context=Depends(mutation_guard),
        documents=Depends(service),
    ):
        try:
            documents.delete(context.principal, asset_id, attachment_id)
        except StorageUnavailable:
            raise unavailable() from None
        return Response(status_code=204)

    return router
