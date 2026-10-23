"""Cookie/CSRF and bearer authenticated document transport."""

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from itsm.attachments.service import AttachmentService, StorageUnavailable
from itsm.identity.api import authenticated_actor, mutation_guard


def service(request: Request):
    with request.app.state.session_factory() as session:
        yield AttachmentService(session, request.app.state.settings)


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
        maximum = request.app.state.settings.attachment_max_bytes
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > maximum:
                raise HTTPException(status_code=422, detail=f"file must contain 1-{maximum} bytes")
            data.extend(chunk)
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
