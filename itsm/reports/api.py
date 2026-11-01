"""Report HTTP adapters over the canonical :class:`ReportService`.

The only anonymous route is ``GET /reports/public/{token}``: the public link
carries an independent capability, never a session, UUID or browser flag. Everything else
uses the existing identity dependencies and Origin/CSRF guards.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.hashing import hash_token
from itsm.identity.service import ValidationFailed
from itsm.reports.schemas import ReportRequest, ReportSettingsInput, TemplateDefinition
from itsm.reports.service import ReportService

PDF_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
}


class ShareInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fields: list[str] = Field(min_length=1, max_length=7)
    expiresInDays: StrictInt = Field(default=30, ge=1, le=365)


def get_report_service(request: Request) -> ReportService:
    service = getattr(request.app.state, "reports_service", None)
    if service is None:  # pragma: no cover - wired by the application lifespan
        raise RuntimeError("reports service is not configured")
    return service


Service = Annotated[ReportService, Depends(get_report_service)]
Auth = Annotated[Any, Depends(authenticated_actor)]
Mutation = Annotated[Any, Depends(mutation_guard)]


def _bearer_digest(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return hash_token(token.strip())


def create_reports_router() -> APIRouter:
    router = APIRouter()

    # ------------------------------------------------------------- templates
    @router.get("/reports/templates")
    def templates(service: Service, context: Auth):
        return service.templates(context.principal)

    @router.put("/reports/templates/{template_id}")
    def save_template(
        template_id: str,
        body: TemplateDefinition,
        service: Service,
        context: Mutation,
    ):
        payload = body.model_dump()
        if payload["id"] != template_id:
            raise ValidationFailed(
                "template id must match the URL", key="api.reports.template_id_url_mismatch"
            )
        return service.save_template(context.principal, payload)

    @router.delete("/reports/templates/{template_id}")
    def delete_template(template_id: str, service: Service, context: Mutation):
        service.delete_template(context.principal, template_id)
        return {"id": template_id, "deleted": True}

    # -------------------------------------------------------------- settings
    @router.get("/reports/settings")
    def read_settings(service: Service, context: Auth):
        return service.get_settings(context.principal)

    @router.put("/reports/settings")
    def save_settings(body: ReportSettingsInput, service: Service, context: Mutation):
        return service.save_settings(context.principal, body.model_dump())

    # --------------------------------------------------------------- preview
    @router.post("/reports/preview")
    def preview(body: ReportRequest, service: Service, context: Mutation):
        return service.preview(context.principal, body)

    # ------------------------------------------------------------------ jobs
    @router.post("/reports/jobs", status_code=202)
    def create_job(
        body: ReportRequest,
        request: Request,
        service: Service,
        context: Mutation,
    ):
        return service.generate(context.principal, body, credential_digest=_bearer_digest(request))

    @router.get("/reports/jobs")
    def list_jobs(
        service: Service,
        context: Auth,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ):
        return service.jobs(context.principal, limit=limit)

    @router.get("/reports/jobs/{job_id}")
    def read_job(job_id: str, service: Service, context: Auth):
        return service.job(context.principal, job_id)

    @router.get("/reports/documents/{document_id}/download")
    def download_document(document_id: str, service: Service, context: Auth):
        document, data = service.download(context.principal, document_id)
        filename = document["name"].replace('"', "").replace("\r", "").replace("\n", "")
        return Response(
            content=data,
            media_type=document["mime"],
            headers={
                **PDF_HEADERS,
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    # ------------------------------------------------- private report page
    @router.get("/reports/assets/{asset_id}")
    def read_asset_report(asset_id: str, service: Service, context: Auth):
        return service.asset_report(context.principal, asset_id)

    @router.get("/reports/assets/{asset_id}/qr")
    def read_asset_qr(asset_id: str, service: Service, context: Auth, response: Response):
        response.headers["Cache-Control"] = "no-store"
        return service.qr(context.principal, asset_id)

    # --------------------------------------------------------------- sharing
    @router.post("/reports/assets/{asset_id}/shares", status_code=201)
    def create_share(
        asset_id: str,
        body: ShareInput,
        service: Service,
        context: Mutation,
        response: Response,
    ):
        response.headers["Cache-Control"] = "no-store"
        return service.create_share(
            context.principal,
            asset_id,
            body.fields,
            expires_in_days=body.expiresInDays,
        )

    @router.delete("/reports/shares/{share_id}")
    def revoke_share(share_id: str, service: Service, context: Mutation):
        return service.revoke_share(context.principal, share_id)

    # Sole anonymous route: the token is the capability.
    @router.get("/reports/public/{token}")
    def public_report(token: str, service: Service, response: Response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return service.public_report(token)

    return router
