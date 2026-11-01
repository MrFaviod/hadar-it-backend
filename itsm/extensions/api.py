"""Authenticated HTTP contract for native extension discovery and lifecycle.

The host service owns every authorization and state transition.  This module
only authenticates the caller, enforces cookie CSRF/origin for mutations, and
maps refusals to the application's stable error envelope.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from itsm.extensions.host import (
    ExtensionConflict,
    ExtensionDigestMismatch,
    ExtensionDisabled,
    ExtensionHandlerFailed,
    ExtensionHostError,
    ExtensionHostService,
    ExtensionIdempotencyConflict,
    ExtensionImportFailed,
    ExtensionMigrationFailed,
    ExtensionNotFound,
    ExtensionRequiresUpgrade,
    ExtensionRollbackIncompatible,
    ExtensionSandboxUnavailable,
    ExtensionStale,
    ExtensionStoreConflict,
    ExtensionStoreValidation,
    ExtensionTooLarge,
    ExtensionUnavailable,
    ExtensionValidationFailed,
)
from itsm.extensions.manifest import MAX_ARCHIVE_BYTES
from itsm.identity.api import AuthDependency, MutationDependency, error_body

NO_STORE = {"Cache-Control": "no-store"}
SCRIPT_HEADERS = {
    **NO_STORE,
    "X-Content-Type-Options": "nosniff",
}
CANDIDATE_TYPES = frozenset(
    {"application/zip", "application/octet-stream", "application/x-zip-compressed"}
)


class ApproveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    digest: str
    expectedVersion: int | None = None


class EnabledBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    expectedVersion: int


class RollbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    digest: str
    expectedVersion: int
    restoreData: bool = False
    confirm: str | None = None


class UninstallBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expectedVersion: int


class ReviewBody(BaseModel):
    """D10: publish (``reviewed``) or withdraw (``draft``) a pack's translations."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(min_length=1, max_length=16)
    expectedVersion: int


def get_extension_host(request: Request) -> Iterator[ExtensionHostService]:
    host = getattr(request.app.state, "extensions", None)
    if not isinstance(host, ExtensionHostService):
        raise ExtensionUnavailable("native extensions are not configured")
    yield host


HostDependency = Annotated[ExtensionHostService, Depends(get_extension_host)]


def _failure(exc: ExtensionHostError) -> tuple[int, str, str]:
    if isinstance(exc, ExtensionStale):
        return 409, "stale", str(exc)
    if isinstance(exc, ExtensionDisabled):
        return 409, "extension_disabled", str(exc)
    if isinstance(exc, ExtensionDigestMismatch):
        return 409, "digest_mismatch", str(exc)
    if isinstance(exc, ExtensionRequiresUpgrade):
        return 409, "extension_requires_upgrade", str(exc)
    if isinstance(exc, ExtensionRollbackIncompatible):
        return 409, "rollback_incompatible", str(exc)
    if isinstance(exc, ExtensionIdempotencyConflict):
        return 409, "idempotency_conflict", str(exc)
    if isinstance(exc, ExtensionSandboxUnavailable):
        return 503, "sandbox_unavailable", str(exc)
    if isinstance(exc, ExtensionStoreConflict):
        return 409, "version_conflict", str(exc)
    if isinstance(exc, ExtensionImportFailed):
        return 422, "import_failed", str(exc)
    if isinstance(exc, (ExtensionStoreValidation, ExtensionValidationFailed)):
        return 422, "validation_failed", str(exc)
    if isinstance(exc, ExtensionTooLarge):
        return 413, "package_too_large", str(exc)
    if isinstance(exc, ExtensionNotFound):
        return 404, "not_found", str(exc)
    if isinstance(exc, ExtensionConflict):
        return 409, "conflict", str(exc)
    if isinstance(exc, ExtensionMigrationFailed):
        return 500, "migration_failed", str(exc)
    if isinstance(exc, ExtensionHandlerFailed):
        return 500, "handler_failed", str(exc)
    if isinstance(exc, ExtensionUnavailable):
        return 503, "unavailable", str(exc)
    return 500, "extension_error", "extension operation failed"


def install_extension_error_handlers(app: FastAPI) -> None:
    """Register one handler so every host refusal keeps the error envelope."""

    @app.exception_handler(ExtensionHostError)
    async def _extension_error(_: Request, exc: ExtensionHostError) -> JSONResponse:
        status_code, code, message = _failure(exc)
        body = error_body(code, message)
        if isinstance(exc, ExtensionValidationFailed) and exc.errors:
            body["error"]["errors"] = list(exc.errors)  # type: ignore[assignment]
        return JSONResponse(status_code=status_code, content=body)


def create_extension_router() -> APIRouter:
    router = APIRouter(prefix="/extensions", tags=["extensions"])

    @router.get("")
    def discovery(context: AuthDependency, host: HostDependency) -> dict[str, Any]:
        return host.discovery(context.principal)

    @router.get("/candidates")
    def list_candidates(context: AuthDependency, host: HostDependency) -> dict[str, Any]:
        return host.list_candidates(context.principal)

    @router.get("/candidates/{candidate_id}")
    def candidate_detail(
        candidate_id: str, context: AuthDependency, host: HostDependency
    ) -> dict[str, Any]:
        return host.candidate_detail(context.principal, candidate_id)

    @router.post("/candidates", status_code=201)
    async def upload_candidate(
        request: Request, context: MutationDependency, host: HostDependency
    ) -> dict[str, Any]:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in CANDIDATE_TYPES:
            raise ExtensionValidationFailed("candidate upload must be an application/zip package")
        declared_length = request.headers.get("content-length")
        if declared_length is not None:
            try:
                length = int(declared_length)
            except ValueError:
                raise ExtensionValidationFailed("content-length is invalid") from None
            if length < 0 or length > MAX_ARCHIVE_BYTES:
                raise ExtensionTooLarge("extension package exceeds the archive limit")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_ARCHIVE_BYTES:
                raise ExtensionTooLarge("extension package exceeds the archive limit")
            body.extend(chunk)
        digest = request.headers.get("x-package-digest")
        if digest is not None and (
            len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower())
        ):
            raise ExtensionDigestMismatch("package digest must be SHA-256 hex")
        return host.submit_candidate(
            context.principal, bytes(body), expected_digest=digest.lower() if digest else None
        )

    @router.post("/candidates/{candidate_id}/approve")
    def approve_candidate(
        candidate_id: str,
        body: ApproveBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        return host.approve_candidate(
            context.principal,
            candidate_id,
            digest=body.digest,
            expected_version=body.expectedVersion,
        )

    @router.post("/{extension_id}/enabled")
    def set_enabled(
        extension_id: str,
        body: EnabledBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        return host.set_enabled(
            context.principal,
            extension_id,
            enabled=body.enabled,
            expected_version=body.expectedVersion,
        )

    @router.post("/{extension_id}/rollback")
    def rollback(
        extension_id: str,
        body: RollbackBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        return host.rollback(
            context.principal,
            extension_id,
            version=body.version,
            digest=body.digest,
            expected_version=body.expectedVersion,
            restore_data=body.restoreData,
            confirm=body.confirm,
        )

    @router.post("/{extension_id}/uninstall")
    def uninstall(
        extension_id: str,
        body: UninstallBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        return host.uninstall(
            context.principal, extension_id, expected_version=body.expectedVersion
        )

    @router.post("/{extension_id}/review")
    def review(
        extension_id: str,
        body: ReviewBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        """Deferred review of one installed language pack; drafts stay inactive."""
        return host.review_language_pack(
            context.principal,
            extension_id,
            status=body.status,
            expected_version=body.expectedVersion,
        )

    @router.post("/{extension_id}/events/reset")
    def reset_events(
        extension_id: str,
        body: UninstallBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        """Clear a stalled consumer's retry budget; the cursor is unchanged."""
        return host.reset_events(
            context.principal, extension_id, expected_version=body.expectedVersion
        )

    @router.post("/{extension_id}/reconcile")
    def reconcile(
        extension_id: str,
        body: UninstallBody,
        context: MutationDependency,
        host: HostDependency,
    ) -> dict[str, Any]:
        """Run the idempotent repair path for one installed module."""
        return host.reconcile(
            context.principal, extension_id, expected_version=body.expectedVersion
        )

    @router.get("/contract-gaps")
    def contract_gaps(context: AuthDependency, host: HostDependency) -> dict[str, Any]:
        return host.contract_gaps(context.principal)

    @router.get("/{extension_id}/status")
    def status(extension_id: str, context: AuthDependency, host: HostDependency) -> dict[str, Any]:
        return host.status(context.principal, extension_id)

    @router.get("/{extension_id}/history")
    def history(extension_id: str, context: AuthDependency, host: HostDependency) -> dict[str, Any]:
        return host.history(context.principal, extension_id)

    @router.get("/{extension_id}/skills/{name}")
    def skill(
        extension_id: str, name: str, context: AuthDependency, host: HostDependency
    ) -> dict[str, Any]:
        return host.skill(context.principal, extension_id, name)

    @router.get("/{extension_id}/frontend.js")
    def frontend_script(
        extension_id: str,
        digest: str,
        context: AuthDependency,
        host: HostDependency,
    ) -> Response:
        if not hmac.compare_digest(digest, digest.lower()):
            raise ExtensionDigestMismatch("frontend digest must be lowercase SHA-256 hex")
        payload = host.frontend_script(context.principal, extension_id, digest=digest)
        return Response(
            content=payload,
            media_type="application/javascript; charset=utf-8",
            headers=SCRIPT_HEADERS,
        )

    @router.post("/{extension_id}/invoke/{operation}")
    def invoke(
        extension_id: str,
        operation: str,
        body: dict[str, Any] | None = None,
        *,
        context: MutationDependency,
        host: HostDependency,
    ) -> Any:
        return host.invoke(context.principal, extension_id, operation, body or {})

    return router
