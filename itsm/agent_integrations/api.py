"""HTTP surface for the common agent sessions and the integration administration."""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from itsm.agent_integrations.service import (
    AgentIntegrationService,
    IntegrationUnavailable,
)
from itsm.identity.api import AuthDependency, MutationDependency

EngineName = Literal["opencode", "hermes"]
Operation = Literal["install", "verify", "update", "repair", "disable", "uninstall"]


class PreferencePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instanceId: str = Field(min_length=1, max_length=36)
    model: str | None = Field(default=None, max_length=200)


class InstancePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=120)
    engine: EngineName | None = None
    baseUrl: str | None = Field(default=None, max_length=2048)
    secretRef: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, max_length=200)
    profile: str | None = Field(default=None, max_length=200)
    directory: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None
    defaultModel: str | None = Field(default=None, max_length=200)
    integrationIdentityId: str | None = Field(default=None, max_length=36)
    quotaMode: Literal["managed", "direct"] | None = None
    directCompanyException: bool | None = None
    managedProviderId: str | None = Field(default=None, max_length=36)
    managedContextTokens: int | None = Field(default=None, ge=1, le=100_000_000)


class TargetPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine: EngineName
    path: str = Field(min_length=1, max_length=1024)
    profile: str | None = Field(default=None, max_length=200)
    version: str | None = Field(default=None, max_length=64)
    remote: bool = False


class McpPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)
    secretRef: str = Field(min_length=1, max_length=128)
    identityId: str = Field(min_length=1, max_length=36)


class InstallPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instanceId: str = Field(min_length=1, max_length=36)
    target: TargetPayload
    mcp: McpPayload | None = None
    skills: list[str] | None = Field(default=None, max_length=50)
    operation: Operation = "install"
    mode: Literal["local", "remote"] = "local"


class ReceiptPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installationId: str | None = Field(default=None, max_length=64)
    instanceId: str | None = Field(default=None, max_length=36)
    requestDigest: str | None = Field(default=None, max_length=200)
    receipt: dict[str, Any]


class ModulePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class ContextMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class SessionCreatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instanceId: str = Field(min_length=1, max_length=36)
    model: str = Field(min_length=1, max_length=200)
    context: list[ContextMessage] | None = Field(default=None, max_length=50)
    assetId: str | None = Field(default=None, max_length=36)


class SessionMessagePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=8000)
    assetId: str | None = Field(default=None, max_length=36)


class SessionUpdatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str | None = Field(default=None, min_length=1, max_length=200)
    instanceId: str | None = Field(default=None, min_length=1, max_length=36)

    @model_validator(mode="after")
    def _require_change(self) -> SessionUpdatePayload:
        if self.model is None and self.instanceId is None:
            raise ValueError("model or instanceId is required")
        return self


class ProviderPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["global", "personal"] | None = None
    name: str | None = Field(default=None, max_length=120)
    baseUrl: str | None = Field(default=None, max_length=2048)
    models: list[str] | None = Field(default=None, max_length=50)
    apiKey: SecretStr | None = Field(default=None, max_length=2048)
    enabled: bool | None = None


def _service(request: Request) -> AgentIntegrationService:
    service = getattr(request.app.state, "agent_integrations", None)
    if service is None:
        raise HTTPException(status_code=503, detail="agent integrations are not configured")
    return service


def _sse(events: Any) -> Any:
    async def generate() -> Any:
        async for event in events:
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return generate()


def create_agent_integrations_router() -> APIRouter:
    router = APIRouter()

    # ------------------------------------------------------------- public engines
    @router.get("/agent/engines")
    async def engines(request: Request, context: AuthDependency) -> dict[str, Any]:
        return await _service(request).engines(context.principal)

    @router.put("/agent/preferences")
    async def save_preference(
        payload: PreferencePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).save_preference(context.principal, payload.model_dump())

    @router.get("/agent/sessions")
    def list_sessions(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).list_sessions(context.principal)

    @router.post("/agent/sessions", status_code=201)
    async def create_session(
        payload: SessionCreatePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).create_session(context.principal, payload.model_dump())

    @router.get("/agent/sessions/{session_id}")
    def get_session(session_id: str, request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).get_session(context.principal, session_id)

    @router.patch("/agent/sessions/{session_id}")
    async def update_session(
        session_id: str,
        payload: SessionUpdatePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).update_session(
            context.principal, session_id, payload.model_dump(exclude_unset=True)
        )

    @router.post("/agent/sessions/{session_id}/messages")
    def send_message(
        session_id: str,
        payload: SessionMessagePayload,
        request: Request,
        context: MutationDependency,
    ) -> StreamingResponse:
        service = _service(request)
        turn = service.prepare_turn(context.principal, session_id, payload.message, payload.assetId)
        return StreamingResponse(
            _sse(turn.stream()),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @router.post("/agent/sessions/{session_id}/cancel")
    async def cancel_session(
        session_id: str, request: Request, context: MutationDependency
    ) -> dict[str, Any]:
        return await _service(request).cancel_session(context.principal, session_id)

    # ---------------------------------------------------------------- providers
    @router.get("/agent/providers")
    def list_providers(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).providers(context.principal)

    @router.post("/agent/providers", status_code=201)
    def create_provider(
        payload: ProviderPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).create_provider(
            context.principal, payload.model_dump(exclude_unset=True)
        )

    @router.patch("/agent/providers/{provider_id}")
    def update_provider(
        provider_id: str,
        payload: ProviderPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).update_provider(
            context.principal, provider_id, payload.model_dump(exclude_unset=True)
        )

    @router.delete("/agent/providers/{provider_id}")
    def delete_provider(
        provider_id: str, request: Request, context: MutationDependency
    ) -> dict[str, Any]:
        return _service(request).delete_provider(context.principal, provider_id)

    @router.post("/agent/providers/{provider_id}/check")
    async def check_provider(
        provider_id: str, request: Request, context: MutationDependency
    ) -> dict[str, Any]:
        return await _service(request).check_provider(context.principal, provider_id)

    # -------------------------------------------------------------- admin surface
    @router.get("/agent/integrations")
    def integrations(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).admin_snapshot(context.principal)

    @router.post("/agent/integrations/instances", status_code=201)
    def create_instance(
        payload: InstancePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).create_instance(
            context.principal, payload.model_dump(exclude_unset=True)
        )

    @router.put("/agent/integrations/instances/{instance_id}")
    def update_instance(
        instance_id: str,
        payload: InstancePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).update_instance(
            context.principal, instance_id, payload.model_dump(exclude_unset=True)
        )

    @router.put("/agent/integrations/defaults")
    async def set_defaults(
        payload: PreferencePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).set_defaults(context.principal, payload.model_dump())

    @router.get("/agent/integrations/catalog")
    def catalog(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).catalog_snapshot(context.principal)

    @router.get("/agent/integrations/modules")
    def modules(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).list_modules(context.principal)

    @router.put("/agent/integrations/modules/{module_id}")
    def set_module(
        module_id: str,
        payload: ModulePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).set_module(context.principal, module_id, payload.model_dump())

    @router.post("/agent/integrations/targets")
    async def detect_target(
        payload: TargetPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).detect_target(context.principal, payload.model_dump())

    @router.post("/agent/integrations/install")
    async def install(
        payload: InstallPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).install(
            context.principal, payload.model_dump(exclude_unset=True)
        )

    @router.get("/agent/integrations/installations/{installation_id}/request")
    def installation_request(
        installation_id: str, request: Request, context: AuthDependency
    ) -> dict[str, Any]:
        return _service(request).installation_request(context.principal, installation_id)

    @router.post("/agent/integrations/receipts")
    async def import_receipt(
        payload: ReceiptPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return await _service(request).import_receipt(context.principal, payload.model_dump())

    return router


def install_agent_integration_error_handlers(app: Any) -> None:
    """Map control-plane domain errors onto the shared error envelope."""

    @app.exception_handler(IntegrationUnavailable)
    async def on_unavailable(request: Request, exc: IntegrationUnavailable) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"error": {"code": "unavailable", "message": str(exc)}},
        )


__all__ = [
    "create_agent_integrations_router",
    "install_agent_integration_error_handlers",
]
