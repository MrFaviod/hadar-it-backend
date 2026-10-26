"""HTTP API for installation-owned system operations; camelCase public DTOs."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import AuthDependency, MutationDependency
from itsm.system.providers import MODEL_PATTERN
from itsm.system.service import SystemService


class DeploymentPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: Literal["development", "test", "production"] | None = None
    maintenanceWindow: Literal["anytime", "outside_business_hours"] | None = None


class ConfigurationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deployment: DeploymentPayload


class ProviderPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["openai", "anthropic"]
    model: str = Field(min_length=1, max_length=120, pattern=MODEL_PATTERN)


class ModulePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class OperationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["deployment.status", "update.prepare", "backup.create"]


def _service(request: Request) -> SystemService:
    service = getattr(request.app.state, "system", None)
    if service is None:  # pragma: no cover - the application always installs it
        raise RuntimeError("system service is not available")
    return service


def create_system_router() -> APIRouter:
    router = APIRouter(prefix="/system", tags=["system"])

    @router.get("/status")
    def status(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).status(context.principal)

    @router.get("/configuration")
    def configuration(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).configuration(context.principal)

    @router.patch("/configuration")
    def update_configuration(
        payload: ConfigurationPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).update_configuration(
            context.principal, payload.model_dump(exclude_none=True)
        )

    @router.get("/providers")
    def providers(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).providers(context.principal)

    @router.put("/providers")
    def set_provider(
        payload: ProviderPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).set_provider(context.principal, payload.model_dump())

    @router.get("/modules")
    def modules(request: Request, context: AuthDependency) -> dict[str, Any]:
        return _service(request).modules(context.principal)

    @router.patch("/modules/{module_id}")
    def set_module(
        module_id: str,
        payload: ModulePayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).set_module(context.principal, module_id, payload.model_dump())

    @router.post("/operations")
    def run_operation(
        payload: OperationPayload,
        request: Request,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return _service(request).operation(context.principal, payload.action)

    return router


__all__ = ["create_system_router"]
