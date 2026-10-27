"""HTTP surface for AI usage quota policies, reports and own summary.

Reserve and settle are intentionally absent: only the server-side gateway may
create or settle usage receipts. These routes never accept an actor identity
from the client.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictInt

from itsm.ai_usage.service import UNSET, AiUsageService
from itsm.identity.api import AuthDependency, MutationDependency

NO_STORE = {"Cache-Control": "no-store"}


def _service(request: Request) -> AiUsageService:
    return request.app.state.agent_usage


ServiceDependency = Annotated[AiUsageService, Depends(_service)]


def _json(payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse(content=payload, headers=NO_STORE)


class PolicyUpdateRequest(BaseModel):
    """Omitted fields are unchanged; explicit null means unlimited."""

    model_config = ConfigDict(extra="forbid")

    companyDailyLimit: StrictInt | None = None
    personalDailyLimit: StrictInt | None = None
    timezone: str | None = None
    cancelTimezoneChange: bool = False


class OverrideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dailyLimit: StrictInt | None
    scope: Literal["company", "personal"] = "company"


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Literal["settled", "released"]
    evidence: dict[str, Any] | None = None
    reason: str | None = None


def create_agent_usage_router() -> APIRouter:
    router = APIRouter(prefix="/agent/usage", tags=["agent-usage"])

    @router.get("/me")
    def me(context: AuthDependency, service: ServiceDependency) -> JSONResponse:
        return _json(service.me(context.principal.actor_id))

    @router.get("/policy")
    def policy(context: AuthDependency, service: ServiceDependency) -> JSONResponse:
        return _json(service.policy(context.principal))

    @router.put("/policy")
    def update_policy(
        payload: PolicyUpdateRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> JSONResponse:
        fields = payload.model_fields_set
        kwargs: dict[str, Any] = {
            "cancel_timezone_change": payload.cancelTimezoneChange,
        }
        if "companyDailyLimit" in fields:
            kwargs["company_daily_limit"] = payload.companyDailyLimit
        if "personalDailyLimit" in fields:
            kwargs["personal_daily_limit"] = payload.personalDailyLimit
        if "timezone" in fields:
            kwargs["timezone"] = payload.timezone if payload.timezone is not None else UNSET
        return _json(service.update_policy(context.principal, **kwargs))

    @router.get("/overrides")
    def overrides(context: AuthDependency, service: ServiceDependency) -> JSONResponse:
        return _json(service.list_overrides(context.principal))

    @router.put("/overrides/{user_id}")
    def set_override(
        user_id: str,
        payload: OverrideRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> JSONResponse:
        return _json(
            service.set_override(
                context.principal,
                user_id,
                daily_limit=payload.dailyLimit,
                scope=payload.scope,
            )
        )

    @router.delete("/overrides/{user_id}")
    def delete_override(
        user_id: str,
        context: MutationDependency,
        service: ServiceDependency,
        scope: Annotated[Literal["company", "personal"], Query()] = "company",
    ) -> JSONResponse:
        return _json(service.delete_override(context.principal, user_id, scope=scope))

    @router.get("/report")
    def report(
        context: AuthDependency,
        service: ServiceDependency,
        userId: str | None = None,
        providerId: str | None = None,
        model: str | None = None,
        engine: str | None = None,
        funding: str | None = None,
        dayFrom: str | None = None,
        dayTo: str | None = None,
        groupBy: str | None = None,
        includeLegacy: bool = True,
    ) -> JSONResponse:
        groups = (
            tuple(part.strip() for part in groupBy.split(",") if part.strip())
            if groupBy is not None
            else None
        )
        return _json(
            service.report(
                context.principal,
                user_id=userId,
                provider_id=providerId,
                model=model,
                engine=engine,
                funding=funding,
                day_from=dayFrom,
                day_to=dayTo,
                group_by=groups,
                include_legacy=includeLegacy,
            )
        )

    @router.get("/pending")
    def pending(
        context: AuthDependency,
        service: ServiceDependency,
        runId: str | None = None,
        userId: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> JSONResponse:
        return _json(
            service.pending_admin(
                context.principal,
                run_id=runId,
                user_id=userId,
                limit=limit,
            )
        )

    @router.post("/reservations/{reservation_id}/resolve")
    def resolve(
        reservation_id: str,
        payload: ResolveRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> JSONResponse:
        result = service.resolve(
            context.principal,
            reservation_id,
            outcome=payload.outcome,
            evidence=payload.evidence,
            reason=payload.reason,
        )
        return _json(result.as_dict())

    return router
