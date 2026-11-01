"""HTTP adapter for preventive maintenance: bounded DTOs over the service."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.i18n.request import resolve_request_locale
from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService
from itsm.maintenance.service import (
    _UNSET,
    DEFAULT_LIMIT_MAINTENANCE,
    MaintenanceService,
)


class TemplateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(min_length=1, max_length=64)
    maintenanceType: str = Field(default="preventivo", min_length=2, max_length=32)
    intervalMonths: int = Field(ge=1, le=120)
    tasks: list[str] | None = Field(default=None, max_length=24)
    responsiblePersonId: str | None = Field(default=None, max_length=36)
    active: bool = True


class TemplatePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervalMonths: int | None = Field(default=None, ge=1, le=120)
    tasks: list[str] | None = Field(default=None, max_length=24)
    responsiblePersonId: str | None = Field(default=None, max_length=36)
    active: bool | None = None


class PlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assetId: str | None = Field(default=None, max_length=36)
    maintenanceType: str = Field(default="preventivo", min_length=2, max_length=32)
    intervalMonths: int | None = Field(default=None, ge=1, le=120)
    tasks: list[str] | None = Field(default=None, max_length=24)
    responsiblePersonId: str | None = Field(default=None, max_length=36)
    dueOn: date | None = None
    lastCompletedOn: date | None = None


class PlanPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervalMonths: int | None = Field(default=None, ge=1, le=120)
    tasks: list[str] | None = Field(default=None, max_length=24)
    responsiblePersonId: str | None = Field(default=None, max_length=36)
    dueOn: date | None = None


class CompleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    completedOn: date | None = None
    notes: str | None = Field(default=None, max_length=500)


class PostponeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dueOn: date
    notes: str | None = Field(default=None, max_length=500)


class CancelInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notes: str | None = Field(default=None, max_length=500)


def get_maintenance_service(request: Request) -> Iterator[MaintenanceService]:
    """One session, one identity service and one maintenance service per request."""
    session = request.app.state.session_factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield MaintenanceService(
            session,
            request.app.state.settings,
            identity=identity,
            source="rest",
            locale=resolve_request_locale(request),
        )
    finally:
        session.close()


MaintenanceDependency = Annotated[MaintenanceService, Depends(get_maintenance_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]


def _provided(payload: BaseModel, name: str) -> Any:
    """Distinguish an omitted field (inherit/leave) from an explicit null (clear)."""
    return getattr(payload, name) if name in payload.model_fields_set else _UNSET


def create_maintenance_router() -> APIRouter:
    """Preventive template and plan routes, mounted under the versioned prefix."""
    router = APIRouter()

    @router.get("/maintenance/templates")
    def list_templates(
        service: MaintenanceDependency,
        context: AuthDependency,
        category: str | None = None,
        limit: int = DEFAULT_LIMIT_MAINTENANCE,
        offset: int = 0,
    ) -> dict[str, Any]:
        return service.list_templates(
            context.principal,
            category=category,
            limit=limit,
            offset=offset,
        ).as_payload()

    @router.post("/maintenance/templates", status_code=201)
    def create_template(
        payload: TemplateInput,
        service: MaintenanceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.create_template(
            context.principal,
            category=payload.category,
            maintenance_type=payload.maintenanceType,
            interval_months=payload.intervalMonths,
            tasks=payload.tasks,
            responsible_person_id=payload.responsiblePersonId,
            active=payload.active,
        ).as_payload()

    @router.patch("/maintenance/templates/{template_id}")
    def update_template(
        template_id: str,
        payload: TemplatePatch,
        service: MaintenanceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.update_template(
            context.principal,
            template_id,
            interval_months=_provided(payload, "intervalMonths"),
            tasks=_provided(payload, "tasks"),
            responsible_person_id=_provided(payload, "responsiblePersonId"),
            active=_provided(payload, "active"),
        ).as_payload()

    @router.delete("/maintenance/templates/{template_id}")
    def delete_template(
        template_id: str,
        service: MaintenanceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.delete_template(context.principal, template_id)

    @router.get("/maintenance/plans")
    def list_plans(
        service: MaintenanceDependency,
        context: AuthDependency,
        state: str | None = None,
        status: str | None = None,
        category: str | None = None,
        site: str | None = None,
        siteId: str | None = None,
        assetId: str | None = None,
        maintenanceType: str | None = None,
        dueFrom: date | None = None,
        dueTo: date | None = None,
        completedFrom: date | None = None,
        completedTo: date | None = None,
        upcomingDays: int = 30,
        archived: bool = False,
        limit: int = DEFAULT_LIMIT_MAINTENANCE,
        offset: int = 0,
    ) -> dict[str, Any]:
        return service.list_plans(
            context.principal,
            state=state,
            status=status,
            category=category,
            site=site,
            site_id=siteId,
            asset_id=assetId,
            maintenance_type=maintenanceType,
            due_from=dueFrom,
            due_to=dueTo,
            completed_from=completedFrom,
            completed_to=completedTo,
            upcoming_days=upcomingDays,
            archived=archived,
            limit=limit,
            offset=offset,
        ).as_payload()

    @router.post("/maintenance/plans", status_code=201)
    def create_plan(
        payload: PlanInput,
        service: MaintenanceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.create_plan(
            context.principal,
            asset_id=_provided(payload, "assetId"),
            maintenance_type=payload.maintenanceType,
            interval_months=_provided(payload, "intervalMonths"),
            tasks=_provided(payload, "tasks"),
            responsible_person_id=_provided(payload, "responsiblePersonId"),
            due_on=payload.dueOn,
            last_completed_on=payload.lastCompletedOn,
        ).as_payload()

    @router.get("/maintenance/plans/{plan_id}")
    def get_plan(
        plan_id: str,
        service: MaintenanceDependency,
        context: AuthDependency,
    ) -> dict[str, Any]:
        return service.get_plan(context.principal, plan_id).as_payload()

    @router.patch("/maintenance/plans/{plan_id}")
    def update_plan(
        plan_id: str,
        payload: PlanPatch,
        service: MaintenanceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.update_plan(
            context.principal,
            plan_id,
            interval_months=_provided(payload, "intervalMonths"),
            tasks=_provided(payload, "tasks"),
            responsible_person_id=_provided(payload, "responsiblePersonId"),
            due_on=_provided(payload, "dueOn"),
        ).as_payload()

    @router.post("/maintenance/plans/{plan_id}/complete")
    def complete_plan(
        plan_id: str,
        service: MaintenanceDependency,
        context: MutationDependency,
        payload: CompleteInput | None = Body(default=None),
    ) -> dict[str, Any]:
        return service.complete_plan(
            context.principal,
            plan_id,
            completed_on=payload.completedOn if payload else None,
            notes=payload.notes if payload else None,
        ).as_payload()

    @router.post("/maintenance/plans/{plan_id}/postpone")
    def postpone_plan(
        plan_id: str,
        payload: PostponeInput,
        service: MaintenanceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.postpone_plan(
            context.principal,
            plan_id,
            due_on=payload.dueOn,
            notes=payload.notes,
        ).as_payload()

    @router.post("/maintenance/plans/{plan_id}/cancel")
    def cancel_plan(
        plan_id: str,
        service: MaintenanceDependency,
        context: MutationDependency,
        payload: CancelInput | None = Body(default=None),
    ) -> dict[str, Any]:
        return service.cancel_plan(
            context.principal,
            plan_id,
            notes=payload.notes if payload else None,
        ).as_payload()

    return router
