"""Authenticated HTTP adapter for interventions, incidents and resolution."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.interventions.service import (
    AFFECTED_MAX,
    ATTACHMENTS_MAX,
    COST_LIMIT,
    DEFAULT_LIMIT,
    DESCRIPTION_MAX,
    MAX_LIMIT,
    NOTES_MAX,
    PART_NAME_MAX,
    PARTS_MAX,
    QUANTITY_MAX,
    InterventionService,
)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PartInput(Input):
    name: str = Field(min_length=1, max_length=PART_NAME_MAX)
    quantity: int = Field(ge=1, le=QUANTITY_MAX)
    unitCost: Decimal | None = Field(
        default=None, ge=0, le=COST_LIMIT, max_digits=12, decimal_places=2
    )


class InterventionInput(Input):
    assetId: str = Field(min_length=1, max_length=36)
    type: str | None = Field(default=None, max_length=32)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    technicianPersonId: str | None = Field(default=None, max_length=36)
    occurredOn: date | None = None
    status: str | None = Field(default=None, max_length=16)
    notes: str | None = Field(default=None, max_length=NOTES_MAX)
    parts: list[PartInput] | None = Field(default=None, max_length=PARTS_MAX)
    laborCost: Decimal | None = Field(
        default=None, ge=0, le=COST_LIMIT, max_digits=12, decimal_places=2
    )
    attachmentIds: list[str] | None = Field(default=None, max_length=ATTACHMENTS_MAX)
    incidentId: str | None = Field(default=None, max_length=36)
    planId: str | None = Field(default=None, max_length=36)


class InterventionUpdate(Input):
    type: str | None = Field(default=None, max_length=32)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    technicianPersonId: str | None = Field(default=None, max_length=36)
    occurredOn: date | None = None
    status: str | None = Field(default=None, max_length=16)
    notes: str | None = Field(default=None, max_length=NOTES_MAX)
    parts: list[PartInput] | None = Field(default=None, max_length=PARTS_MAX)
    laborCost: Decimal | None = Field(
        default=None, ge=0, le=COST_LIMIT, max_digits=12, decimal_places=2
    )
    attachmentIds: list[str] | None = Field(default=None, max_length=ATTACHMENTS_MAX)


class IncidentInput(Input):
    primaryAssetId: str = Field(min_length=1, max_length=36)
    description: str = Field(min_length=1, max_length=DESCRIPTION_MAX)
    priority: str | None = Field(default=None, max_length=16)
    affectedAssetIds: list[str] | None = Field(default=None, max_length=AFFECTED_MAX)
    responsiblePersonId: str | None = Field(default=None, max_length=36)
    openedOn: date | None = None


class AffectedAssetsInput(Input):
    affectedAssetIds: list[str] = Field(default_factory=list, max_length=AFFECTED_MAX)


class TransitionInput(Input):
    note: str | None = Field(default=None, max_length=NOTES_MAX)


class ResolutionConfirmInput(Input):
    token: str = Field(min_length=1, max_length=200)
    note: str | None = Field(default=None, max_length=NOTES_MAX)


def get_intervention_service(request: Request):
    with request.app.state.session_factory() as session:
        yield InterventionService(session, request.app.state.settings)


Service = Annotated[InterventionService, Depends(get_intervention_service)]
Auth = Annotated[Any, Depends(authenticated_actor)]
Mutation = Annotated[Any, Depends(mutation_guard)]


def _values(payload: BaseModel) -> dict[str, Any]:
    return payload.model_dump(exclude_unset=True)


def create_intervention_router():
    router = APIRouter()

    @router.post("/interventions", status_code=201)
    def create_intervention(
        payload: InterventionInput,
        service: Service,
        context: Mutation,
    ) -> dict[str, Any]:
        return service.create(context.principal, _values(payload)).as_payload()

    @router.get("/interventions")
    def list_interventions(
        service: Service,
        context: Auth,
        category: Annotated[str | None, Query(max_length=120)] = None,
        site: Annotated[str | None, Query(max_length=120)] = None,
        status: Annotated[str | None, Query(max_length=16)] = None,
        asset_id: Annotated[str | None, Query(alias="assetId")] = None,
        technician_person_id: Annotated[str | None, Query(alias="technicianPersonId")] = None,
        incident_id: Annotated[str | None, Query(alias="incidentId")] = None,
        from_date: Annotated[date | None, Query(alias="from")] = None,
        to_date: Annotated[date | None, Query(alias="to")] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return service.list(
            context.principal,
            category=category,
            site=site,
            status=status,
            asset_id=asset_id,
            technician_person_id=technician_person_id,
            incident_id=incident_id,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
            offset=offset,
        ).as_payload()

    @router.get("/interventions/costs")
    def intervention_costs(
        service: Service,
        context: Auth,
        asset_id: Annotated[str | None, Query(alias="assetId")] = None,
        incident_id: Annotated[str | None, Query(alias="incidentId")] = None,
        from_date: Annotated[date | None, Query(alias="from")] = None,
        to_date: Annotated[date | None, Query(alias="to")] = None,
    ) -> dict[str, Any]:
        return service.costs(
            context.principal,
            asset_id=asset_id,
            incident_id=incident_id,
            from_date=from_date,
            to_date=to_date,
        ).as_payload()

    @router.get("/interventions/{intervention_id}")
    def read_intervention(
        intervention_id: str,
        service: Service,
        context: Auth,
    ) -> dict[str, Any]:
        return service.get(context.principal, intervention_id).as_payload()

    @router.patch("/interventions/{intervention_id}")
    def update_intervention(
        intervention_id: str,
        payload: InterventionUpdate,
        service: Service,
        context: Mutation,
    ) -> dict[str, Any]:
        return service.update(context.principal, intervention_id, _values(payload)).as_payload()

    @router.post("/incidents", status_code=201)
    def create_incident(
        payload: IncidentInput,
        service: Service,
        context: Mutation,
    ) -> dict[str, Any]:
        return service.create_incident(context.principal, _values(payload)).as_payload()

    @router.get("/incidents")
    def list_incidents(
        service: Service,
        context: Auth,
        active: Annotated[bool | None, Query()] = None,
        status: Annotated[str | None, Query(max_length=16)] = None,
        priority: Annotated[str | None, Query(max_length=16)] = None,
        category: Annotated[str | None, Query(max_length=120)] = None,
        site: Annotated[str | None, Query(max_length=120)] = None,
        asset_id: Annotated[str | None, Query(alias="assetId")] = None,
        responsible_person_id: Annotated[str | None, Query(alias="responsiblePersonId")] = None,
        from_date: Annotated[date | None, Query(alias="from")] = None,
        to_date: Annotated[date | None, Query(alias="to")] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return service.list_incidents(
            context.principal,
            active=active,
            status=status,
            priority=priority,
            category=category,
            site=site,
            asset_id=asset_id,
            responsible_person_id=responsible_person_id,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
            offset=offset,
        ).as_payload()

    @router.get("/incidents/{incident_id}")
    def read_incident(
        incident_id: str,
        service: Service,
        context: Auth,
    ) -> dict[str, Any]:
        return service.get_incident(context.principal, incident_id).as_payload()

    @router.patch("/incidents/{incident_id}/affected-assets")
    def update_affected_assets(
        incident_id: str,
        payload: AffectedAssetsInput,
        service: Service,
        context: Mutation,
    ) -> dict[str, Any]:
        return service.update_incident_assets(
            context.principal, incident_id, payload.affectedAssetIds
        ).as_payload()

    @router.post("/incidents/{incident_id}/acknowledge")
    def acknowledge_incident(
        incident_id: str,
        service: Service,
        context: Mutation,
        payload: TransitionInput | None = None,
    ) -> dict[str, Any]:
        return service.acknowledge_incident(
            context.principal, incident_id, note=None if payload is None else payload.note
        ).as_payload()

    @router.post("/incidents/{incident_id}/resolve")
    def resolve_incident(
        incident_id: str,
        service: Service,
        context: Mutation,
        payload: TransitionInput | None = None,
    ) -> dict[str, Any]:
        return service.resolve_incident(
            context.principal, incident_id, note=None if payload is None else payload.note
        ).as_payload()

    @router.post("/incidents/{incident_id}/close")
    def close_incident(
        incident_id: str,
        service: Service,
        context: Mutation,
        payload: TransitionInput | None = None,
    ) -> dict[str, Any]:
        return service.close_incident(
            context.principal, incident_id, note=None if payload is None else payload.note
        ).as_payload()

    @router.post("/incidents/{incident_id}/resolution/prepare")
    def prepare_resolution(
        incident_id: str,
        service: Service,
        context: Mutation,
        payload: TransitionInput | None = None,
    ) -> dict[str, Any]:
        return service.prepare_resolution(
            context.principal, incident_id, note=None if payload is None else payload.note
        ).as_payload()

    @router.post("/incidents/{incident_id}/resolution/confirm")
    def confirm_resolution(
        incident_id: str,
        payload: ResolutionConfirmInput,
        service: Service,
        context: Mutation,
    ) -> dict[str, Any]:
        return service.confirm_resolution(
            context.principal, incident_id, payload.token, note=payload.note
        ).as_payload()

    @router.get("/assets/{asset_id}/technical-history")
    def read_technical_history(
        asset_id: str,
        service: Service,
        context: Auth,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return service.asset_technical_history(
            context.principal, asset_id, limit=limit, offset=offset
        ).as_payload()

    return router


__all__ = ["create_intervention_router"]
