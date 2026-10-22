"""HTTP adapter for the directory: bounded DTOs over the canonical service.

No rule lives here: the router translates camelCase payloads into service
arguments, fixes the trusted audit ``source`` to ``rest`` and relies on the
existing origin/CSRF mutation guard. Responses are the service's explicit
payloads, so REST, the agent and MCP keep one contract.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.directory.service import (
    CONTACT_EMAIL_MAX,
    CONTACT_PHONE_MAX,
    DEFAULT_LIMIT,
    DEFAULT_TREE_DEPTH,
    DEFAULT_TREE_NODES,
    DEPARTMENT_NAME_MAX,
    LOCATION_DESCRIPTION_MAX,
    LOCATION_NAME_MAX,
    MAX_LIMIT,
    MAX_TREE_DEPTH,
    MAX_TREE_NODES,
    NOTES_MAX,
    PERSON_JOB_TITLE_MAX,
    PERSON_NAME_MAX,
    PLAN_PAGE_MAX,
    PLAN_REF_MAX,
    REASON_MAX,
    DirectoryService,
)
from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService

REST_SOURCE = "rest"

_AUDIT_FIELDS = ("effectiveAt", "reason", "notes")


class _Patch(BaseModel):
    """Shared patch behavior: explicit fields only, unknown fields rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DepartmentInput(_Patch):
    name: str = Field(min_length=1, max_length=DEPARTMENT_NAME_MAX)
    effectiveAt: datetime | None = None
    notes: str | None = Field(default=None, max_length=NOTES_MAX)


class DepartmentUpdate(_Patch):
    name: str | None = Field(default=None, min_length=1, max_length=DEPARTMENT_NAME_MAX)
    active: bool | None = None
    effectiveAt: datetime | None = None
    reason: str | None = Field(default=None, max_length=REASON_MAX)
    notes: str | None = Field(default=None, max_length=NOTES_MAX)


class PersonInput(_Patch):
    name: str = Field(min_length=1, max_length=PERSON_NAME_MAX)
    jobTitle: str | None = Field(default=None, max_length=PERSON_JOB_TITLE_MAX)
    departmentId: str | None = Field(default=None, max_length=36)
    siteId: str | None = Field(default=None, max_length=36)
    contactEmail: str | None = Field(default=None, max_length=CONTACT_EMAIL_MAX)
    contactPhone: str | None = Field(default=None, max_length=CONTACT_PHONE_MAX)
    status: str | None = Field(default=None, max_length=16)
    effectiveAt: datetime | None = None
    notes: str | None = Field(default=None, max_length=NOTES_MAX)


class PersonUpdate(_Patch):
    name: str | None = Field(default=None, min_length=1, max_length=PERSON_NAME_MAX)
    jobTitle: str | None = Field(default=None, max_length=PERSON_JOB_TITLE_MAX)
    departmentId: str | None = Field(default=None, max_length=36)
    siteId: str | None = Field(default=None, max_length=36)
    contactEmail: str | None = Field(default=None, max_length=CONTACT_EMAIL_MAX)
    contactPhone: str | None = Field(default=None, max_length=CONTACT_PHONE_MAX)
    status: str | None = Field(default=None, max_length=16)
    effectiveAt: datetime | None = None
    reason: str | None = Field(default=None, max_length=REASON_MAX)
    notes: str | None = Field(default=None, max_length=NOTES_MAX)


class LocationInput(_Patch):
    level: str = Field(min_length=1, max_length=16)
    parentId: str | None = Field(default=None, max_length=36)
    name: str = Field(min_length=1, max_length=LOCATION_NAME_MAX)
    description: str | None = Field(default=None, max_length=LOCATION_DESCRIPTION_MAX)
    latitude: float | None = None
    longitude: float | None = None
    planRef: str | None = Field(default=None, max_length=PLAN_REF_MAX)
    planPage: str | None = Field(default=None, max_length=PLAN_PAGE_MAX)
    effectiveAt: datetime | None = None
    notes: str | None = Field(default=None, max_length=NOTES_MAX)


class LocationUpdate(_Patch):
    parentId: str | None = Field(default=None, max_length=36)
    name: str | None = Field(default=None, min_length=1, max_length=LOCATION_NAME_MAX)
    description: str | None = Field(default=None, max_length=LOCATION_DESCRIPTION_MAX)
    latitude: float | None = None
    longitude: float | None = None
    planRef: str | None = Field(default=None, max_length=PLAN_REF_MAX)
    planPage: str | None = Field(default=None, max_length=PLAN_PAGE_MAX)
    active: bool | None = None
    effectiveAt: datetime | None = None
    reason: str | None = Field(default=None, max_length=REASON_MAX)
    notes: str | None = Field(default=None, max_length=NOTES_MAX)


def get_directory_service(request: Request) -> Iterator[DirectoryService]:
    """One session and one service per request; the identity seam is shared."""
    session = request.app.state.session_factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield DirectoryService(session, request.app.state.settings, identity=identity)
    finally:
        session.close()


ServiceDependency = Annotated[DirectoryService, Depends(get_directory_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]

_CAMEL_TO_FIELD = {
    "jobTitle": "job_title",
    "departmentId": "department_id",
    "siteId": "site_id",
    "contactEmail": "contact_email",
    "contactPhone": "contact_phone",
    "parentId": "parent_id",
    "planRef": "plan_ref",
    "planPage": "plan_page",
}


def _values(payload: BaseModel) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split one payload into entity fields and the separate audit metadata."""
    fields: dict[str, Any] = {}
    audit: dict[str, Any] = {}
    for name in payload.model_fields_set:
        value = getattr(payload, name)
        if name in _AUDIT_FIELDS:
            audit[name] = value
        else:
            fields[_CAMEL_TO_FIELD.get(name, name)] = value
    return fields, audit


def _audit_kwargs(audit: dict[str, Any]) -> dict[str, Any]:
    return {
        "effective_at": audit.get("effectiveAt"),
        "reason": audit.get("reason"),
        "notes": audit.get("notes"),
    }


def create_directory_router() -> APIRouter:
    """Directory routes; ``/locations/tree`` is declared before ``/{location_id}``."""
    router = APIRouter()

    # ------------------------------------------------------------ departments
    @router.get("/departments")
    def list_departments(
        service: ServiceDependency,
        context: AuthDependency,
        query: str | None = None,
        active: bool | None = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.list_departments(
            context.principal,
            query=query,
            active=active,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    @router.post("/departments", status_code=201)
    def create_department(
        payload: DepartmentInput,
        service: ServiceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        fields, audit = _values(payload)
        created = service.create_department(
            context.principal,
            fields,
            source=REST_SOURCE,
            effective_at=audit.get("effectiveAt"),
            notes=audit.get("notes"),
        )
        return created.as_payload()

    @router.get("/departments/{department_id}")
    def read_department(
        department_id: str,
        service: ServiceDependency,
        context: AuthDependency,
    ) -> dict[str, Any]:
        return service.get_department(context.principal, department_id).as_payload()

    @router.patch("/departments/{department_id}")
    def update_department(
        department_id: str,
        payload: DepartmentUpdate,
        service: ServiceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        fields, audit = _values(payload)
        updated = service.update_department(
            context.principal,
            department_id,
            fields,
            source=REST_SOURCE,
            **_audit_kwargs(audit),
        )
        return updated.as_payload()

    @router.get("/departments/{department_id}/history")
    def read_department_history(
        department_id: str,
        service: ServiceDependency,
        context: AuthDependency,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.history(
            context.principal,
            entity="department",
            entity_id=department_id,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    # ----------------------------------------------------------------- people
    @router.get("/people")
    def list_people(
        service: ServiceDependency,
        context: AuthDependency,
        query: str | None = None,
        status: Annotated[str | None, Query(max_length=16)] = None,
        department_id: Annotated[str | None, Query(alias="departmentId")] = None,
        site_id: Annotated[str | None, Query(alias="siteId")] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.list_people(
            context.principal,
            query=query,
            status=status,
            department_id=department_id,
            site_id=site_id,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    @router.post("/people", status_code=201)
    def create_person(
        payload: PersonInput,
        service: ServiceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        fields, audit = _values(payload)
        created = service.create_person(
            context.principal,
            fields,
            source=REST_SOURCE,
            effective_at=audit.get("effectiveAt"),
            notes=audit.get("notes"),
        )
        return created.as_payload()

    @router.get("/people/{person_id}")
    def read_person(
        person_id: str,
        service: ServiceDependency,
        context: AuthDependency,
    ) -> dict[str, Any]:
        return service.get_person(context.principal, person_id).as_payload()

    @router.patch("/people/{person_id}")
    def update_person(
        person_id: str,
        payload: PersonUpdate,
        service: ServiceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        fields, audit = _values(payload)
        updated = service.update_person(
            context.principal,
            person_id,
            fields,
            source=REST_SOURCE,
            **_audit_kwargs(audit),
        )
        return updated.as_payload()

    @router.get("/people/{person_id}/history")
    def read_person_history(
        person_id: str,
        service: ServiceDependency,
        context: AuthDependency,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.history(
            context.principal,
            entity="person",
            entity_id=person_id,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    # -------------------------------------------------------------- locations
    @router.get("/locations")
    def list_locations(
        service: ServiceDependency,
        context: AuthDependency,
        query: str | None = None,
        level: str | None = None,
        parent_id: Annotated[str | None, Query(alias="parentId")] = None,
        active: bool | None = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.list_locations(
            context.principal,
            query=query,
            level=level,
            parent_id=parent_id,
            active=active,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    @router.post("/locations", status_code=201)
    def create_location(
        payload: LocationInput,
        service: ServiceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        fields, audit = _values(payload)
        created = service.create_location(
            context.principal,
            fields,
            source=REST_SOURCE,
            effective_at=audit.get("effectiveAt"),
            notes=audit.get("notes"),
        )
        return created.as_payload()

    @router.get("/locations/tree")
    def read_location_tree(
        service: ServiceDependency,
        context: AuthDependency,
        root_id: Annotated[str | None, Query(alias="rootId")] = None,
        depth: Annotated[int, Query(ge=1, le=MAX_TREE_DEPTH)] = DEFAULT_TREE_DEPTH,
        max_nodes: Annotated[int, Query(alias="maxNodes", ge=1, le=MAX_TREE_NODES)] = (
            DEFAULT_TREE_NODES
        ),
    ) -> dict[str, Any]:
        tree = service.location_tree(
            context.principal,
            root_id=root_id,
            depth=depth,
            max_nodes=max_nodes,
        )
        return tree.as_payload()

    @router.get("/locations/{location_id}")
    def read_location(
        location_id: str,
        service: ServiceDependency,
        context: AuthDependency,
    ) -> dict[str, Any]:
        return service.get_location(context.principal, location_id).as_payload()

    @router.patch("/locations/{location_id}")
    def update_location(
        location_id: str,
        payload: LocationUpdate,
        service: ServiceDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        fields, audit = _values(payload)
        updated = service.update_location(
            context.principal,
            location_id,
            fields,
            source=REST_SOURCE,
            **_audit_kwargs(audit),
        )
        return updated.as_payload()

    @router.get("/locations/{location_id}/history")
    def read_location_history(
        location_id: str,
        service: ServiceDependency,
        context: AuthDependency,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        page = service.history(
            context.principal,
            entity="location",
            entity_id=location_id,
            limit=limit,
            offset=offset,
        )
        return page.as_payload()

    return router


__all__ = [
    "DepartmentInput",
    "DepartmentUpdate",
    "LocationInput",
    "LocationUpdate",
    "PersonInput",
    "PersonUpdate",
    "create_directory_router",
    "get_directory_service",
]
