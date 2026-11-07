"""Authorized HTTP surface for the dashboard and durable workspace state."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query, Request

from itsm.dashboard.service import DashboardService
from itsm.identity.api import AuthDependency, MutationDependency
from itsm.identity.service import IdentityService
from itsm.workspace.service import WorkspaceService


def _dashboard_service(request: Request) -> Iterator[DashboardService]:
    factory = request.app.state.session_factory
    session = factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield DashboardService(session, identity, request.app.state.settings, source="rest")
    finally:
        session.close()


def _workspace_service(request: Request) -> Iterator[WorkspaceService]:
    factory = request.app.state.session_factory
    session = factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        yield WorkspaceService(session, identity, source="rest")
    finally:
        session.close()


DashboardDependency = Annotated[DashboardService, Depends(_dashboard_service)]
WorkspaceDependency = Annotated[WorkspaceService, Depends(_workspace_service)]
JsonObject = dict[str, Any]


def create_dashboard_router() -> APIRouter:
    """Mount the dashboard and workspace routes under ``settings.api_prefix``."""
    router = APIRouter()

    @router.get("/dashboard")
    def dashboard_summary(
        context: AuthDependency,
        service: DashboardDependency,
        period: Annotated[str, Query()] = "24h",
        category: Annotated[str | None, Query(max_length=64)] = None,
        site_id: Annotated[str | None, Query(alias="siteId")] = None,
    ) -> dict[str, Any]:
        return service.summary(
            context.principal, period=period, category=category, site_id=site_id
        )

    @router.get("/workspace/state")
    def get_workspace_state(
        context: AuthDependency,
        service: WorkspaceDependency,
    ) -> dict[str, Any]:
        return service.get_state(context.principal)

    @router.put("/workspace/state")
    def save_workspace_state(
        context: MutationDependency,
        service: WorkspaceDependency,
        payload: JsonObject = Body(...),
    ) -> dict[str, Any]:
        return service.save_state(context.principal, payload)

    @router.get("/workspace/shortcuts")
    def list_shortcuts(
        context: AuthDependency,
        service: WorkspaceDependency,
    ) -> list[dict[str, Any]]:
        return service.list_shortcuts(context.principal)

    @router.post("/workspace/shortcuts", status_code=201)
    def create_shortcut(
        context: MutationDependency,
        service: WorkspaceDependency,
        payload: JsonObject = Body(...),
    ) -> dict[str, Any]:
        return service.create_shortcut(context.principal, payload)

    @router.patch("/workspace/shortcuts/{shortcut_id}")
    def update_shortcut(
        shortcut_id: str,
        context: MutationDependency,
        service: WorkspaceDependency,
        payload: JsonObject = Body(...),
    ) -> dict[str, Any]:
        return service.update_shortcut(context.principal, shortcut_id, payload)

    @router.delete("/workspace/shortcuts/{shortcut_id}")
    def delete_shortcut(
        shortcut_id: str,
        context: MutationDependency,
        service: WorkspaceDependency,
    ) -> dict[str, Any]:
        return service.delete_shortcut(context.principal, shortcut_id)

    @router.get("/workspace/views")
    def list_views(
        context: AuthDependency,
        service: WorkspaceDependency,
    ) -> list[dict[str, Any]]:
        return service.list_views(context.principal)

    @router.post("/workspace/views", status_code=201)
    def create_view(
        context: MutationDependency,
        service: WorkspaceDependency,
        payload: JsonObject = Body(...),
    ) -> dict[str, Any]:
        return service.create_view(context.principal, payload)

    @router.patch("/workspace/views/{view_id}")
    def update_view(
        view_id: str,
        context: MutationDependency,
        service: WorkspaceDependency,
        payload: JsonObject = Body(...),
    ) -> dict[str, Any]:
        return service.update_view(context.principal, view_id, payload)

    @router.delete("/workspace/views/{view_id}")
    def delete_view(
        view_id: str,
        context: MutationDependency,
        service: WorkspaceDependency,
    ) -> dict[str, Any]:
        return service.delete_view(context.principal, view_id)

    @router.get("/workspace/integrations")
    def get_integrations(
        context: AuthDependency,
        service: WorkspaceDependency,
    ) -> dict[str, Any]:
        return service.get_integrations(context.principal)

    @router.put("/workspace/integrations")
    def save_integrations(
        context: MutationDependency,
        service: WorkspaceDependency,
        payload: JsonObject = Body(...),
    ) -> dict[str, Any]:
        return service.save_integrations(context.principal, payload)

    return router


__all__ = ["create_dashboard_router"]
