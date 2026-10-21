"""Thin authenticated metadata routes; permissions and validation live in the service."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext
from itsm.inventory.catalog import InventoryCatalog


def catalog_service(request: Request) -> Iterator[InventoryCatalog]:
    with request.app.state.session_factory() as session:
        yield InventoryCatalog(session, request.app.state.settings)


ServiceDependency = Annotated[InventoryCatalog, Depends(catalog_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]


def create_catalog_router() -> APIRouter:
    router = APIRouter(prefix="/inventory/config", tags=["inventory configuration"])

    @router.get("")
    def get_config(service: ServiceDependency, auth: AuthDependency) -> dict[str, Any]:
        return service.get(auth.principal)

    @router.put("/{kind}/{key}")
    def put_config(
        kind: str,
        key: str,
        payload: dict[str, Any],
        service: ServiceDependency,
        auth: MutationDependency,
    ) -> dict[str, Any]:
        return service.put(auth.principal, kind, key, payload)

    return router
