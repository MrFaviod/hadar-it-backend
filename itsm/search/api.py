"""Search HTTP surface: canonical query, status and operator actions."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request

from itsm.identity.api import AuthDependency, MutationDependency
from itsm.identity.service import IdentityService
from itsm.search.indexer import process_search_rebuild, process_search_sync
from itsm.search.service import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MAX_OFFSET,
    SearchService,
)


def get_search_service(request: Request) -> Iterator[SearchService]:
    """One session, one identity service and one search service per request."""
    session = request.app.state.session_factory()
    try:
        identity = IdentityService(session, request.app.state.settings)
        request.state.session = session
        request.state.identity = identity
        yield SearchService(session, identity, request.app.state.settings, source="rest")
    finally:
        session.close()


SearchDependency = Annotated[SearchService, Depends(get_search_service)]


def create_search_router(
    *,
    sync_task: Callable[[], Any] | None = None,
    rebuild_task: Callable[[], Any] | None = None,
) -> APIRouter:
    """Build the ``/search`` router.

    ``sync_task`` and ``rebuild_task`` are zero-argument callables supplied by
    the application composition (for example wrappers around the task queue).
    Without them the endpoint runs the trusted executor inline, which is fine
    for small installations and makes the router testable in isolation.
    """
    router = APIRouter()

    @router.get("/search")
    def search(
        q: Annotated[str, Query(min_length=1, max_length=200)],
        service: SearchDependency,
        context: AuthDependency,
        kind: Annotated[list[str] | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
    ) -> dict[str, Any]:
        page = service.search(context.principal, q, kinds=kind, limit=limit, offset=offset)
        return page.as_payload()

    @router.get("/search/status")
    def status(service: SearchDependency, context: AuthDependency) -> dict[str, Any]:
        service.authorize_index_admin(context.principal)
        return service.status()

    @router.post("/search/sync", status_code=202)
    def trigger_sync(
        request: Request,
        service: SearchDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        service.authorize_index_admin(context.principal)
        if sync_task is not None:
            sync_task()
            return {"state": "queued"}
        result = process_search_sync(request.app.state.settings)
        return {"state": "completed", **result}

    @router.post("/search/rebuild", status_code=202)
    def trigger_rebuild(
        request: Request,
        service: SearchDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        service.authorize_index_admin(context.principal)
        if rebuild_task is not None:
            rebuild_task()
            return {"state": "queued"}
        result = process_search_rebuild(request.app.state.settings)
        return {"state": "completed", **result}

    return router


__all__ = ["create_search_router", "get_search_service"]
