"""FastAPI application: versioned API, health checks and centralized errors."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from itsm import __version__
from itsm.agent_integrations.api import (
    create_agent_integrations_router,
    install_agent_integration_error_handlers,
)
from itsm.agent_integrations.catalog import SkillCatalog
from itsm.agent_integrations.extensions import ExtensionRegistry, load_extension_modules
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.agents.api import create_agent_router
from itsm.agents.runtime import AgentRuntime
from itsm.appearance import build_appearance_service, create_appearance_router
from itsm.attachments.api import create_attachment_router
from itsm.config import Settings, get_settings
from itsm.dashboard.api import create_dashboard_router
from itsm.database import (
    Readiness,
    check_readiness,
    create_engine_from_settings,
    create_session_factory,
)
from itsm.directory.api import create_directory_router
from itsm.directory.media_api import create_directory_media_router
from itsm.identity.api import (
    authenticated_actor,
    create_identity_router,
    get_identity_service,
    install_error_handlers,
    mutation_guard,
)
from itsm.identity.service import AuthContext, IdentityService
from itsm.interventions.api import create_intervention_router
from itsm.inventory.api import create_inventory_router
from itsm.inventory.catalog_api import create_catalog_router
from itsm.logging import configure_logging, log_event
from itsm.maintenance.api import create_maintenance_router
from itsm.mcp.server import TOOL_NAMES, create_mcp_server
from itsm.monitoring.api import create_monitoring_router
from itsm.notifications.api import create_notification_router
from itsm.notifications.service import record_alert_event
from itsm.redundancy.api import create_redundancy_router
from itsm.relationships.api import create_relationship_router
from itsm.reports.api import create_reports_router
from itsm.reports.service import build_report_service
from itsm.search.api import create_search_router
from itsm.search.indexer import install_search_sync
from itsm.system.api import create_system_router
from itsm.system.service import SystemService
from itsm.tasks import TaskQueue, TaskStorageUnavailable, create_task_queue
from itsm.workflows.api import create_workflow_router

TASK_ID_PATTERN = r"^[A-Za-z0-9_-]{8,64}$"

logger = logging.getLogger("itsm.api")

ERROR_STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "too_many_requests",
    503: "unavailable",
}


class DemoTaskRequest(BaseModel):
    """Bounded demo work: a short echo, never a task or function name."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    message: str = Field(min_length=1, max_length=1000)
    delay_seconds: int = Field(default=0, ge=0, le=300)


class TaskAcceptedResponse(BaseModel):
    task_id: str
    state: str


class TaskStatusResponse(BaseModel):
    task_id: str
    state: str
    result: dict[str, Any] | None
    error: str | None
    retries_remaining: int | None


def error_payload(code: str, message: str) -> dict[str, dict[str, str]]:
    return {"error": {"code": code, "message": message}}


def _optional_services(settings: Settings) -> dict[str, str]:
    return {
        "prometheus": "configured" if settings.prometheus_url else "not_configured",
        "meilisearch": "configured" if settings.meilisearch_url else "not_configured",
        "redis": "configured" if settings.service_redis_url else "not_configured",
    }


def _task_storage_ok(queue: TaskQueue) -> bool:
    try:
        queue.probe()
    except TaskStorageUnavailable:
        return False
    return True


def _extension_components(settings: Settings) -> tuple[Any, Any]:
    """Build the official catalog, registry and trusted installed modules."""
    catalog = SkillCatalog()
    registry = ExtensionRegistry(catalog, reserved_names=TOOL_NAMES)
    loaded = load_extension_modules(catalog, registry, settings.agent_extension_modules)
    if loaded:
        log_event(logger, "agent.extensions.loaded", modules=",".join(loaded))
    return catalog, registry


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the API application for one settings snapshot."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, secrets=settings.sensitive_values())

    sessions: dict[str, Callable[[], Session]] = {}
    services: dict[str, SystemService] = {}

    def late_session_factory() -> Session:
        return sessions["factory"]()

    def late_system_service() -> SystemService:
        service = services.get("system")
        if service is None:  # pragma: no cover - only before lifespan startup
            service = SystemService(settings, late_session_factory)
        return service

    # FastMCP requires its own lifespan and reuses the API session factory.
    skill_catalog, extension_registry = _extension_components(settings)
    mcp_server = create_mcp_server(
        settings,
        late_session_factory,
        extensions=extension_registry,
        system_service=late_system_service,
    )
    extension_mount = getattr(mcp_server, "extension_mount", None)
    mcp_app = mcp_server.http_app(path="/mcp")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine_from_settings(settings)
        factory = create_session_factory(engine)
        sessions["factory"] = factory
        app.state.settings = settings
        app.state.engine = engine
        app.state.session_factory = factory
        install_search_sync(settings)
        app.state.task_queue = create_task_queue(settings)
        app.state.agent_runtime = AgentRuntime(settings, app.state.session_factory)
        app.state.agent_integrations = AgentIntegrationService(
            settings,
            app.state.session_factory,
            runtime=app.state.agent_runtime,
            catalog=skill_catalog,
            extension_sync=getattr(extension_mount, "sync", None),
        )
        app.state.agent_integrations.initialize()
        app.state.system = SystemService(
            settings,
            factory,
            integrations=app.state.agent_integrations,
        )
        services["system"] = app.state.system
        app.state.agent_runtime.attach_system(app.state.system)
        app.state.reports_service = build_report_service(
            settings, factory, task_queue=app.state.task_queue
        )
        app.state.appearance_service = build_appearance_service(settings, factory)
        log_event(
            logger,
            "app.started",
            app=settings.app_name,
            environment=settings.environment,
            database=settings.safe_database_url(),
            task_storage=settings.task_storage,
        )
        try:
            async with mcp_app.lifespan(app):
                yield
        finally:
            engine.dispose()
            log_event(logger, "app.stopped", app=settings.app_name)

    app = FastAPI(
        title="ITSM backend",
        version=__version__,
        lifespan=lifespan,
    )
    install_error_handlers(app)
    install_agent_integration_error_handlers(app)

    @app.middleware("http")
    async def log_requests(request: Request, call_next: Any) -> Any:
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            log_event(
                logger,
                "request.completed",
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(part) for part in error["loc"][1:]),
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                **error_payload("validation_error", "request validation failed"),
                "details": details,
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def on_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = ERROR_STATUS_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else "request failed"
        return JSONResponse(status_code=exc.status_code, content=error_payload(code, message))

    @app.exception_handler(Exception)
    async def on_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error while serving %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content=error_payload("internal_error", "internal server error"),
        )

    api = APIRouter(prefix=settings.api_prefix)

    @api.get("/health/live")
    def live() -> dict[str, str]:
        """Liveness: the process can answer HTTP, no dependencies involved."""
        return {"status": "ok"}

    @api.post("/tasks/demo", status_code=202)
    def submit_demo_task(
        payload: DemoTaskRequest,
        request: Request,
        context: AuthContext = Depends(mutation_guard),
        identity: IdentityService = Depends(get_identity_service),
    ) -> TaskAcceptedResponse:
        """Queue the bounded echo demo task; no caller-defined task names."""
        if len(payload.message) > settings.demo_message_max_length:
            raise HTTPException(
                status_code=422,
                detail=(f"message must be at most {settings.demo_message_max_length} characters"),
            )
        if payload.delay_seconds > settings.demo_max_delay_seconds:
            raise HTTPException(
                status_code=422,
                detail=(f"delay_seconds must be at most {settings.demo_max_delay_seconds}"),
            )
        try:
            status = request.app.state.task_queue.submit_demo(
                payload.message,
                delay_seconds=payload.delay_seconds,
            )
        except TaskStorageUnavailable as exc:
            log_event(logger, "task.storage_unavailable", level=logging.ERROR)
            raise HTTPException(status_code=503, detail="task storage unavailable") from exc
        identity.record_operation(
            context.principal,
            action="tasks.demo.submit",
            resource=f"task:{status.task_id}",
        )
        log_event(
            logger,
            "task.submitted",
            task_id=status.task_id,
            task_name="demo_echo",
            state=status.state.value,
        )
        return TaskAcceptedResponse(task_id=status.task_id, state=status.state.value)

    @api.get("/tasks/{task_id}")
    def demo_task_status(
        request: Request,
        task_id: str = Path(pattern=TASK_ID_PATTERN),
        context: AuthContext = Depends(authenticated_actor),
    ) -> TaskStatusResponse:
        """Read the stored task state without consuming the result."""
        try:
            status = request.app.state.task_queue.get_status(task_id)
        except TaskStorageUnavailable as exc:
            log_event(logger, "task.storage_unavailable", level=logging.ERROR)
            raise HTTPException(status_code=503, detail="task storage unavailable") from exc
        if status is None:
            raise HTTPException(status_code=404, detail="task not found")
        return TaskStatusResponse(
            task_id=status.task_id,
            state=status.state.value,
            result=status.result,
            error=status.error,
            retries_remaining=status.retries_remaining,
        )

    @api.get("/health/ready")
    def ready(request: Request) -> JSONResponse:
        """Readiness: database, migration head and task storage only."""
        readiness: Readiness = check_readiness(
            request.app.state.engine,
            settings,
            task_storage_ok=_task_storage_ok(request.app.state.task_queue),
        )
        payload = readiness.as_dict()
        payload["optional_services"] = _optional_services(settings)
        return JSONResponse(status_code=200 if readiness.is_ready else 503, content=payload)

    api.include_router(create_workflow_router())
    api.include_router(create_inventory_router())
    api.include_router(create_attachment_router())
    api.include_router(create_maintenance_router())
    api.include_router(create_intervention_router())
    api.include_router(create_monitoring_router(notifier=record_alert_event))
    api.include_router(create_notification_router())
    api.include_router(create_reports_router())
    api.include_router(create_dashboard_router())
    api.include_router(create_appearance_router())
    api.include_router(
        create_search_router(
            sync_task=lambda: app.state.task_queue.submit_search_sync(),
            rebuild_task=lambda: app.state.task_queue.submit_search_rebuild(),
        )
    )
    # Relationship and directory routes must be registered before the MCP mount:
    # a mount on the same prefix would otherwise shadow them.
    api.include_router(create_relationship_router())
    api.include_router(create_redundancy_router())
    api.include_router(create_catalog_router())
    api.include_router(create_directory_router())
    api.include_router(create_directory_media_router())
    api.include_router(create_agent_router())
    api.include_router(create_agent_integrations_router())
    api.include_router(create_system_router())
    api.include_router(create_identity_router())
    app.include_router(api)
    app.mount(settings.api_prefix, mcp_app)
    return app


# ASGI entrypoint: uvicorn itsm.main:app
app = create_app()
