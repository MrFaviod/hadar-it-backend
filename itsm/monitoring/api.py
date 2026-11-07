"""FastAPI routes for monitoring configuration, devices, alerts and machine ingestion.

Human routes use the existing cookie session and mutation guard. Machine routes
(Alertmanager webhook, Prometheus HTTP SD and config gauges) use dedicated bearer
tokens from settings and never accept a session principal. Field names are
camelCase because they are the public contract; the service keeps snake_case.
"""

import hmac
import json
from collections.abc import Callable, Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from itsm.config import Settings
from itsm.identity.api import AuthContext, authenticated_actor, mutation_guard
from itsm.monitoring import rules
from itsm.monitoring.service import MonitoringService

Notifier = Callable[..., Any]

Auth = Annotated[AuthContext, Depends(authenticated_actor)]
Mutation = Annotated[AuthContext, Depends(mutation_guard)]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetMonitoringInput(Input):
    enabled: bool | None = None
    checkType: str | None = Field(default=None, max_length=16)
    target: str | None = Field(default=None, max_length=500)
    intervalSeconds: int | None = None
    metrics: list[str] | None = Field(default=None, max_length=8)
    thresholds: dict[str, dict[str, float]] | None = None
    minimumDurationSeconds: int | None = None
    exporterId: str | None = Field(default=None, max_length=36)
    snmpModule: str | None = Field(default=None, max_length=64)
    snmpAuthRef: str | None = Field(default=None, max_length=64)


class ProfileInput(Input):
    enabled: bool | None = None
    checkType: str | None = Field(default=None, max_length=16)
    intervalSeconds: int | None = None
    metrics: list[str] | None = Field(default=None, max_length=8)
    thresholds: dict[str, dict[str, float]] | None = None
    minimumDurationSeconds: int | None = None
    exporterId: str | None = Field(default=None, max_length=36)
    snmpModule: str | None = Field(default=None, max_length=64)
    snmpAuthRef: str | None = Field(default=None, max_length=64)


class ExporterInput(Input):
    id: str | None = Field(default=None, max_length=36)
    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=16)
    module: str = Field(min_length=1, max_length=64)
    address: str | None = Field(default=None, max_length=200)
    enabled: bool = True


class AlertIncidentInput(Input):
    incidentId: str | None = Field(default=None, max_length=36)


class AcknowledgeInput(Input):
    notes: str | None = Field(default=None, max_length=2000)


class SilenceInput(Input):
    assetId: str | None = Field(default=None, max_length=36)
    alertId: str | None = Field(default=None, max_length=36)
    endsAt: str = Field(min_length=1, max_length=64)
    comment: str = Field(min_length=1, max_length=200)


class WindowInput(Input):
    id: str | None = Field(default=None, max_length=36)
    name: str | None = Field(default=None, max_length=120)
    assetIds: list[str] | None = Field(default=None, max_length=50)
    daysOfWeek: list[int] | None = Field(default=None, max_length=7)
    startTime: str | None = Field(default=None, max_length=5)
    endTime: str | None = Field(default=None, max_length=5)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None


def _values(payload: BaseModel) -> dict[str, Any]:
    return payload.model_dump(exclude_unset=True)


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_machine_token(request: Request, secret: Any, label: str) -> None:
    expected = secret.get_secret_value() if secret is not None else ""
    if not expected:
        raise HTTPException(status_code=503, detail=f"{label} is not configured")
    presented = _bearer(request)
    if presented is None or not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="invalid monitoring token")


async def _bounded_json(request: Request, limit: int) -> dict[str, Any]:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise HTTPException(status_code=413, detail="payload too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid content-length") from exc
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="payload too large")
        chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be a JSON object")
    return payload


def create_monitoring_router(notifier: Notifier | None = None) -> APIRouter:
    """Build the monitoring routes; the notifier is the notification module's seam."""
    router = APIRouter()

    def service_dependency(request: Request) -> Iterator[MonitoringService]:
        settings: Settings = request.app.state.settings
        factory = request.app.state.session_factory
        with factory() as session:
            yield MonitoringService(
                session,
                settings,
                source="rest",
                notifier=notifier,
            )

    @router.get("/monitoring/devices")
    def list_devices(
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
        limit: Annotated[int, Query(ge=1, le=rules.MAX_LIMIT)] = rules.DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
        category: str | None = None,
        siteId: str | None = None,
        period: str = rules.DEFAULT_PERIOD,
    ) -> dict[str, Any]:
        return service.list_devices(
            context.principal,
            limit=limit,
            offset=offset,
            category=category,
            site_id=siteId,
            period=period,
        )

    @router.get("/monitoring/devices/{asset_id}")
    def get_device(
        asset_id: str,
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
        period: str = rules.DEFAULT_PERIOD,
    ) -> dict[str, Any]:
        return service.get_device(context.principal, asset_id, period)

    @router.get("/monitoring/config")
    def get_config(
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.get_config(context.principal)

    @router.patch("/monitoring/assets/{asset_id}")
    def update_asset(
        asset_id: str,
        payload: AssetMonitoringInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.update_asset(context.principal, asset_id, _values(payload))

    @router.put("/monitoring/profiles/{category}")
    def update_profile(
        category: str,
        payload: ProfileInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.update_profile(context.principal, category, _values(payload))

    @router.post("/monitoring/exporters", status_code=201)
    def save_exporter(
        payload: ExporterInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.save_exporter(context.principal, _values(payload))

    @router.get("/monitoring/alerts")
    def list_alerts(
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
        limit: Annotated[int, Query(ge=1, le=rules.MAX_LIMIT)] = rules.DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
        state: str | None = None,
        assetId: str | None = None,
    ) -> dict[str, Any]:
        return service.list_alerts(
            context.principal,
            limit=limit,
            offset=offset,
            state=state,
            asset_id=assetId,
        )

    @router.get("/monitoring/alerts/{alert_id}")
    def get_alert(
        alert_id: str,
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.get_alert(context.principal, alert_id)

    @router.get("/monitoring/alerts/{alert_id}/history")
    def alert_history(
        alert_id: str,
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
        limit: Annotated[int, Query(ge=1, le=rules.MAX_LIMIT)] = rules.DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return service.history(context.principal, alert_id, limit=limit, offset=offset)

    @router.post("/monitoring/alerts/{alert_id}/acknowledge")
    def acknowledge(
        alert_id: str,
        payload: AcknowledgeInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.acknowledge(
            context.principal, alert_id, notes=payload.notes or ""
        )

    @router.post("/monitoring/alerts/{alert_id}/incident", status_code=201)
    def link_incident(
        alert_id: str,
        payload: AlertIncidentInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.link_incident(
            context.principal, alert_id, incident_id=payload.incidentId
        )

    @router.post("/monitoring/alerts/{alert_id}/maintenance")
    def prepare_maintenance(
        alert_id: str,
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.prepare_maintenance(context.principal, alert_id)

    @router.post("/monitoring/silences", status_code=201)
    def silence(
        payload: SilenceInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        return service.silence(context.principal, _values(payload))

    @router.get("/monitoring/windows")
    def list_windows(
        context: Auth,
        service: MonitoringService = Depends(service_dependency),
        limit: Annotated[int, Query(ge=1, le=rules.MAX_LIMIT)] = rules.DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        return service.list_windows(context.principal, limit=limit, offset=offset)

    @router.post("/monitoring/windows", status_code=201)
    def create_window(
        payload: WindowInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        values = _values(payload)
        values.pop("id", None)
        return service.save_window(context.principal, values)

    @router.put("/monitoring/windows/{window_id}")
    def update_window(
        window_id: str,
        payload: WindowInput,
        context: Mutation,
        service: MonitoringService = Depends(service_dependency),
    ) -> dict[str, Any]:
        values = {key: value for key, value in _values(payload).items() if key != "id"}
        return service.save_window(context.principal, {"id": window_id, **values})

    # ------------------------------------------------------------ machine routes
    @router.post("/monitoring/alertmanager", status_code=202)
    async def alertmanager_webhook(request: Request) -> dict[str, Any]:
        settings: Settings = request.app.state.settings
        require_machine_token(request, settings.monitoring_ingest_token, "monitoring ingest token")
        payload = await _bounded_json(request, rules.MAX_INGEST_BYTES)

        def handle() -> dict[str, Any]:
            factory = request.app.state.session_factory
            with factory() as session:
                return MonitoringService(
                    session,
                    settings,
                    source="alertmanager",
                    notifier=notifier,
                ).ingest_alertmanager(payload)

        return await run_in_threadpool(handle)

    @router.get("/monitoring/discovery")
    def discovery(
        request: Request,
        check_type: Annotated[str, Query(alias="check_type")],
    ) -> JSONResponse:
        settings: Settings = request.app.state.settings
        require_machine_token(
            request, settings.monitoring_discovery_token, "monitoring discovery token"
        )
        if check_type not in rules.CHECK_TYPES:
            raise HTTPException(status_code=400, detail="unsupported check_type")
        factory = request.app.state.session_factory
        with factory() as session:
            targets = MonitoringService(session, settings).discovery(check_type)
        return JSONResponse(content=targets)

    @router.get("/monitoring/prometheus-metrics")
    def prometheus_metrics(request: Request) -> PlainTextResponse:
        settings: Settings = request.app.state.settings
        require_machine_token(
            request, settings.monitoring_discovery_token, "monitoring discovery token"
        )
        factory = request.app.state.session_factory
        with factory() as session:
            body = MonitoringService(session, settings).config_metrics()
        return PlainTextResponse(
            content=body, media_type="text/plain; version=0.0.4; charset=utf-8"
        )

    return router


__all__ = ["create_monitoring_router", "require_machine_token"]
