"""Synthetic demo-only discovery; targets always refer to this private backend."""

from __future__ import annotations

import time
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from itsm.demo.exporter import CONTENT_TYPE, exposition
from itsm.demo.state import is_demo
from itsm.monitoring.models import MonitorAsset

_STARTED = time.monotonic()


def create_demo_telemetry_router() -> APIRouter:
    router = APIRouter(prefix="/demo/telemetry")

    def current_assets(request: Request) -> list[str]:
        if request.app.state.release_mode != "demo":
            raise HTTPException(status_code=404, detail="not found")
        with request.app.state.session_factory() as session:
            if not is_demo(session):
                raise HTTPException(status_code=404, detail="not found")
            return list(
                session.scalars(
                    select(MonitorAsset.asset_id).where(
                        MonitorAsset.enabled.is_(True), MonitorAsset.check_type == "node"
                    )
                )
            )

    @router.get("/targets")
    def targets(request: Request) -> JSONResponse:
        payload = [
            {
                "targets": ["backend:8000"],
                "labels": {
                    "asset_id": asset_id,
                    "check_type": "node",
                    "module": "node",
                    "dataset": "fictional-infrastructure-v1",
                    "__metrics_path__": f"/api/v1/demo/telemetry/metrics/{asset_id}",
                },
            }
            for asset_id in current_assets(request)
        ]
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    @router.get("/metrics/{asset_id}")
    def metrics(request: Request, asset_id: str) -> Response:
        try:
            if str(UUID(asset_id)) != asset_id:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=404, detail="not found") from None
        if asset_id not in current_assets(request):
            raise HTTPException(status_code=404, detail="not found")
        return Response(
            exposition(asset_id, time.monotonic() - _STARTED),
            media_type=CONTENT_TYPE,
            headers={"Cache-Control": "no-store"},
        )

    return router
