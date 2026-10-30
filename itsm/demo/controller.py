"""One-process demo reset scheduler and full-response request quiescence."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import Engine
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from itsm.config import Settings
from itsm.demo.cycle import cycle_status, reset_demo
from itsm.demo.reset import validate_reset_paths
from itsm.logging import log_event

logger = logging.getLogger("itsm.demo")


class DemoController:
    """Serialize demo requests and reset; never race an active streaming response."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lock = asyncio.Lock()
        self.unavailable = False
        self.resetting = False
        self.engine: Engine | None = None
        self.factory: Callable[[], Session] | None = None

    def status(self) -> dict:
        if self.factory is None:
            raise RuntimeError("demo controller is not initialized")
        with self.factory() as session:
            return cycle_status(session)

    async def tick(self, now: datetime | None = None) -> None:
        """Run one due cycle; clock injection allows deterministic scheduler tests."""
        if self.unavailable:
            return
        async with self.lock:
            try:
                status = await asyncio.to_thread(self.status)
                if status["resetting"]:
                    self.unavailable = True
                    return
                deadline = datetime.fromisoformat(status["nextResetAt"])
                if (now or datetime.now(UTC)) < deadline:
                    return
                self.resetting = True
                if self.engine is None:
                    raise RuntimeError("demo controller is not initialized")
                await asyncio.to_thread(reset_demo, self.settings, self.engine)
            except Exception:
                self.unavailable = True
                log_event(logger, "demo.reset_failed", level=logging.ERROR)
            finally:
                self.resetting = False

    async def run(self) -> None:
        validate_reset_paths(self.settings)
        while True:
            await self.tick()
            await asyncio.sleep(1)


class DemoCycleMiddleware:
    """An exclusive gate covers response streaming, background tasks and resets."""

    def __init__(self, app: ASGIApp, controller: DemoController) -> None:
        self.app = app
        self.controller = controller

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        controller = self.controller
        if controller.unavailable or controller.resetting:
            response = JSONResponse(
                {"error": {"code": "demo_reset_unavailable", "message": "demo reset unavailable"}},
                status_code=503,
                headers={"Retry-After": "5", "Cache-Control": "no-store"},
            )
            return await response(scope, receive, send)
        async with controller.lock:
            if controller.unavailable:
                response = JSONResponse(
                    {"error": {"code": "demo_reset_unavailable"}}, status_code=503
                )
                return await response(scope, receive, send)
            await self.app(scope, receive, send)
