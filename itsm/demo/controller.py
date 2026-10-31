"""One-process demo reset scheduler and counted request quiescence."""

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


class DemoRequestGate:
    """Counted shared access for requests and exclusive access for the reset.

    Every ordinary request enters once and leaves when its response (including
    streaming and background work) is finished, so concurrent visitors no longer
    wait for each other. The reset takes the exclusive side: it stops admitting
    new requests, waits until the in-flight count drains, and only then touches
    the database, so no response can race the cleanup.

    The gate is process-local and single-loop by design: it is created and used
    inside the API event loop, and never awaited from another loop.
    """

    def __init__(self) -> None:
        self._in_flight = 0
        self._resetting = False
        self._idle = asyncio.Event()
        self._idle.set()

    @property
    def in_flight(self) -> int:
        return self._in_flight

    @property
    def resetting(self) -> bool:
        return self._resetting

    async def enter(self) -> bool:
        """Admit one request; ``False`` while a reset owns the gate."""
        if self._resetting:
            return False
        self._in_flight += 1
        self._idle.clear()
        return True

    def leave(self) -> None:
        if self._in_flight:
            self._in_flight -= 1
        if self._in_flight == 0:
            self._idle.set()

    async def begin_reset(self) -> None:
        """Stop admitting requests, then wait for the ones in flight to finish."""
        self._resetting = True
        await self._idle.wait()

    def end_reset(self) -> None:
        self._resetting = False


class DemoController:
    """Own the persisted deadline and the reset's exclusive request gate."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.gate = DemoRequestGate()
        self.unavailable = False
        self.engine: Engine | None = None
        self.factory: Callable[[], Session] | None = None

    @property
    def resetting(self) -> bool:
        return self.gate.resetting

    def status(self) -> dict:
        if self.factory is None:
            raise RuntimeError("demo controller is not initialized")
        with self.factory() as session:
            return cycle_status(session)

    async def tick(self, now: datetime | None = None) -> None:
        """Run one due cycle; clock injection allows deterministic scheduler tests."""
        if self.unavailable:
            return
        try:
            status = await asyncio.to_thread(self.status)
        except Exception:
            self.unavailable = True
            log_event(logger, "demo.reset_failed", level=logging.ERROR)
            return
        if status["resetting"]:
            self.unavailable = True
            log_event(logger, "demo.reset_stuck", level=logging.ERROR)
            return
        deadline = datetime.fromisoformat(status["nextResetAt"])
        if (now or datetime.now(UTC)) < deadline:
            return
        await self.gate.begin_reset()
        try:
            if self.engine is None:
                raise RuntimeError("demo controller is not initialized")
            await asyncio.to_thread(reset_demo, self.settings, self.engine)
        except Exception:
            self.unavailable = True
            log_event(logger, "demo.reset_failed", level=logging.ERROR)
        finally:
            self.gate.end_reset()

    async def run(self) -> None:
        validate_reset_paths(self.settings)
        while True:
            await self.tick()
            await asyncio.sleep(1)


class DemoCycleMiddleware:
    """A counted gate: requests run concurrently, a reset drains and excludes them."""

    def __init__(self, app: ASGIApp, controller: DemoController) -> None:
        self.app = app
        self.controller = controller

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        controller = self.controller
        if controller.unavailable:
            return await self._unavailable(scope, receive, send)
        gate = controller.gate
        if not await gate.enter():
            return await self._unavailable(scope, receive, send)
        try:
            await self.app(scope, receive, send)
        finally:
            gate.leave()

    @staticmethod
    async def _unavailable(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"error": {"code": "demo_reset_unavailable", "message": "demo reset unavailable"}},
            status_code=503,
            headers={"Retry-After": "5", "Cache-Control": "no-store"},
        )
        await response(scope, receive, send)
