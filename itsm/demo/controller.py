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
from itsm.demo.lock import DemoDirectoryLock, DemoProcessConflict
from itsm.demo.reset import recovery_hint, validate_reset_paths
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

    async def begin_reset(self, drain_seconds: float = 10.0) -> bool:
        """Stop admitting requests, then wait at most ``drain_seconds`` to drain.

        Returns ``True`` when every in-flight request finished. A client that
        holds a request open must not keep the demo in permanent 503: the caller
        is told the drain timed out and decides whether to reset anyway.
        """
        self._resetting = True
        try:
            await asyncio.wait_for(self._idle.wait(), timeout=drain_seconds)
        except TimeoutError:
            return False
        return True

    def end_reset(self) -> None:
        self._resetting = False


class DemoController:
    """Own the persisted deadline and the reset's exclusive request gate."""

    # A client holding a request open cannot postpone the hourly reset forever;
    # after this long the reset proceeds and logs ``demo.reset_drain_timeout``.
    DRAIN_SECONDS = 10.0

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.gate = DemoRequestGate()
        self.unavailable = False
        self.engine: Engine | None = None
        self.factory: Callable[[], Session] | None = None
        self._stuck_reported = False
        self._lock: DemoDirectoryLock | None = None
        # Serializes reset ownership inside this process: a tick that loses the
        # race re-reads the persisted state instead of resetting a second time.
        self._reset_lock = asyncio.Lock()

    @property
    def resetting(self) -> bool:
        return self.gate.resetting

    def prepare(self) -> None:
        """Claim the directory for this process and report a stuck previous reset."""
        directory = self.settings.demo_data_directory
        if directory is not None:
            lock = DemoDirectoryLock(directory)
            try:
                lock.acquire()
            except DemoProcessConflict as conflict:
                log_event(
                    logger,
                    "demo.process_conflict",
                    level=logging.ERROR,
                    reason=str(conflict),
                )
                raise
            self._lock = lock
        try:
            status = self.status()
        except Exception:
            # Readiness failures are reported by the scheduler tick, not hidden here.
            return
        if status["resetting"]:
            self._mark_stuck()

    def release(self) -> None:
        """Release the directory so the next process (or recover) can own it."""
        if self._lock is not None:
            self._lock.release()
            self._lock = None

    def _mark_stuck(self) -> None:
        self.unavailable = True
        if self._stuck_reported:
            return
        self._stuck_reported = True
        log_event(
            logger,
            "demo.reset_stuck",
            level=logging.ERROR,
            recovery=recovery_hint(self.settings),
        )

    def status(self) -> dict:
        if self.factory is None:
            raise RuntimeError("demo controller is not initialized")
        with self.factory() as session:
            return cycle_status(session)

    async def _read_status(self) -> dict | None:
        """Read the persisted cycle; ``None`` means this process is unavailable."""
        try:
            return await asyncio.to_thread(self.status)
        except Exception:
            # A transient read failure is retried on the next tick; only a failed
            # reset makes the demo unavailable.
            log_event(logger, "demo.reset_failed", level=logging.ERROR)
            return None

    async def tick(self, now: datetime | None = None) -> None:
        """Run one due cycle; clock injection allows deterministic scheduler tests."""
        if self.unavailable:
            return
        status = await self._read_status()
        if status is None:
            return
        if status["resetting"]:
            if self.gate.resetting:
                return
            # The snapshot may predate the end of this process's own reset, so a
            # stale ``resetting`` flag is only stuck when a fresh read agrees.
            status = await self._read_status()
            if status is None:
                return
            if status["resetting"]:
                self._mark_stuck()
                return
        moment = now or datetime.now(UTC)
        if moment < datetime.fromisoformat(status["nextResetAt"]):
            return
        async with self._reset_lock:
            # Two ticks can both observe a due deadline before either owns the
            # reset; only the holder of this lock may start one, and it re-reads
            # the state it is about to act on.
            fresh = await self._read_status()
            if fresh is None:
                return
            if fresh["resetting"]:
                if not self.gate.resetting:
                    self._mark_stuck()
                return
            if moment < datetime.fromisoformat(fresh["nextResetAt"]):
                return
            await self._begin_reset()
            try:
                await self._reset_and_wait()
            except Exception:
                self.unavailable = True
                log_event(logger, "demo.reset_failed", level=logging.ERROR)
            finally:
                self.gate.end_reset()

    async def _begin_reset(self) -> None:
        """Open the gate for this tick's reset.

        A cancellation while draining in-flight requests arrives before any
        reset work exists, so ownership is released and the gate reopened here
        instead of leaking a shut gate that later looks like a stuck reset.
        """
        try:
            opened = await self.gate.begin_reset(self.DRAIN_SECONDS)
        except asyncio.CancelledError:
            self.gate.end_reset()
            raise
        if not opened:
            log_event(
                logger,
                "demo.reset_drain_timeout",
                level=logging.WARNING,
                inFlight=self.gate.in_flight,
            )

    async def _reset_and_wait(self) -> None:
        """Run one reset without letting cancellation abandon the worker.

        The worker runs in a thread, which cancellation cannot stop. Ownership
        therefore stays held until the real reset finishes: the caller is only
        allowed to unwind afterwards, and a failed worker is still reported.
        """
        if self.engine is None:
            raise RuntimeError("demo controller is not initialized")
        worker = asyncio.ensure_future(asyncio.to_thread(reset_demo, self.settings, self.engine))
        cancelled = False
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                cancelled = True
            except Exception:
                # The failure is re-raised from the result below.
                break
        try:
            worker.result()
        except Exception:
            log_event(logger, "demo.reset_failed", level=logging.ERROR)
            if cancelled:
                # The caller is unwinding, so ``tick`` cannot mark this failure
                # itself; a partially reset installation must stay failclosed
                # instead of admitting requests with a broken dataset.
                self.unavailable = True
            else:
                raise
        if cancelled:
            raise asyncio.CancelledError()

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
