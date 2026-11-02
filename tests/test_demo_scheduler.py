"""Counted request gate, in-flight cap and scheduler failure containment."""

import asyncio
import threading
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from itsm.demo.controller import DemoController, DemoCycleMiddleware
from itsm.limits import DemoLimits, DemoLimitsMiddleware
from itsm.main import create_app
from tests.test_demo_reset import demo_settings


async def call(app, *, headers: list[tuple[bytes, bytes]] | None = None) -> list[dict]:
    """Drive one HTTP request through an ASGI app and collect its messages."""
    messages: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": ("127.0.0.1", 40000),
        "server": ("127.0.0.1", 80),
    }
    await app(scope, receive, send)
    return messages


def response_status(messages: list[dict]) -> int:
    start = next(message for message in messages if message["type"] == "http.response.start")
    return start["status"]


def response_headers(messages: list[dict]) -> dict[str, str]:
    start = next(message for message in messages if message["type"] == "http.response.start")
    return {name.decode(): value.decode() for name, value in start["headers"]}


def response_body(messages: list[dict]) -> str:
    return next(
        message["body"] for message in messages if message["type"] == "http.response.body"
    ).decode()


async def wait_until(predicate, timeout: float = 10.0) -> None:
    """Await an observable state; bounded so a missing transition fails loudly."""
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "expected state was never reached"
        await asyncio.sleep(0.005)


def blocking_app(blocked: asyncio.Event, release: asyncio.Event, *, block_first_only: bool = True):
    """An inner app whose first request stays open until ``release`` is set."""
    calls = 0

    async def app(scope, receive, send) -> None:
        nonlocal calls
        calls += 1
        if calls == 1 or not block_first_only:
            blocked.set()
            await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

    return app


def test_due_tick_resets_running_app_without_restart(settings_factory, monkeypatch, tmp_path):
    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        first = client.get("/api/v1/demo/status").json()
        due = datetime.fromisoformat(first["nextResetAt"]) + timedelta(seconds=1)
        original_engine = client.app.state.engine
        client.portal.call(client.app.state.demo_controller.tick, due)
        second = client.get("/api/v1/demo/status")
        assert second.status_code == 200, second.text
        assert second.json()["generation"] == first["generation"] + 1
        assert client.app.state.engine is original_engine
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": settings.auth_origin},
        )
        assert login.status_code == 200, login.text


def test_failed_reset_stays_unavailable(settings_factory, monkeypatch, tmp_path):
    settings = demo_settings(settings_factory, monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        first = client.get("/api/v1/demo/status").json()
        # A later operator path misconfiguration must never trigger unscoped cleanup.
        settings.attachment_storage_path = tmp_path / "outside"
        due = datetime.fromisoformat(first["nextResetAt"]) + timedelta(seconds=1)
        client.portal.call(client.app.state.demo_controller.tick, due)
        response = client.get("/api/v1/demo/status")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "demo_reset_unavailable"
        client.portal.call(client.app.state.demo_controller.tick, due)
        assert client.get("/api/v1/auth/me").status_code == 503


def test_slow_request_does_not_block_a_concurrent_request(settings_factory):
    async def scenario():
        controller = DemoController(settings_factory(demo_max_in_flight=4))
        limits = DemoLimits(controller.settings)
        blocked = asyncio.Event()
        release = asyncio.Event()
        app = DemoCycleMiddleware(
            DemoLimitsMiddleware(blocking_app(blocked, release), limits), controller
        )

        slow = asyncio.create_task(call(app))
        await blocked.wait()
        started = time.monotonic()
        concurrent = await asyncio.wait_for(call(app), timeout=2.0)
        elapsed = time.monotonic() - started
        assert response_status(concurrent) == 200, response_body(concurrent)
        assert elapsed < 0.5
        assert not slow.done()
        release.set()
        await slow

    asyncio.run(scenario())


def test_in_flight_cap_answers_server_busy_with_retry_after(settings_factory):
    async def scenario():
        limits = DemoLimits(settings_factory(demo_max_in_flight=1))
        blocked = asyncio.Event()
        release = asyncio.Event()
        app = DemoLimitsMiddleware(blocking_app(blocked, release), limits)

        slow = asyncio.create_task(call(app))
        await blocked.wait()
        rejected = await asyncio.wait_for(call(app), timeout=2.0)
        assert response_status(rejected) == 503
        headers = response_headers(rejected)
        assert int(headers["retry-after"]) >= 1
        assert headers["cache-control"] == "no-store"
        assert '"server_busy"' in response_body(rejected)
        release.set()
        await slow

    asyncio.run(scenario())


def test_due_reset_drains_in_flight_requests_and_rejects_new_ones(settings_factory, monkeypatch):
    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        monkeypatch.setattr(
            controller,
            "status",
            lambda: {
                "enabled": True,
                "nextResetAt": "2000-01-01T00:00:00+00:00",
                "generation": 1,
                "resetting": False,
            },
        )
        resets: list[int] = []
        monkeypatch.setattr(
            "itsm.demo.controller.reset_demo", lambda settings, engine: resets.append(1)
        )
        blocked = asyncio.Event()
        release = asyncio.Event()
        app = DemoCycleMiddleware(blocking_app(blocked, release), controller)

        slow = asyncio.create_task(call(app))
        await blocked.wait()
        tick = asyncio.create_task(controller.tick())
        for _ in range(500):
            if controller.resetting:
                break
            await asyncio.sleep(0)
        assert controller.resetting
        assert resets == []
        assert not tick.done()
        rejected = await asyncio.wait_for(call(app), timeout=2.0)
        assert response_status(rejected) == 503
        assert response_headers(rejected)["cache-control"] == "no-store"
        assert '"demo_reset_unavailable"' in response_body(rejected)
        release.set()
        await slow
        await tick
        assert resets == [1]
        assert not controller.resetting
        assert response_status(await call(app)) == 200

    asyncio.run(scenario())


def test_a_stuck_request_cannot_hold_the_reset_off_forever(settings_factory, monkeypatch):
    """A client that keeps a body open must not turn the whole demo into 503."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        monkeypatch.setattr(controller, "DRAIN_SECONDS", 0.05)
        monkeypatch.setattr(
            controller,
            "status",
            lambda: {
                "enabled": True,
                "nextResetAt": "2000-01-01T00:00:00+00:00",
                "generation": 1,
                "resetting": False,
            },
        )
        monkeypatch.setattr(
            "itsm.demo.controller.reset_demo",
            lambda settings, engine: controller.__dict__.setdefault("resets", []).append(1),
        )
        blocked = asyncio.Event()
        release = asyncio.Event()
        app = DemoCycleMiddleware(blocking_app(blocked, release), controller)
        stuck = asyncio.create_task(call(app))
        await blocked.wait()
        await asyncio.wait_for(controller.tick(), timeout=2.0)
        assert controller.__dict__["resets"] == [1]
        assert not controller.resetting
        assert response_status(await asyncio.wait_for(call(app), timeout=2.0)) == 200
        release.set()
        await stuck

    asyncio.run(scenario())


def test_concurrent_tick_does_not_mark_its_own_reset_stuck(settings_factory, monkeypatch):
    """The hourly loop must not poison the process while its own reset runs."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        persisted = {
            "enabled": True,
            "nextResetAt": "2000-01-01T00:00:00+00:00",
            "generation": 1,
            "resetting": False,
        }
        monkeypatch.setattr(controller, "status", lambda: dict(persisted))
        started = threading.Event()
        release = threading.Event()

        def slow_reset(settings, engine):
            # A real reset commits its in-flight flag before touching the database.
            persisted["resetting"] = True
            started.set()
            assert release.wait(timeout=10)
            persisted["resetting"] = False
            persisted["generation"] += 1

        monkeypatch.setattr("itsm.demo.controller.reset_demo", slow_reset)

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        running = asyncio.create_task(controller.tick())
        for _ in range(500):
            if started.is_set():
                break
            await asyncio.sleep(0.01)
        assert started.is_set()
        assert controller.resetting

        # The scheduler loop ticks again while reset_demo is still running.
        await asyncio.wait_for(controller.tick(), timeout=2.0)
        assert controller.unavailable is False
        # The gate still excludes requests: that is the reset's own 503, not a poison.
        assert response_status(await call(app)) == 503

        release.set()
        await asyncio.wait_for(running, timeout=10.0)
        assert persisted["generation"] == 2
        assert persisted["resetting"] is False
        assert not controller.resetting
        assert controller.unavailable is False
        assert response_status(await call(app)) == 200

    asyncio.run(scenario())


def test_stale_resetting_snapshot_after_the_reset_ends_is_not_stuck(settings_factory, monkeypatch):
    """A snapshot read while the reset ran must be revalidated, not trusted blindly."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        persisted = {
            "enabled": True,
            "nextResetAt": "2000-01-01T00:00:00+00:00",
            "generation": 1,
            "resetting": False,
        }
        reset_started = threading.Event()
        release_reset = threading.Event()
        snapshot_taken = threading.Event()
        release_snapshot = threading.Event()

        def slow_reset(settings, engine):
            # The real reset commits its in-flight flag before touching the database.
            persisted["resetting"] = True
            reset_started.set()
            assert release_reset.wait(timeout=10)
            persisted["resetting"] = False
            persisted["generation"] += 1
            persisted["nextResetAt"] = "2100-01-01T00:00:00+00:00"

        def status():
            if persisted["resetting"]:
                snapshot = dict(persisted)
                snapshot_taken.set()
                assert release_snapshot.wait(timeout=10)
                return snapshot
            return dict(persisted)

        monkeypatch.setattr(controller, "status", status)
        monkeypatch.setattr("itsm.demo.controller.reset_demo", slow_reset)

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        owner = asyncio.create_task(controller.tick())
        await asyncio.wait_for(asyncio.to_thread(reset_started.wait, 10), timeout=15)
        assert controller.resetting

        # This tick snapshots resetting=True while the reset still owns the gate.
        stale = asyncio.create_task(controller.tick())
        await asyncio.wait_for(asyncio.to_thread(snapshot_taken.wait, 10), timeout=15)

        release_reset.set()
        await asyncio.wait_for(owner, timeout=10)
        assert not controller.resetting

        # The snapshot is now older than the reset it described.
        release_snapshot.set()
        await asyncio.wait_for(stale, timeout=10)
        assert controller.unavailable is False
        assert persisted["generation"] == 2
        assert response_status(await call(app)) == 200

    asyncio.run(scenario())


def test_two_due_ticks_cannot_enter_the_reset_concurrently(settings_factory, monkeypatch):
    """Two ticks that snapshot a due deadline may not both run reset_demo."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        expired = {
            "enabled": True,
            "nextResetAt": "2000-01-01T00:00:00+00:00",
            "generation": 1,
            "resetting": False,
        }
        fresh = {
            "enabled": True,
            "nextResetAt": "2100-01-01T00:00:00+00:00",
            "generation": 2,
            "resetting": False,
        }
        # Both ticks must snapshot the expired deadline before either can own the
        # reset, so the interleaving is explicit instead of timing dependent.
        barrier = threading.Barrier(2, timeout=10)
        completed = threading.Event()
        entered = threading.Event()
        release_reset = threading.Event()
        reads = 0
        reads_lock = threading.Lock()
        entries = 0
        active = 0
        maximum = 0
        state_lock = threading.Lock()

        def status():
            nonlocal reads
            with reads_lock:
                reads += 1
                index = reads
            if index <= 2:
                barrier.wait()
                return dict(expired)
            return dict(fresh) if completed.is_set() else dict(expired)

        def counting_reset(settings, engine):
            nonlocal entries, active, maximum
            with state_lock:
                entries += 1
                active += 1
                maximum = max(maximum, active)
            entered.set()
            assert release_reset.wait(timeout=10)
            with state_lock:
                active -= 1
            completed.set()

        monkeypatch.setattr(controller, "status", status)
        monkeypatch.setattr("itsm.demo.controller.reset_demo", counting_reset)

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        first = asyncio.create_task(controller.tick())
        second = asyncio.create_task(controller.tick())
        await asyncio.wait_for(asyncio.to_thread(entered.wait, 10), timeout=15)
        release_reset.set()
        await asyncio.wait_for(asyncio.gather(first, second), timeout=15)

        # Only the lock owner may enter the reset; the loser re-reads the state
        # the owner left behind instead of resetting the database again.
        assert entries == 1
        assert maximum == 1
        assert completed.is_set()
        assert controller.unavailable is False
        assert not controller.resetting
        assert response_status(await call(app)) == 200

    asyncio.run(scenario())


def test_cancelled_tick_keeps_the_gate_closed_until_the_reset_thread_finishes(
    settings_factory, monkeypatch
):
    """Cancellation must not reopen the gate while reset_demo still runs."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        persisted = {
            "enabled": True,
            "nextResetAt": "2000-01-01T00:00:00+00:00",
            "generation": 1,
            "resetting": False,
        }
        reset_started = threading.Event()
        release_reset = threading.Event()
        reset_finished = threading.Event()
        releases: list[bool] = []

        def slow_reset(settings, engine):
            persisted["resetting"] = True
            reset_started.set()
            assert release_reset.wait(timeout=10)
            persisted["resetting"] = False
            persisted["generation"] += 1
            persisted["nextResetAt"] = "2100-01-01T00:00:00+00:00"
            reset_finished.set()

        monkeypatch.setattr(controller, "status", lambda: dict(persisted))
        monkeypatch.setattr("itsm.demo.controller.reset_demo", slow_reset)
        original_end = controller.gate.end_reset

        def recording_end_reset() -> None:
            releases.append(reset_finished.is_set())
            original_end()

        monkeypatch.setattr(controller.gate, "end_reset", recording_end_reset)

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        tick = asyncio.create_task(controller.tick())
        await asyncio.wait_for(asyncio.to_thread(reset_started.wait, 10), timeout=15)
        assert controller.resetting

        tick.cancel()
        # Yields only deliver the cancellation; they do not order the reset.
        for _ in range(20):
            await asyncio.sleep(0)
            if tick.done():
                break
        assert not tick.done()
        assert controller.resetting
        assert response_status(await call(app)) == 503
        assert releases == []

        release_reset.set()
        await asyncio.wait_for(asyncio.to_thread(reset_finished.wait, 10), timeout=15)
        with pytest.raises(asyncio.CancelledError):
            await tick
        # Ownership was released only after the worker thread finished.
        assert releases == [True]
        assert not controller.resetting
        assert controller.unavailable is False
        assert persisted["generation"] == 2
        assert response_status(await call(app)) == 200

    asyncio.run(scenario())


def test_cancelled_drain_reopens_the_gate_without_starting_a_reset(settings_factory, monkeypatch):
    """Cancellation while draining in-flight requests must not leave the gate shut."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        persisted = {
            "enabled": True,
            "nextResetAt": "2000-01-01T00:00:00+00:00",
            "generation": 1,
            "resetting": False,
        }
        monkeypatch.setattr(controller, "status", lambda: dict(persisted))

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        assert await controller.gate.enter()
        tick = asyncio.create_task(controller.tick())
        await wait_until(lambda: controller.resetting)

        tick.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(tick, timeout=10)
        assert not controller.resetting
        controller.gate.leave()
        assert response_status(await call(app)) == 200
        assert persisted["generation"] == 1

    asyncio.run(scenario())


def test_cancelled_tick_keeps_a_failed_reset_failclosed(settings_factory, monkeypatch):
    """A cancelled caller must not hide a reset that failed after it started."""

    async def scenario():
        controller = DemoController(settings_factory())
        controller.engine = object()
        persisted = {
            "enabled": True,
            "nextResetAt": "2000-01-01T00:00:00+00:00",
            "generation": 1,
            "resetting": False,
        }
        reset_started = threading.Event()
        release_reset = threading.Event()
        entries = []

        def failing_reset(settings, engine):
            # The real reset commits its in-flight flag before touching storage.
            persisted["resetting"] = True
            entries.append(1)
            reset_started.set()
            assert release_reset.wait(timeout=10)
            raise RuntimeError("reset failed after partial work")

        monkeypatch.setattr(controller, "status", lambda: dict(persisted))
        monkeypatch.setattr("itsm.demo.controller.reset_demo", failing_reset)

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        tick = asyncio.create_task(controller.tick())
        await asyncio.wait_for(asyncio.to_thread(reset_started.wait, 10), timeout=15)
        tick.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(tick, timeout=15)
        finally:
            release_reset.set()

        # The worker failed after the destructive stage began, so the process must
        # stay closed and the persisted flag must remain for explicit recovery.
        assert controller.unavailable is True
        assert persisted["resetting"] is True
        assert persisted["generation"] == 1
        assert not controller.resetting
        assert response_status(await call(app)) == 503

        # While closed, a later tick cannot start a second worker.
        await controller.tick()
        assert entries == [1]

    asyncio.run(scenario())


def test_tick_reports_a_reset_left_stuck_by_another_process(settings_factory, monkeypatch):
    """A persisted flag with no local reset owning the gate is still a stuck reset."""

    async def scenario():
        controller = DemoController(settings_factory())
        monkeypatch.setattr(
            controller,
            "status",
            lambda: {
                "enabled": True,
                "nextResetAt": "2000-01-01T00:00:00+00:00",
                "generation": 3,
                "resetting": True,
            },
        )

        async def ok_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        app = DemoCycleMiddleware(ok_app, controller)
        assert not controller.resetting
        await asyncio.wait_for(controller.tick(), timeout=2.0)
        assert controller.unavailable is True
        unavailable = await asyncio.wait_for(call(app), timeout=2.0)
        assert response_status(unavailable) == 503
        assert '"demo_reset_unavailable"' in response_body(unavailable)

    asyncio.run(scenario())
