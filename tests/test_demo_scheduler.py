"""Counted request gate, in-flight cap and scheduler failure containment."""

import asyncio
import time
from datetime import datetime, timedelta

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
        await asyncio.sleep(0)
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
