"""Request quiescence and scheduler failure containment with deterministic clock."""

import asyncio
from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from itsm.demo.controller import DemoController, DemoCycleMiddleware
from itsm.main import create_app
from tests.test_demo_reset import demo_settings


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


def test_full_response_gate_quiesces_before_due_reset(settings_factory):
    async def scenario():
        controller = DemoController(settings_factory())
        response_started = asyncio.Event()
        release_response = asyncio.Event()
        reset_started = asyncio.Event()

        async def app(scope, receive, send):
            response_started.set()
            await release_response.wait()

        middleware = DemoCycleMiddleware(app, controller)

        async def reset_after_gate():
            async with controller.lock:
                reset_started.set()

        request = asyncio.create_task(middleware({"type": "http"}, None, None))
        await response_started.wait()
        reset = asyncio.create_task(reset_after_gate())
        await asyncio.sleep(0)
        assert not reset_started.is_set()
        release_response.set()
        await request
        await reset
        assert reset_started.is_set()

    asyncio.run(scenario())
