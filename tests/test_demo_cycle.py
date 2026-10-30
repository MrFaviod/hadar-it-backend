"""Persisted demo countdown through the public HTTP interface."""

from fastapi.testclient import TestClient
from itsm.main import create_app
from tests.conftest import run_migrations


def test_demo_status_is_disabled_outside_demo(settings_factory):
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/demo/status")
        assert response.status_code == 200
        assert response.json() == {"enabled": False}
        assert response.headers["cache-control"] == "no-store"


def test_demo_deadline_is_server_owned_and_survives_restart(settings_factory, monkeypatch):
    from datetime import datetime

    monkeypatch.setenv("RELEASE_MODE", "demo")
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/demo/status")
        assert response.status_code == 200, response.text
        first = response.json()
        assert first["enabled"] is True
        assert first["generation"] == 1
        assert first["resetting"] is False
        delta = datetime.fromisoformat(first["nextResetAt"]) - datetime.fromisoformat(
            first["serverTime"]
        )
        assert 3590 < delta.total_seconds() <= 3600
        assert response.headers["cache-control"] == "no-store"
    with TestClient(create_app(settings)) as client:
        second = client.get("/api/v1/demo/status").json()
        assert second["generation"] == first["generation"]
        assert second["nextResetAt"] == first["nextResetAt"]
