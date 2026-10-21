"""Health, readiness and migration behaviour through the public HTTP API."""

from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient
from itsm.config import Settings
from tests.conftest import EventCollector, run_migrations


def test_live_endpoint_does_not_depend_on_the_database(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    broken = settings_factory(database_url="sqlite:////nonexistent-directory/itsm.db")

    response = client(broken).get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_pending_migrations_before_upgrade(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    test_client = client(settings_factory())

    response = test_client.get("/api/v1/health/ready")

    body = response.json()
    assert response.status_code == 503
    assert body["status"] == "unavailable"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["migrations"] == "pending"
    assert body["migrations"]["current"] is None
    assert body["migrations"]["head"] is not None


def test_readiness_is_ok_after_explicit_migration_command(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    migration = run_migrations(settings)
    assert migration.returncode == 0, migration.stderr

    response = client(settings).get("/api/v1/health/ready")

    body = response.json()
    assert response.status_code == 200, body
    assert body["status"] == "ok"
    assert body["checks"] == {"database": "ok", "migrations": "ok", "tasks": "ok"}
    assert body["migrations"]["current"] == body["migrations"]["head"]


def test_app_startup_does_not_apply_migrations(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()

    # Constructing the app and serving requests must not create schema state.
    first = client(settings).get("/api/v1/health/ready")
    second = client(settings).get("/api/v1/health/ready")

    assert first.json()["checks"]["migrations"] == "pending"
    assert second.json()["checks"]["migrations"] == "pending"


def test_optional_service_urls_are_informational_and_never_block_readiness(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(
        prometheus_url="http://127.0.0.1:9/prometheus",
        meilisearch_url="http://127.0.0.1:9/meilisearch",
    )
    assert run_migrations(settings).returncode == 0

    response = client(settings).get("/api/v1/health/ready")

    body = response.json()
    assert response.status_code == 200
    assert body["optional_services"] == {
        "prometheus": "configured",
        "meilisearch": "configured",
        "redis": "not_configured",
    }


def test_ready_response_never_leaks_the_database_url(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()

    response = client(settings).get("/api/v1/health/ready")

    body = response.text
    assert settings.database_url not in body
    assert "password" not in body.lower()


def test_readiness_reports_database_failure_without_crashing(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(database_url="sqlite:////nonexistent-directory/itsm.db")

    response = client(settings).get("/api/v1/health/ready")

    body = response.json()
    assert response.status_code == 503
    assert body["checks"]["database"] == "unavailable"
    assert body["status"] == "unavailable"


def test_requests_are_logged_as_structured_json_events(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
    events: EventCollector,
) -> None:
    test_client = client(settings_factory())

    test_client.get("/api/v1/health/live")

    completed = [event for event in events.events if event["event"] == "request.completed"]
    assert completed
    assert completed[-1]["method"] == "GET"
    assert completed[-1]["path"] == "/api/v1/health/live"
    assert completed[-1]["status_code"] == 200
    assert isinstance(completed[-1]["duration_ms"], int | float)
