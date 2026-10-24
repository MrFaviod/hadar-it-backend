"""Live PostgreSQL checks.

Skipped unless an isolated test database is provided. Never point these
variables at a shared or production database: the suite applies migrations and
lets Huey create its own tables in that database.

* ``ITSM_TEST_DATABASE_URL`` — main DB, e.g.
  ``postgresql+psycopg://itsm:...@127.0.0.1:32768/itsm``
* ``ITSM_TEST_TASK_POSTGRES_DSN`` — optional native psycopg DSN for the
  PostgreSQL-backed queue; defaults to the main URL without the driver suffix.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from sqlalchemy import inspect
from tests.conftest import run_migrations, running_worker, wait_for_status

DATABASE_URL = os.environ.get("ITSM_TEST_DATABASE_URL", "")
TASK_DSN = os.environ.get(
    "ITSM_TEST_TASK_POSTGRES_DSN",
    DATABASE_URL.replace("postgresql+psycopg://", "postgresql://"),
)

pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="ITSM_TEST_DATABASE_URL not set (isolated live PostgreSQL only)",
)


def live_settings(settings_factory: Callable[..., Settings], **overrides: object) -> Settings:
    return settings_factory(database_url=DATABASE_URL, **overrides)


def test_postgres_migrations_and_readiness(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = live_settings(settings_factory)

    migration = run_migrations(settings)

    assert migration.returncode == 0, migration.stderr
    engine = create_engine_from_settings(settings)
    try:
        assert inspect(engine).has_table("itsm_infrastructure")
    finally:
        engine.dispose()

    readiness = client(settings).get("/api/v1/health/ready")

    assert readiness.status_code == 200, readiness.text
    body = readiness.json()
    assert body["checks"] == {"database": "ok", "migrations": "ok", "tasks": "ok"}
    assert body["migrations"]["status"] == "ok"
    assert body["migrations"]["current"] == body["migrations"]["head"]


def test_postgres_huey_storage_runs_the_echo_task(
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
    settings_factory: Callable[..., Settings],
    tmp_path: Path,
) -> None:
    settings = live_settings(
        settings_factory,
        task_storage="postgres",
        task_postgres_dsn=TASK_DSN,
    )
    migration = run_migrations(settings)
    assert migration.returncode == 0, migration.stderr
    test_client, auth = signed_in_client(settings)

    submitted = test_client.post("/api/v1/tasks/demo", json={"message": "postgres"}, headers=auth)
    assert submitted.status_code == 202, submitted.text

    with running_worker(settings, log_path=tmp_path / "worker-postgres.log"):
        completed = wait_for_status(test_client, submitted.json()["task_id"], {"complete"})

    assert completed["result"] == {"message": "postgres"}
