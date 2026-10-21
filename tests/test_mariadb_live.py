"""Live MariaDB checks for the main database seam.

Skipped unless ``ITSM_TEST_MARIADB_URL`` points at a disposable instance you
own, for example
``mysql+pymysql://USER:...@127.0.0.1:PORT/DB``. The suite applies migrations and
never downgrades; it does not touch other databases or services.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from sqlalchemy import inspect
from tests.conftest import run_migrations

MARIADB_URL = os.environ.get("ITSM_TEST_MARIADB_URL", "")

pytestmark = pytest.mark.skipif(
    not MARIADB_URL,
    reason="ITSM_TEST_MARIADB_URL not set (isolated live MariaDB only)",
)


def test_mariadb_migrations_and_readiness(
    client: Callable[..., TestClient],
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(database_url=MARIADB_URL)

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
