"""Portable identity schema: tables, seeded roles and a reversible migration."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from tests.conftest import run_cli, run_migrations

IDENTITY_TABLES = {
    "identity_roles",
    "identity_role_policies",
    "identity_identities",
    "identity_sessions",
    "identity_credentials",
    "identity_login_attempts",
    "identity_security_settings",
    "identity_audit_events",
}


@pytest.fixture
def migrated(settings_factory: Callable[..., Settings]) -> Settings:
    settings = settings_factory()
    result = run_migrations(settings)
    assert result.returncode == 0, result.stderr
    return settings


def test_identity_migration_creates_the_expected_tables(migrated: Settings) -> None:
    engine = create_engine_from_settings(migrated)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert tables >= IDENTITY_TABLES


def test_identity_migration_seeds_built_in_roles_and_one_settings_row(migrated: Settings) -> None:
    engine = create_engine_from_settings(migrated)
    try:
        with Session(engine) as session:
            roles = session.execute(
                text("SELECT id, built_in FROM identity_roles ORDER BY id")
            ).all()
            settings_rows = session.execute(
                text("SELECT id, session_minutes FROM identity_security_settings")
            ).all()
            identities = session.execute(text("SELECT COUNT(*) FROM identity_identities")).scalar()
    finally:
        engine.dispose()

    assert [row[0] for row in roles] == ["admin", "operator", "reader"]
    assert all(bool(row[1]) for row in roles)
    assert len(settings_rows) == 1
    assert settings_rows[0][1] == 480
    assert identities == 0


def test_identity_migration_downgrades_back_to_the_foundation(migrated: Settings) -> None:
    downgraded = run_cli(
        ["-m", "alembic", "-c", str(migrated.alembic_config_path), "downgrade", "0001_foundation"],
        migrated,
    )
    assert downgraded.returncode == 0, downgraded.stderr

    engine = create_engine_from_settings(migrated)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert not (IDENTITY_TABLES & tables)
    assert "itsm_infrastructure" in tables

    upgraded = run_migrations(migrated)
    assert upgraded.returncode == 0, upgraded.stderr
