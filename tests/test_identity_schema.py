"""Portable identity schema: tables, seeded profiles and explicit data migration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

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

SYSTEM_PERMISSIONS = {
    "system.view",
    "system.providers",
    "system.modules",
    "system.configure",
    "system.backup",
    "system.update",
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


def test_identity_migration_seeds_the_profiles_and_one_settings_row(migrated: Settings) -> None:
    engine = create_engine_from_settings(migrated)
    try:
        with Session(engine) as session:
            roles = session.execute(
                text("SELECT id, name, built_in FROM identity_roles ORDER BY id")
            ).all()
            settings_rows = session.execute(
                text("SELECT id, session_minutes FROM identity_security_settings")
            ).all()
            identities = session.execute(text("SELECT COUNT(*) FROM identity_identities")).scalar()
            columns = {
                column["name"]
                for column in inspect(session.get_bind()).get_columns("identity_identities")
            }
    finally:
        engine.dispose()

    assert [row[0] for row in roles] == ["admin", "operator", "superadmin", "user"]
    built_in = {row[0]: bool(row[2]) for row in roles}
    assert built_in == {
        "admin": True,
        "operator": False,
        "superadmin": True,
        "user": True,
    }
    assert {row[0]: row[1] for row in roles} == {
        "admin": "Administrador",
        "operator": "Operador",
        "superadmin": "Superadministrador",
        "user": "Usuario",
    }
    assert "role_owner" in columns
    assert len(settings_rows) == 1
    assert settings_rows[0][1] == 480
    assert identities == 0


def test_migration_keeps_admins_and_operators_and_migrates_readers_to_user(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    upgraded = run_cli(
        [
            "-m",
            "alembic",
            "-c",
            str(settings.alembic_config_path),
            "upgrade",
            "0020_agent_integrations",
        ],
        settings,
    )
    assert upgraded.returncode == 0, upgraded.stderr

    now = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
    identities = (
        ("id-admin", "legacy.admin", "admin", 1),
        ("id-reader", "legacy.reader", "reader", 1),
        ("id-operator", "legacy.operator", "operator", 1),
        ("id-inactive", "inactive.reader", "reader", 0),
        ("id-custom", "legacy.custom", "role-legacy", 1),
    )
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            session.execute(
                text(
                    "INSERT INTO identity_roles (id, name, built_in, created_at) "
                    "VALUES ('role-legacy', 'Rol heredado', 0, :now)"
                ),
                {"now": now},
            )
            for identity_id, username, role_id, active in identities:
                session.execute(
                    text(
                        "INSERT INTO identity_identities ("
                        "id, username, name, email, actor_kind, person_id, active, "
                        "password_hash, role_id, delegated_by_id, created_at, updated_at, "
                        "last_access_at"
                        ") VALUES ("
                        ":id, :username, :name, NULL, 'human', NULL, :active, "
                        "NULL, :role_id, NULL, :now, :now, NULL)"
                    ),
                    {
                        "id": identity_id,
                        "username": username,
                        "name": username,
                        "active": active,
                        "role_id": role_id,
                        "now": now,
                    },
                )
            session.commit()
    finally:
        engine.dispose()

    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr

    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            assignments = dict(
                session.execute(text("SELECT username, role_id FROM identity_identities")).all()
            )
            roles = {
                row[0]: bool(row[1])
                for row in session.execute(text("SELECT id, built_in FROM identity_roles")).all()
            }
            owners = session.execute(
                text(
                    "SELECT COUNT(*) FROM identity_identities "
                    "WHERE role_id = 'superadmin' AND active = 1"
                )
            ).scalar()
            user_permissions = set(
                session.execute(
                    text(
                        "SELECT resource || '.' || operation FROM identity_role_policies "
                        "WHERE role_id = 'user'"
                    )
                ).scalars()
            )
            operator_permissions = set(
                session.execute(
                    text(
                        "SELECT resource || '.' || operation FROM identity_role_policies "
                        "WHERE role_id = 'operator'"
                    )
                ).scalars()
            )
            owner_permissions = set(
                session.execute(
                    text(
                        "SELECT resource || '.' || operation FROM identity_role_policies "
                        "WHERE role_id = 'superadmin'"
                    )
                ).scalars()
            )
            admin_permissions = set(
                session.execute(
                    text(
                        "SELECT resource || '.' || operation FROM identity_role_policies "
                        "WHERE role_id = 'admin'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()

    assert assignments == {
        "legacy.admin": "admin",
        "legacy.reader": "user",
        "legacy.operator": "operator",
        "inactive.reader": "user",
        "legacy.custom": "role-legacy",
    }
    assert roles == {
        "admin": True,
        "operator": False,
        "role-legacy": False,
        "superadmin": True,
        "user": True,
    }
    assert owners == 0
    assert user_permissions == {"assets.view", "people.view"}
    assert operator_permissions == {
        "assets.view",
        "assets.edit",
        "assets.assign",
        "assets.remote",
        "people.view",
        "people.create",
        "people.edit",
    }
    assert owner_permissions >= SYSTEM_PERMISSIONS
    assert admin_permissions & SYSTEM_PERMISSIONS == set()
    assert {"assets.purge", "reports.share"} <= admin_permissions


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
