"""Casbin evaluates ITSM-owned policies; the database stays the only source."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.identity.policy import PolicyEngine
from sqlalchemy import text
from sqlalchemy.orm import Session
from tests.conftest import run_migrations

SYSTEM_PERMISSIONS = frozenset(
    {
        "system.view",
        "system.providers",
        "system.modules",
        "system.configure",
        "system.backup",
        "system.update",
    }
)
OWNER_PERMISSIONS = frozenset(PERMISSION_CATALOG) | SYSTEM_PERMISSIONS
BUSINESS_PERMISSIONS = OWNER_PERMISSIONS - SYSTEM_PERMISSIONS


@pytest.fixture
def migrated(settings_factory: Callable[..., Settings]) -> Settings:
    settings = settings_factory()
    result = run_migrations(settings)
    assert result.returncode == 0, result.stderr
    return settings


def engine_for(settings: Settings) -> PolicyEngine:
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            return PolicyEngine.load(session)
    finally:
        engine.dispose()


def test_superadmin_role_covers_the_whole_permission_catalog(migrated: Settings) -> None:
    engine = engine_for(migrated)

    for code in OWNER_PERMISSIONS:
        resource, operation = code.split(".", 1)
        assert engine.allowed("superadmin", resource, operation), code
    assert engine.permissions("superadmin") == OWNER_PERMISSIONS


def test_admin_role_covers_business_administration_without_installation_authority(
    migrated: Settings,
) -> None:
    engine = engine_for(migrated)

    for code in BUSINESS_PERMISSIONS:
        resource, operation = code.split(".", 1)
        assert engine.allowed("admin", resource, operation), code
    assert engine.permissions("admin") == BUSINESS_PERMISSIONS
    assert engine.permissions("admin") & SYSTEM_PERMISSIONS == frozenset()
    for code in SYSTEM_PERMISSIONS:
        resource, operation = code.split(".", 1)
        assert engine.allowed("admin", resource, operation) is False, code


def test_user_and_preserved_operator_roles_match_their_defined_grants(
    migrated: Settings,
) -> None:
    engine = engine_for(migrated)

    assert engine.permissions("user") == frozenset({"assets.view", "people.view"})
    assert engine.allowed("user", "assets", "edit") is False
    assert engine.allowed("user", "assets", "view") is True
    assert engine.allowed("user", "system", "view") is False

    assert engine.allowed("operator", "assets", "remote") is True
    assert engine.allowed("operator", "people", "create") is True
    assert engine.allowed("operator", "users", "edit") is False
    assert engine.permissions("operator") & SYSTEM_PERMISSIONS == frozenset()
    assert engine.permissions("operator") == frozenset(
        {
            "assets.view",
            "assets.edit",
            "assets.assign",
            "assets.remote",
            "people.view",
            "people.create",
            "people.edit",
        }
    )


def test_unknown_role_and_unknown_permission_are_denied_by_default(migrated: Settings) -> None:
    engine = engine_for(migrated)

    assert engine.allowed("custom-missing", "assets", "view") is False
    assert engine.allowed("admin", "assets", "delete") is False
    assert engine.allowed("admin", "secrets", "write") is False


def test_policy_deleted_in_the_database_is_denied_after_reload(migrated: Settings) -> None:
    """No hidden administrator bypass: Casbin alone decides with stored policies."""
    assert engine_for(migrated).allowed("user", "assets", "view") is True

    engine = create_engine_from_settings(migrated)
    try:
        with Session(engine) as session:
            session.execute(
                text(
                    "DELETE FROM identity_role_policies "
                    "WHERE role_id = 'user' AND resource = 'assets' AND operation = 'view'"
                )
            )
            session.commit()
    finally:
        engine.dispose()

    reloaded = engine_for(migrated)
    assert reloaded.allowed("user", "assets", "view") is False
    assert reloaded.allowed("user", "people", "view") is True
