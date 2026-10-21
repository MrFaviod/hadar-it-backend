"""Opt-in F2 identity persistence checks on disposable live SQL databases.

Only use databases dedicated to verification. Unlike SQLite fixtures these URLs
are external resources; absent URLs are explicitly skipped, never simulated.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.service import IdentityService
from sqlalchemy.orm import Session
from tests.conftest import run_migrations


@pytest.mark.parametrize(
    "variable", ["ITSM_TEST_IDENTITY_POSTGRES_URL", "ITSM_TEST_IDENTITY_MARIADB_URL"]
)
def test_live_identity_migration_login_and_policy_persistence(variable: str) -> None:
    url = os.environ.get(variable)
    if not url:
        pytest.skip(f"{variable} not configured: live engine not validated")
    settings = Settings(database_url=url, _env_file=None)
    migration = run_migrations(settings)
    assert migration.returncode == 0, migration.stderr
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    suffix = uuid4().hex[:10]
    password = "Disposable-Live-SQL-Only-2026!"
    try:
        with factory() as db:
            service = IdentityService(db, settings)
            installed = service.bootstrap_admin("sql-" + suffix, "SQL test administrator", password)
            grant = service.login(installed.username, password)
            role = service.create_role(
                grant.principal, name="SQL reader " + suffix, permissions=["assets.view"]
            )
            user = service.create_user(
                grant.principal,
                username="reader-" + suffix,
                name="SQL reader",
                role_id=role.id,
                password=password,
            )
            reader_grant = service.login(user.username, password)
            token = reader_grant.token
        with Session(engine) as db:
            service = IdentityService(db, settings)
            restored = service.authenticate_session(token)
            assert restored.principal.actor_id == user.id
            assert restored.permissions == frozenset({"assets.view"})
            service.authorize(restored.principal, "assets.view")
            assert service.me(restored).user.person_id is None
    finally:
        engine.dispose()
