"""Installation CLI contract: bootstrap-admin and machine credential issuance.

Every check drives the real ``python -m itsm.identity.cli`` process against a
migrated SQLite database, so exit codes, stdout/stderr and the persisted state
are the same artifacts an installer would see. No .env file is read or written
and no credential is ever echoed back.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.service import AuthenticationFailed, IdentityService
from sqlalchemy import text
from tests.conftest import BACKEND_ROOT, run_migrations, worker_environment
from tests.identity_support import PASSWORD

CLI = "itsm.identity.cli"


def run_identity_cli(
    args: list[str],
    settings,
    *,
    extra_env: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    env = worker_environment(settings)
    env.pop("ITSM_BOOTSTRAP_PASSWORD", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", CLI, *args],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def migrated(settings_factory):
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    return settings


def bootstrap_args() -> list[str]:
    return ["bootstrap-admin", "--username", "ana.admin", "--name", "Ana Admin"]


def service(settings) -> IdentityService:
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    return IdentityService(factory(), settings)


def count(settings, table: str) -> int:
    engine = create_engine_from_settings(settings)
    with engine.connect() as connection:
        return int(connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one())


def test_bootstrap_admin_creates_the_first_administrator_from_process_env(settings_factory) -> None:
    settings = migrated(settings_factory)

    result = run_identity_cli(
        bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
    )

    assert result.returncode == 0, result.stderr
    assert PASSWORD not in result.stdout
    assert PASSWORD not in result.stderr
    assert "argon2" not in result.stdout.lower()
    assert count(settings, "identity_identities") == 1
    identity = service(settings).login("ana.admin", PASSWORD)
    assert identity.permissions  # admin role resolved through Casbin


def test_bootstrap_admin_refuses_to_run_twice(settings_factory) -> None:
    settings = migrated(settings_factory)
    first = run_identity_cli(
        bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
    )
    assert first.returncode == 0, first.stderr

    second = run_identity_cli(
        ["bootstrap-admin", "--username", "other.admin", "--name", "Other"],
        settings,
        extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD},
    )

    assert second.returncode != 0
    assert count(settings, "identity_identities") == 1
    assert "other.admin" not in second.stdout


def test_bootstrap_admin_requires_an_explicit_password(settings_factory) -> None:
    settings = migrated(settings_factory)

    result = run_identity_cli(bootstrap_args(), settings)

    assert result.returncode != 0
    assert count(settings, "identity_identities") == 0
    assert "password" in result.stderr.lower()


def test_bootstrap_admin_rejects_a_password_below_the_minimum(settings_factory) -> None:
    settings = migrated(settings_factory)

    result = run_identity_cli(
        bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": "short"}
    )

    assert result.returncode != 0
    assert "short" not in result.stdout
    assert count(settings, "identity_identities") == 0


def test_machine_identity_credential_is_printed_once_and_stored_as_a_digest(
    settings_factory,
) -> None:
    settings = migrated(settings_factory)
    assert (
        run_identity_cli(
            bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
        ).returncode
        == 0
    )

    result = run_identity_cli(
        [
            "create-machine-identity",
            "--username",
            "agent.collector",
            "--name",
            "Collector",
            "--actor-kind",
            "internal_agent",
            "--role",
            "reader",
        ],
        settings,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    token = payload["token"]
    assert token.startswith("itsm_mk_")
    assert result.stdout.count(token) == 1
    assert count(settings, "identity_credentials") == 1
    with create_engine_from_settings(settings).connect() as connection:
        stored = connection.execute(
            text("SELECT token_digest FROM identity_credentials")
        ).scalar_one()
    assert token not in str(stored)
    assert len(str(stored)) == 64

    actor = service(settings).authenticate_token(token)
    assert actor.principal.kind == "internal_agent"
    assert actor.principal.actor_id


def test_machine_identity_cannot_be_granted_the_admin_role(settings_factory) -> None:
    settings = migrated(settings_factory)
    assert (
        run_identity_cli(
            bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
        ).returncode
        == 0
    )

    result = run_identity_cli(
        [
            "create-machine-identity",
            "--username",
            "agent.rogue",
            "--name",
            "Rogue",
            "--actor-kind",
            "external_agent",
            "--role",
            "admin",
        ],
        settings,
    )

    assert result.returncode != 0
    assert "itsm_mk_" not in result.stdout
    assert count(settings, "identity_credentials") == 0


def test_revoking_a_machine_token_invalidates_it(settings_factory) -> None:
    settings = migrated(settings_factory)
    assert (
        run_identity_cli(
            bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
        ).returncode
        == 0
    )
    issued = run_identity_cli(
        [
            "create-machine-identity",
            "--username",
            "agent.collector",
            "--name",
            "Collector",
            "--actor-kind",
            "internal_agent",
            "--role",
            "reader",
        ],
        settings,
    )
    assert issued.returncode == 0, issued.stderr
    token = json.loads(issued.stdout)["token"]

    revoked = run_identity_cli(["revoke-machine-token", "--username", "agent.collector"], settings)

    assert revoked.returncode == 0, revoked.stderr
    assert token not in revoked.stdout
    with create_engine_from_settings(settings).connect() as connection:
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM identity_credentials WHERE revoked_at IS NULL")
            ).scalar_one()
            == 0
        )
    with pytest.raises(AuthenticationFailed):
        service(settings).authenticate_token(token)


def test_revoking_an_unknown_machine_identity_fails(settings_factory) -> None:
    settings = migrated(settings_factory)

    result = run_identity_cli(["revoke-machine-token", "--username", "agent.missing"], settings)

    assert result.returncode != 0
    assert "agent.missing" in result.stderr


def test_bootstrap_admin_never_requires_a_migrated_schema_to_print_secrets(
    settings_factory,
) -> None:
    settings = settings_factory()

    result = run_identity_cli(
        bootstrap_args(), settings, extra_env={"ITSM_BOOTSTRAP_PASSWORD": PASSWORD}
    )

    assert result.returncode != 0
    assert PASSWORD not in result.stdout
    assert PASSWORD not in result.stderr
    assert Path(settings.database_url.removeprefix("sqlite:///")).name == "app.db"
