"""Development maintenance CLI: init, status and resettable dev data.

Covers S3 (dev installs a reasonable fictitious dataset inside a database meant
for development), S4 (errors are easy to diagnose and the environment can be
reset or regenerated without much work) and S5 (development mode cannot point at
a production database and delete it).

Every command is exercised through the public interface
``python -m itsm.devtools <command>`` in a real subprocess; refusals are proven
by the database file and its sentinel rows staying byte-identical.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from itsm.config import Settings
from itsm.database import (
    create_engine_from_settings,
    create_session_factory,
    migration_state,
)
from itsm.demo.state import DemoInstallation
from itsm.identity.clock import utcnow
from itsm.identity.models import Identity
from itsm.identity.service import IdentityService
from itsm.inventory.service import InventoryService
from itsm.release_identity import claim_identity, read_identity
from itsm.release_mode import RELEASE_MODE_ENV
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from tests.conftest import bootstrap_superadmin, run_migrations

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Dev-Tools-Password-42"
# Development reuses the shared populated demo seed: 14 authored assets, plus the
# two rows its completed import creates through the canonical workflow.
DATASET_ASSETS = 14
INVENTORY_ASSETS = DATASET_ASSETS + 2


def env_for(tmp_path: Path, **overrides: str | None) -> dict[str, str]:
    """Environment for the real CLI: isolated files, dev mode, explicit password."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "PYTHONUNBUFFERED": "1",
            RELEASE_MODE_ENV: "dev",
            "ITSM_ENVIRONMENT": "test",
            "ITSM_DATABASE_URL": f"sqlite:///{tmp_path / 'dev.db'}",
            "ITSM_ATTACHMENT_STORAGE_PATH": str(tmp_path / "dev-data" / "attachments"),
            "ITSM_TASK_SQLITE_PATH": str(tmp_path / "dev-data" / "tasks" / "huey.db"),
            "ITSM_DEV_DATA_DIR": str(tmp_path / "dev-data"),
            "ITSM_DEV_ADMIN_PASSWORD": PASSWORD,
            "ITSM_AUTH_ORIGIN": "http://testserver",
            "ITSM_AUTH_COOKIE_SECURE": "false",
            "ITSM_LOG_LEVEL": "WARNING",
        }
    )
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def run(
    tmp_path: Path,
    command: str,
    *arguments: str,
    **overrides: str | None,
) -> subprocess.CompletedProcess[str]:
    """Run one real CLI command with isolated settings."""
    return subprocess.run(
        [sys.executable, "-m", "itsm.devtools", command, *arguments],
        cwd=BACKEND_ROOT,
        env=env_for(tmp_path, **overrides),
        capture_output=True,
        text=True,
        timeout=180,
    )


def payload(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def refused(result: subprocess.CompletedProcess[str]) -> str:
    """Assert a refusal and return the diagnostic message."""
    assert result.returncode != 0, result.stdout
    assert result.stdout == ""
    return result.stderr


def dev_settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Settings pointing at the same files as the CLI environment."""
    values: dict[str, Any] = {
        "environment": "test",
        "database_url": f"sqlite:///{tmp_path / 'dev.db'}",
        "attachment_storage_path": tmp_path / "dev-data" / "attachments",
        "task_sqlite_path": tmp_path / "dev-data" / "tasks" / "huey.db",
        "auth_origin": "http://testserver",
        "auth_cookie_secure": False,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def persisted_identity(settings: Settings):
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            return read_identity(session)
    finally:
        engine.dispose()


def schema_state(settings: Settings):
    engine = create_engine_from_settings(settings)
    try:
        return migration_state(engine, settings)
    finally:
        engine.dispose()


def login_and_count(settings: Settings, username: str, password: str) -> tuple[int, int]:
    """Return (assets, identities) after a real login, proving the admin works."""
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            identity = IdentityService(session, settings)
            principal = identity.login(username, password).principal
            assets = InventoryService(session, settings).search(principal).total
            identities = session.scalar(select(func.count()).select_from(Identity)) or 0
            return assets, int(identities)
    finally:
        engine.dispose()


def file_bytes(path: Path) -> bytes:
    assert path.is_file()
    return path.read_bytes()


def initialise(tmp_path: Path, **overrides: str | None) -> dict[str, Any]:
    return payload(run(tmp_path, "init", **overrides))


def test_init_creates_schema_dev_marker_admin_and_dataset(tmp_path: Path) -> None:
    completed = run(tmp_path, "init")
    assert completed.returncode == 0, completed.stderr
    assert PASSWORD not in completed.stdout + completed.stderr
    result = json.loads(completed.stdout)

    assert result["status"] == "initialized"
    assert result["mode"] == "dev"
    assert result["identity"]["marker"] == "dev"
    assert result["admin"]["username"] == "dev.admin"
    assert result["dataset"]["assets"] == DATASET_ASSETS

    settings = dev_settings(tmp_path)
    state = schema_state(settings)
    assert state.is_current, state
    identity = persisted_identity(settings)
    assert identity is not None and identity.release_mode == "dev"
    assets, users = login_and_count(settings, "dev.admin", PASSWORD)
    assert assets == INVENTORY_ASSETS
    assert users >= 2

    # The environment is explicit in the command output, without the password.
    assert result["database"]["kind"] == "sqlite"
    assert "password" not in result["admin"]


def test_dev_seed_preserves_superadmin_and_excludes_public_credentials(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient
    from itsm.main import create_app

    initialise(tmp_path)
    settings = dev_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "dev.admin", "password": PASSWORD},
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["user"]["roleId"] == "superadmin"
        assert response.json()["demoMode"] is False
        rejected = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": "http://testserver"},
        )
        assert rejected.status_code == 401, rejected.text


def test_second_init_is_idempotent(tmp_path: Path) -> None:
    first = initialise(tmp_path)
    first_assets, first_users = login_and_count(dev_settings(tmp_path), "dev.admin", PASSWORD)

    second = payload(run(tmp_path, "init"))

    assert second["status"] == "unchanged"
    assert second["counts"]["identity_identities"] == first["counts"]["identity_identities"]
    assert second["identity"]["marker"] == "dev"
    assets, users = login_and_count(dev_settings(tmp_path), "dev.admin", PASSWORD)
    assert (assets, users) == (first_assets, first_users)
    assert "password" not in second["admin"]


def test_init_generates_and_prints_a_password_once(tmp_path: Path) -> None:
    first = payload(run(tmp_path, "init", ITSM_DEV_ADMIN_PASSWORD=None))

    admin = first["admin"]
    assert admin["passwordSource"] == "generated"
    generated = admin["password"]
    assert len(generated) >= 12
    assets, _ = login_and_count(dev_settings(tmp_path), "dev.admin", generated)
    assert assets == INVENTORY_ASSETS

    second = payload(run(tmp_path, "init", ITSM_DEV_ADMIN_PASSWORD=None))
    assert second["status"] == "unchanged"
    assert "password" not in second["admin"]
    assert generated not in second["admin"].get("password", "")


def test_status_reports_redacted_database_and_reset_decision(tmp_path: Path) -> None:
    initialise(tmp_path)

    result = payload(run(tmp_path, "status"))

    assert result["mode"] == "dev"
    assert result["database"]["kind"] == "sqlite"
    assert result["database"]["url"].startswith("sqlite:")
    assert result["identity"]["marker"] == "dev"
    assert result["schema"]["status"] == "ok"
    assert result["schema"]["current"] == result["schema"]["head"]
    assert result["counts"]["identity_identities"] >= 2
    assert result["reset"]["allowed"] is True
    assert result["reset"]["target"] == "dev.db"
    assert result["reset"]["reasons"] == []


def test_status_redacts_credentials_when_the_database_is_unreachable(tmp_path: Path) -> None:
    result = payload(
        run(
            tmp_path,
            "status",
            ITSM_DATABASE_URL="postgresql+psycopg://itsm:sup3r-secret@127.0.0.1:1/itsm",
        )
    )

    assert result["database"]["reachable"] is False
    assert result["identity"]["marker"] is None
    assert result["reset"]["allowed"] is False
    assert "sup3r-secret" not in json.dumps(result)


def test_reset_reseeds_and_keeps_the_schema(tmp_path: Path) -> None:
    initialise(tmp_path)
    settings = dev_settings(tmp_path)
    before = schema_state(settings)
    assets_before, users_before = login_and_count(settings, "dev.admin", PASSWORD)

    result = payload(
        run(
            tmp_path,
            "reset",
            "--yes-reset-dev-database",
            "--confirm",
            "dev.db",
        )
    )

    assert result["status"] == "reset"
    assert result["target"] == "dev.db"
    after = schema_state(settings)
    assert after.current == before.current
    assets, users = login_and_count(settings, "dev.admin", PASSWORD)
    assert (assets, users) == (assets_before, users_before)
    assert result["counts"]["identity_identities"] == users_before


def test_regenerate_recreates_the_sqlite_file(tmp_path: Path) -> None:
    initialise(tmp_path)
    database = tmp_path / "dev.db"
    before_inode = database.stat().st_ino

    result = payload(
        run(
            tmp_path,
            "reset",
            "--regenerate",
            "--yes-reset-dev-database",
            "--confirm",
            "dev.db",
        )
    )

    assert result["status"] == "regenerated"
    assert database.stat().st_ino != before_inode
    settings = dev_settings(tmp_path)
    assert schema_state(settings).is_current
    assets, _ = login_and_count(settings, "dev.admin", PASSWORD)
    assert assets == INVENTORY_ASSETS


@pytest.mark.parametrize("mode", [None, "prod", "demo"])
def test_every_command_refuses_a_non_dev_release_mode(tmp_path: Path, mode: str | None) -> None:
    initialise(tmp_path)
    database = tmp_path / "dev.db"
    before = file_bytes(database)

    for command in (
        ["init"],
        ["status"],
        ["reset", "--yes-reset-dev-database", "--confirm", "dev.db"],
    ):
        result = run(tmp_path, *command, RELEASE_MODE=mode)
        message = refused(result)
        assert "RELEASE_MODE=dev" in message
        assert file_bytes(database) == before

    if mode is None:
        fresh = tmp_path / "fresh"
        fresh.mkdir()
        result = run(fresh, "init", RELEASE_MODE=None)
        assert "RELEASE_MODE=dev" in refused(result)
        assert not (fresh / "dev.db").exists()


def test_reset_refuses_a_prod_marked_database(tmp_path: Path) -> None:
    settings = dev_settings(tmp_path)
    assert run_migrations(settings).returncode == 0
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            claim_identity(session, "prod", instance_id="sentinel-prod")
            session.commit()
    finally:
        engine.dispose()
    bootstrap_superadmin(settings)
    database = tmp_path / "dev.db"
    before = file_bytes(database)

    for command in (
        ["reset", "--yes-reset-dev-database", "--confirm", "dev.db"],
        ["reset", "--regenerate", "--yes-reset-dev-database", "--confirm", "dev.db"],
        ["init"],
    ):
        message = refused(run(tmp_path, *command))
        assert "prod" in message
        assert file_bytes(database) == before

    identity = persisted_identity(settings)
    assert identity is not None
    assert identity.instance_id == "sentinel-prod"
    assets, _ = login_and_count(settings, "ana.admin", "installer-password-2026")
    assert assets == 0


def test_reset_refuses_a_demo_marked_database(tmp_path: Path) -> None:
    settings = dev_settings(tmp_path)
    assert run_migrations(settings).returncode == 0
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            session.add(
                DemoInstallation(id=1, dataset="fictional-infrastructure-v1", created_at=utcnow())
            )
            session.commit()
    finally:
        engine.dispose()
    database = tmp_path / "dev.db"
    before = file_bytes(database)

    message = refused(run(tmp_path, "reset", "--yes-reset-dev-database", "--confirm", "dev.db"))

    assert "deployment identity" in message
    assert file_bytes(database) == before
    assert persisted_identity(settings) is None


def test_reset_refuses_an_unmarked_non_empty_database(tmp_path: Path) -> None:
    settings = dev_settings(tmp_path)
    assert run_migrations(settings).returncode == 0
    bootstrap_superadmin(settings)
    database = tmp_path / "dev.db"
    before = file_bytes(database)

    message = refused(run(tmp_path, "reset", "--yes-reset-dev-database", "--confirm", "dev.db"))

    assert "deployment identity" in message
    assert file_bytes(database) == before
    assets, _ = login_and_count(settings, "ana.admin", "installer-password-2026")
    assert assets == 0


def test_reset_refuses_a_remote_database_without_connecting(tmp_path: Path) -> None:
    result = run(
        tmp_path,
        "reset",
        "--yes-reset-dev-database",
        "--confirm",
        "itsm",
        ITSM_DATABASE_URL="postgresql+psycopg://itsm:sup3r-secret@db.example.invalid:5432/itsm",
    )

    message = refused(result)
    assert "local database" in message
    assert "sup3r-secret" not in message
    assert "db.example.invalid" not in message


def test_reset_requires_the_flag_and_a_matching_confirmation(tmp_path: Path) -> None:
    initialise(tmp_path)
    settings = dev_settings(tmp_path)
    before = schema_state(settings)

    message = refused(run(tmp_path, "reset"))
    assert "--yes-reset-dev-database" in message

    message = refused(run(tmp_path, "reset", "--yes-reset-dev-database"))
    assert "--confirm" in message

    message = refused(run(tmp_path, "reset", "--yes-reset-dev-database", "--confirm", "prod.db"))
    assert "prod.db" in message and "dev.db" in message

    # The refusals changed nothing.
    assert schema_state(settings).current == before.current
    assets, _ = login_and_count(settings, "dev.admin", PASSWORD)
    assert assets == INVENTORY_ASSETS


def test_reset_refuses_attachment_paths_outside_the_dev_data_directory(
    tmp_path: Path,
) -> None:
    attachments = tmp_path / "attachments"
    attachments.mkdir()
    sentinel = attachments / "sentinel.txt"
    sentinel.write_text("outside dev data", encoding="utf-8")
    initialise(
        tmp_path,
        ITSM_ATTACHMENT_STORAGE_PATH=str(attachments),
        ITSM_DEV_DATA_DIR=None,
    )
    database = tmp_path / "dev.db"
    before = file_bytes(database)

    message = refused(
        run(
            tmp_path,
            "reset",
            "--yes-reset-dev-database",
            "--confirm",
            "dev.db",
            ITSM_ATTACHMENT_STORAGE_PATH=str(attachments),
            ITSM_DEV_DATA_DIR=None,
        )
    )

    assert "dev" in message
    assert sentinel.read_text(encoding="utf-8") == "outside dev data"
    assert file_bytes(database) == before


def test_reset_clears_attachment_and_task_data_inside_the_dev_directory(
    tmp_path: Path,
) -> None:
    initialise(tmp_path)
    attachment = tmp_path / "dev-data" / "attachments" / "blob"
    attachment.parent.mkdir(parents=True, exist_ok=True)
    attachment.write_bytes(b"fictional attachment")
    queue = tmp_path / "dev-data" / "tasks" / "huey.db"
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.write_bytes(b"queue")

    result = payload(run(tmp_path, "reset", "--yes-reset-dev-database", "--confirm", "dev.db"))

    assert result["status"] == "reset"
    assert not attachment.exists()
    assert not queue.exists()


def test_error_output_is_actionable_and_verbose_shows_a_traceback(tmp_path: Path) -> None:
    message = refused(run(tmp_path, "reset"))
    assert message.count("\n") == 0 or message.endswith("\n")
    assert "error:" in message
    assert "next:" in message

    verbose = run(tmp_path, "reset", "--verbose")
    assert verbose.returncode != 0
    assert "Traceback (most recent call last)" in verbose.stderr


def test_init_does_not_mark_development_as_public_demo(tmp_path: Path) -> None:
    """Shared fictional data must not turn development into a public demo."""
    result = initialise(tmp_path)

    assert result["dataset"]["demoMarker"] is False
    assert result["identity"]["marker"] == "dev"
    settings = dev_settings(tmp_path)
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            marker = session.get(DemoInstallation, 1)
            assert marker is None
    finally:
        engine.dispose()
