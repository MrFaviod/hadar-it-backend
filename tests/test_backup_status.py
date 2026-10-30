"""Backup status boundary: an authenticated summary of maintenance-published state.

Covers S9 (the installation owner can see whether backups are healthy) and S18
(backup metadata is read-only in the backend: it never runs engine tools, never
opens engine sockets and never mutates backups). Every assertion goes through the
public HTTP surface of a real app over a migrated database, and the published
status file is a real file on disk that must not change because of a request.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo.seed import seed
from itsm.identity.hashing import hash_password
from itsm.identity.models import Identity, IdentityRolePolicy
from itsm.release_mode import RELEASE_MODE_ENV
from sqlalchemy.orm import Session
from tests.conftest import ADMIN_PASSWORD, bootstrap_superadmin, run_migrations, sign_in

BACKUP_STATUS_PATH = "/system/backups/status"
SECRET = "s3cret-backup-token-2026"
SHA256 = "0" * 64

#: Keys the API may publish. Anything else the maintenance service writes --
#: locators, filesystem paths, dump names, hashes, tool versions, restore
#: commands -- stays outside the authenticated browser surface.
SUMMARY_KEYS = {
    "available",
    "reason",
    "checkedAt",
    "status",
    "engine",
    "backupCount",
    "lastBackup",
    "failures",
    "lastUpgrade",
    "updatedAt",
}
LAST_BACKUP_KEYS = {
    "id",
    "createdAt",
    "size",
    "engine",
    "verified",
    "checksum",
    "alembicRevision",
}
LAST_UPGRADE_KEYS = {"status", "currentRevision", "headRevision", "backupId"}
EXCLUDED_KEYS = {
    "path",
    "dumpFile",
    "database",
    "backupRoot",
    "sha256",
    "toolVersions",
    "restoreCommand",
    "engineTools",
    "dsn",
}


def _keys(value: Any) -> set[str]:
    """Collect every mapping key in a JSON-shaped value."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            found.add(str(key))
            found |= _keys(item)
    elif isinstance(value, list):
        for item in value:
            found |= _keys(item)
    return found


def published_document(directory: Path) -> dict[str, Any]:
    """The documented maintenance status shape plus hostile extras."""
    backup_root = directory / "backups"
    backup_id = "postgresql-20260911T100000000000Z-abc123"
    return {
        "status": "ok",
        "engine": "postgresql",
        "database": f"postgresql://itsm:{SECRET}@db.internal:5432/itsm",
        "backupRoot": str(backup_root),
        "backupCount": 3,
        "updatedAt": "2026-09-11T10:00:00+00:00",
        "lastBackup": {
            "id": backup_id,
            "createdAt": "2026-09-11T10:00:00+00:00",
            "size": 1048576,
            "engine": "postgresql",
            "sha256": SHA256,
            "verified": True,
            "checksum": True,
            "alembicRevision": "0040_release_modes",
            "path": str(backup_root / backup_id),
            "dumpFile": "itsm.pgc",
        },
        "failures": [
            {
                "at": "2026-09-10T03:00:00+00:00",
                "operation": "backup",
                "reason": (
                    f"backup root {backup_root} is not writable "
                    f"(dsn=postgresql://itsm:{SECRET}@db.internal/itsm token={SECRET})"
                ),
            },
            "not-a-failure-object",
        ],
        "lastUpgrade": {
            "status": "up to date",
            "currentRevision": "0040_release_modes",
            "headRevision": "0040_release_modes",
            "backupId": None,
            "restoreCommand": (
                f"pg_restore --dbname=postgresql://itsm:{SECRET}@db.internal/itsm "
                f"{backup_root / backup_id}"
            ),
            "error": f"failed while reading {backup_root / backup_id} with {SECRET}",
        },
        "toolVersions": {"pg_dump": "16.3"},
    }


def write_status(path: Path, payload: Mapping[str, Any]) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path.read_bytes()


@contextmanager
def started(settings: Settings, mode: str = "dev") -> Iterator[TestClient]:
    """Start the real app in one release mode without leaking the variable."""
    from itsm.main import create_app

    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = mode
    client: TestClient | None = None
    try:
        client = TestClient(create_app(settings))
        client.__enter__()
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous
    try:
        yield client
    finally:
        client.__exit__(None, None, None)


def install(
    settings_factory: Callable[..., Settings],
    status_path: Path | None,
    **overrides: Any,
) -> Settings:
    settings = settings_factory(backup_status_path=status_path, **overrides)
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    bootstrap_superadmin(settings)
    return settings


def _role_identity(
    settings: Settings,
    *,
    username: str,
    role_id: str,
    grant_system_view: bool = False,
) -> None:
    engine = create_engine_from_settings(settings)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            if grant_system_view:
                session.add(
                    IdentityRolePolicy(role_id=role_id, resource="system", operation="view")
                )
            session.add(
                Identity(
                    id=str(uuid4()),
                    username=username,
                    name=username,
                    actor_kind="human",
                    active=True,
                    password_hash=hash_password(ADMIN_PASSWORD),
                    role_id=role_id,
                )
            )
            session.commit()
    finally:
        engine.dispose()


def login(client: TestClient, settings: Settings, username: str) -> dict[str, str]:
    response = client.post(
        f"{settings.api_prefix}/auth/login",
        json={"username": username, "password": ADMIN_PASSWORD},
        headers={"Origin": settings.auth_origin},
    )
    assert response.status_code == 200, response.text
    return {
        "X-CSRF-Token": str(response.json()["csrfToken"]),
        "Origin": settings.auth_origin,
    }


def snapshot(path: Path) -> tuple[bytes | None, list[str]]:
    """Exact bytes plus directory listing, used to prove nothing was written."""
    listing = sorted(entry.name for entry in path.parent.iterdir()) if path.parent.exists() else []
    return (path.read_bytes() if path.is_file() else None), listing


# ------------------------------------------------------------------ accepted


def test_superadmin_reads_the_published_summary(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """The installation owner sees backup health; locators and secrets do not."""
    status_path = tmp_path / "ops" / "status.json"
    bytes_written = write_status(status_path, published_document(tmp_path / "ops"))
    settings = install(settings_factory, status_path)
    before = snapshot(status_path)
    with started(settings) as client:
        auth = sign_in(client, settings)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is True
    assert body["reason"] is None
    assert set(body) == SUMMARY_KEYS
    assert body["status"] == "ok"
    assert body["engine"] == "postgresql"
    assert body["backupCount"] == 3
    assert body["updatedAt"] == "2026-09-11T10:00:00+00:00"
    assert body["lastBackup"] == {
        "id": "postgresql-20260911T100000000000Z-abc123",
        "createdAt": "2026-09-11T10:00:00+00:00",
        "size": 1048576,
        "engine": "postgresql",
        "verified": True,
        "checksum": True,
        "alembicRevision": "0040_release_modes",
    }
    assert body["lastUpgrade"] == {
        "status": "up to date",
        "currentRevision": "0040_release_modes",
        "headRevision": "0040_release_modes",
        "backupId": None,
    }
    # The malformed failure entry is dropped; the kept one keeps its shape.
    assert len(body["failures"]) == 1
    assert set(body["failures"][0]) == {"at", "operation", "reason"}
    assert body["failures"][0]["operation"] == "backup"
    assert "writable" in body["failures"][0]["reason"]
    assert "[redacted]" in body["failures"][0]["reason"]

    published = json.dumps(body)
    assert EXCLUDED_KEYS.isdisjoint(_keys(body))
    assert SECRET not in published
    assert str(tmp_path) not in published
    assert "postgresql://" not in published
    assert SHA256 not in published
    assert "pg_restore" not in published
    # Reading published metadata never rewrites the file nor creates neighbours.
    assert snapshot(status_path) == before
    assert status_path.read_bytes() == bytes_written


def test_malformed_fields_are_dropped_instead_of_forwarded(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """Wrongly typed published values degrade to null, never to raw passthrough."""
    status_path = tmp_path / "ops" / "status.json"
    write_status(
        status_path,
        {
            "status": 17,
            "engine": ["postgresql"],
            "backupCount": "many",
            "updatedAt": {"at": "yesterday"},
            "lastBackup": "postgresql-20260911T100000000000Z-abc123",
            "failures": {"operation": "backup"},
            "lastUpgrade": ["status"],
        },
    )
    settings = install(settings_factory, status_path)
    before = snapshot(status_path)
    with started(settings) as client:
        auth = sign_in(client, settings)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is True
    assert set(body) == SUMMARY_KEYS
    assert body["status"] is None
    assert body["engine"] is None
    assert body["backupCount"] is None
    assert body["updatedAt"] is None
    assert body["lastBackup"] is None
    assert body["failures"] == []
    assert body["lastUpgrade"] is None
    assert snapshot(status_path) == before


# ---------------------------------------------------------------- unavailable


def test_unconfigured_status_path_is_honestly_unavailable(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = install(settings_factory, None)
    with started(settings) as client:
        auth = sign_in(client, settings)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == SUMMARY_KEYS
    assert body["available"] is False
    assert body["reason"] == "unconfigured"
    assert body["lastBackup"] is None
    assert body["failures"] == []


def test_missing_status_file_is_unavailable_and_never_created(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    status_path = tmp_path / "ops" / "status.json"
    settings = install(settings_factory, status_path)
    with started(settings) as client:
        auth = sign_in(client, settings)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is False
    assert body["reason"] == "missing"
    assert not status_path.exists()
    assert not status_path.parent.exists()


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b"{not-json", "malformed"),
        (b"[]", "malformed"),
        (b'"ok"', "malformed"),
        (json.dumps({"status": "ok", "failures": "x" * 70_000}).encode(), "too_large"),
    ],
)
def test_unusable_status_content_is_unavailable(
    settings_factory: Callable[..., Settings],
    tmp_path: Path,
    content: bytes,
    reason: str,
) -> None:
    status_path = tmp_path / "ops" / "status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_bytes(content)
    settings = install(settings_factory, status_path)
    before = snapshot(status_path)
    with started(settings) as client:
        auth = sign_in(client, settings)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is False
    assert body["reason"] == reason
    assert body["lastBackup"] is None
    assert str(tmp_path) not in response.text
    assert snapshot(status_path) == before


def test_a_directory_instead_of_a_file_is_unavailable(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    status_path = tmp_path / "ops"
    status_path.mkdir()
    settings = install(settings_factory, status_path)
    with started(settings) as client:
        auth = sign_in(client, settings)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is False
    assert body["reason"] == "not_a_file"
    assert list(status_path.iterdir()) == []


# -------------------------------------------------------------------- denied


def test_anonymous_callers_are_rejected_without_disclosure(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    status_path = tmp_path / "ops" / "status.json"
    write_status(status_path, published_document(tmp_path / "ops"))
    settings = install(settings_factory, status_path)
    before = snapshot(status_path)
    with started(settings) as client:
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}")
    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "unauthorized"
    assert "available" not in response.text
    assert "postgresql" not in response.text
    assert SECRET not in response.text
    assert snapshot(status_path) == before


@pytest.mark.parametrize(
    ("username", "role_id"), [("admin.maria", "admin"), ("ops.operator", "operator")]
)
def test_administrator_and_operator_roles_are_denied(
    settings_factory: Callable[..., Settings],
    tmp_path: Path,
    username: str,
    role_id: str,
) -> None:
    """Backup metadata is reserved to the installation owner, not to any admin."""
    status_path = tmp_path / "ops" / "status.json"
    write_status(status_path, published_document(tmp_path / "ops"))
    settings = install(settings_factory, status_path)
    # The operator even holds the raw grant: the reserved ceiling still denies it.
    _role_identity(settings, username=username, role_id=role_id, grant_system_view=True)
    before = snapshot(status_path)
    with started(settings) as client:
        auth = login(client, settings, username)
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}", headers=auth)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "forbidden"
    assert "available" not in response.text
    assert SECRET not in response.text
    assert str(tmp_path) not in response.text
    assert snapshot(status_path) == before


def test_demo_mode_denies_the_protected_system_path(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The public demo denies the whole system surface before authentication."""
    directory = tmp_path_factory.mktemp("demo-backup-status")
    (directory / "tasks").mkdir(parents=True, exist_ok=True)
    status_path = directory / "ops" / "status.json"
    write_status(status_path, published_document(directory / "ops"))
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{directory / 'demo.db'}",
        task_sqlite_path=directory / "tasks" / "huey.db",
        attachment_storage_path=directory / "blobs",
        auth_origin="http://testserver",
        auth_cookie_secure=False,
        log_level="WARNING",
        demo_rate_limit_per_minute=6000,
        demo_rate_limit_burst=6000,
        demo_login_rate_per_minute=1000,
        demo_login_rate_burst=1000,
        backup_status_path=status_path,
    )
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            payload = seed(session, settings, "demo.owner", ADMIN_PASSWORD)
            assert payload["mode"] == "demo"
    finally:
        engine.dispose()
    before = snapshot(status_path)
    with started(settings, "demo") as client:
        response = client.get(f"{settings.api_prefix}{BACKUP_STATUS_PATH}")
        visitor = client.post(
            f"{settings.api_prefix}/auth/login",
            json={"username": "admin", "password": "admin"},
            headers={"Origin": settings.auth_origin},
        )
        assert visitor.status_code == 200, visitor.text
        authenticated = client.get(
            f"{settings.api_prefix}{BACKUP_STATUS_PATH}",
            headers={
                "X-CSRF-Token": str(visitor.json()["csrfToken"]),
                "Origin": settings.auth_origin,
            },
        )
    for denied in (response, authenticated):
        assert denied.status_code == 403, denied.text
        assert denied.json()["error"]["code"] == "demo_restricted"
        assert SECRET not in denied.text
    assert snapshot(status_path) == before
