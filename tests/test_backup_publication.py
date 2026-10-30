"""Scheduled-backup publication: the ops-owned summary the API is allowed to read.

The maintenance service owns backups; the backend only reads a small JSON
document. These tests drive the real preparation CLI, the public
``backup_cycle`` publisher and the public HTTP endpoint. They cover S9 (the
installation owner can see the real last backup, its size and revision) and S18
(no extra platform: the API gains no tools, no engine sockets and no hashing
because publication happens in the ops service).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings, get_settings
from itsm.deployment import backup_cycle
from itsm.ops import service, store
from itsm.ops.engines import OpsError
from itsm.release_identity import DeploymentIdentityError
from itsm.release_mode import RELEASE_MODE_ENV
from tests.conftest import BACKEND_ROOT, bootstrap_superadmin, sign_in

STATUS_PATH = "/system/backups/status"
PUBLIC_KEYS = {
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
PRIVATE_KEYS = {
    "database",
    "backupRoot",
    "path",
    "sha256",
    "dumpFile",
    "restoreCommand",
    "toolVersions",
}
#: Fields publication adds to the private ops record; failure and upgrade history
#: already live there raw and are never replaced.
RECORD_KEYS = {"status", "engine", "backupCount", "lastBackup", "updatedAt"}
SECRET = "s3cret-ops-token-2026"


def keys(value: Any) -> set[str]:
    """Collect every mapping key in a JSON-shaped value."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            found.add(str(key))
            found |= keys(item)
    elif isinstance(value, list):
        for item in value:
            found |= keys(item)
    return found


def prepare_prod(tmp_path: Path) -> Path:
    """Create a production installation through its real one-shot CLI."""
    root = tmp_path / "prod"
    root.mkdir()
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(
        RELEASE_MODE="prod",
        ITSM_DATABASE_URL=f"sqlite:///{root / 'app.db'}",
        ITSM_TASK_SQLITE_PATH=str(root / "tasks.db"),
        ITSM_ATTACHMENT_STORAGE_PATH=str(root / "attachments"),
        ITSM_OPS_BACKUP_ROOT=str(root / "backups"),
        ITSM_ENVIRONMENT="test",
    )
    result = subprocess.run(
        [sys.executable, "-m", "itsm.deployment", "prepare"],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    return root


def configure(monkeypatch: pytest.MonkeyPatch, root: Path, status_path: Path) -> None:
    """Point the real publisher at the prepared installation and one summary path."""
    monkeypatch.setenv(RELEASE_MODE_ENV, "prod")
    monkeypatch.setenv("ITSM_ENVIRONMENT", "test")
    monkeypatch.setenv("ITSM_DATABASE_URL", f"sqlite:///{root / 'app.db'}")
    monkeypatch.setenv("ITSM_TASK_SQLITE_PATH", str(root / "tasks.db"))
    monkeypatch.setenv("ITSM_ATTACHMENT_STORAGE_PATH", str(root / "attachments"))
    monkeypatch.setenv("ITSM_OPS_BACKUP_ROOT", str(root / "backups"))
    monkeypatch.setenv("ITSM_OPS_STATUS_PATH", str(status_path))


def published_summary(private: dict[str, Any], public: dict[str, Any]) -> None:
    """The public copy is exactly the allow-listed part of the private status."""
    assert set(public) == PUBLIC_KEYS
    assert {key: private[key] for key in RECORD_KEYS} == {key: public[key] for key in RECORD_KEYS}


def test_scheduled_backup_publishes_the_operational_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = prepare_prod(tmp_path)
    directory = tmp_path / "backup-status"
    directory.mkdir(mode=0o700)
    published_path = directory / "status.json"
    configure(monkeypatch, root, published_path)

    outcome = backup_cycle()

    assert outcome["status"] == "ok"
    backup_root = root / "backups"
    private = json.loads((backup_root / "status.json").read_text())
    public_bytes = published_path.read_bytes()
    public = json.loads(public_bytes)
    published_summary(private, public)

    assert public["status"] == "ok"
    assert public["engine"] == "sqlite"
    assert public["backupCount"] == 1
    assert datetime.fromisoformat(public["updatedAt"])
    last = public["lastBackup"]
    assert set(last) == LAST_BACKUP_KEYS
    manifest = json.loads((backup_root / outcome["backupId"] / "manifest.json").read_text())
    assert last["id"] == outcome["backupId"]
    assert last["engine"] == "sqlite"
    assert last["size"] == manifest["size"] > 0
    assert last["createdAt"] == manifest["createdAt"]
    assert last["alembicRevision"] == manifest["alembicRevision"]
    assert last["alembicRevision"] is not None
    assert last["checksum"] is True
    assert last["verified"] is True

    # The public copy carries no locator, path, digest or tool detail.
    text = public_bytes.decode()
    assert str(tmp_path) not in text
    assert "sqlite:///" not in text
    assert manifest["sha256"] not in text
    assert PRIVATE_KEYS.isdisjoint(public)
    assert PRIVATE_KEYS.isdisjoint(last)
    # The private ops record keeps its own copy; the external copy is restricted
    # to the allow-list. Raw locators only ever stay in the private record.
    assert private["engine"] == "sqlite"
    assert "failures" not in private
    assert "lastUpgrade" not in private

    # One atomic private write, no temporary neighbour left behind.
    assert stat.S_IMODE(published_path.stat().st_mode) == 0o600
    assert [entry.name for entry in directory.iterdir()] == ["status.json"]


def test_publication_keeps_history_and_reports_a_corrupt_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = prepare_prod(tmp_path)
    directory = tmp_path / "backup-status"
    directory.mkdir(mode=0o700)
    published_path = directory / "status.json"
    configure(monkeypatch, root, published_path)
    outcome = backup_cycle()
    backup_root = root / "backups"
    manifest = json.loads((backup_root / outcome["backupId"] / "manifest.json").read_text())
    dump = backup_root / outcome["backupId"] / manifest["dumpFile"]
    dump.write_bytes(dump.read_bytes() + b"corruption")

    store.record_failure(
        backup_root,
        operation="restore",
        reason=f"{SECRET} could not read {tmp_path / 'private' / 'artifact'}",
        engine="sqlite",
        database=f"sqlite:///{SECRET}",
        secrets=(SECRET,),
    )
    store.record_upgrade(
        backup_root,
        {
            "status": "failed",
            "currentRevision": "0029_deployment_identity",
            "headRevision": "0030_demo_cycle",
            "backupId": None,
            "error": f"{SECRET} failed under {tmp_path / 'private'}",
            "restoreCommand": f"pg_restore --dbname=sqlite:///{SECRET}",
        },
        engine="sqlite",
        database=f"sqlite:///{SECRET}",
    )

    service.publish_status(
        service.OpsContext(get_settings(), backup_root, status_path=published_path)
    )

    public = json.loads(published_path.read_text())
    assert set(public) == PUBLIC_KEYS
    assert public["status"] == "failed"
    assert public["backupCount"] == 1
    assert public["lastBackup"]["id"] == outcome["backupId"]
    assert public["lastBackup"]["checksum"] is False
    assert public["lastBackup"]["verified"] is False
    # Failure history survives and stays source-sanitized.
    assert len(public["failures"]) == 1
    assert public["failures"][0]["operation"] == "restore"
    assert "could not read" in public["failures"][0]["reason"]
    # Only the allow-listed upgrade keys survive, without the error or command.
    assert public["lastUpgrade"] == {
        "status": "failed",
        "currentRevision": "0029_deployment_identity",
        "headRevision": "0030_demo_cycle",
        "backupId": None,
    }
    assert set(public["lastUpgrade"]) == LAST_UPGRADE_KEYS
    text = published_path.read_text()
    assert SECRET not in text
    assert str(tmp_path) not in text
    assert "pg_restore" not in text
    assert "sqlite:///" not in text
    assert stat.S_IMODE(published_path.stat().st_mode) == 0o600

    # The private ops record keeps the raw history the browser copy never sees.
    private = json.loads((backup_root / "status.json").read_text())
    assert private["database"] == f"sqlite:///{SECRET}"
    assert private["lastUpgrade"]["error"].startswith(SECRET)


def test_api_serves_the_external_summary_without_private_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = prepare_prod(tmp_path)
    directory = tmp_path / "backup-status"
    directory.mkdir(mode=0o700)
    published_path = directory / "status.json"
    configure(monkeypatch, root, published_path)
    outcome = backup_cycle()

    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{root / 'app.db'}",
        task_sqlite_path=root / "tasks.db",
        attachment_storage_path=root / "attachments",
        auth_origin="http://testserver",
        auth_cookie_secure=False,
        log_level="WARNING",
        backup_status_path=published_path,
    )
    bootstrap_superadmin(settings)
    before = published_path.read_bytes()
    from itsm.main import create_app

    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = "prod"
    try:
        with TestClient(create_app(settings)) as client:
            auth = sign_in(client, settings)
            response = client.get(f"{settings.api_prefix}{STATUS_PATH}", headers=auth)
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous

    assert response.status_code == 200, response.text
    body = response.json()
    public = json.loads(before)
    assert body["available"] is True
    assert body["reason"] is None
    assert body["status"] == "ok"
    assert body["engine"] == "sqlite"
    assert body["backupCount"] == 1
    assert body["updatedAt"] == public["updatedAt"]
    assert body["lastBackup"] == public["lastBackup"]
    assert body["lastBackup"]["id"] == outcome["backupId"]
    assert body["lastUpgrade"] == public["lastUpgrade"]
    assert body["failures"] == public["failures"]
    assert PRIVATE_KEYS.isdisjoint(keys(body))
    assert str(tmp_path) not in response.text
    # Reading never rewrites or scans the ops-owned publication.
    assert published_path.read_bytes() == before


def test_publication_path_must_be_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = prepare_prod(tmp_path)
    configure(monkeypatch, root, Path("relative") / "status.json")

    with pytest.raises(DeploymentIdentityError):
        backup_cycle()

    assert not (root / "backups").exists()


def test_publication_never_creates_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = prepare_prod(tmp_path)
    absent = tmp_path / "absent" / "status.json"
    configure(monkeypatch, root, absent)

    with pytest.raises(OpsError):
        backup_cycle()

    assert not absent.parent.exists()
