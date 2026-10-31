"""Attachment blobs inside the ops artifact: archive, verify, restore.

Attachment metadata lives in the core database but the bytes live in
``ITSM_ATTACHMENT_STORAGE_PATH``. A backup that only carries the database is not
a recoverable backup: a restore would report success while every download
returns ``503 attachment storage unavailable``. These checks drive the real
``python -m itsm.ops`` process against an isolated SQLite core database and an
isolated attachment storage root.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path

from itsm.config import Settings
from tests.test_ops_sqlite import migrated, payload, run_ops

KEY_ONE = "0123456789abcdef0123456789abcdef"
KEY_TWO = "fedcba9876543210fedcba9876543210"


def run_attachment_ops(
    args: list[str],
    settings: Settings,
    *,
    backup_root: Path,
    storage_root: Path,
    timeout: float = 180.0,
) -> subprocess.CompletedProcess[str]:
    return run_ops(
        args,
        settings,
        backup_root,
        extra_env={"ITSM_ATTACHMENT_STORAGE_PATH": str(storage_root)},
        timeout=timeout,
    )


def create_blob(storage_root: Path, key: str, data: bytes) -> Path:
    storage_root.mkdir(parents=True, exist_ok=True)
    path = storage_root / key
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def manifest_of(created: subprocess.CompletedProcess[str]) -> tuple[dict, Path]:
    assert created.returncode == 0, created.stdout + created.stderr
    created_json = payload(created)
    directory = Path(created_json["path"])
    return json.loads((directory / "manifest.json").read_text()), directory


def test_backup_archives_attachment_blobs_with_checksums(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    storage_root = tmp_path / "attachments"
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    create_blob(storage_root, KEY_ONE, b"first attachment payload")
    create_blob(storage_root, KEY_TWO, b"second attachment payload")

    created = run_attachment_ops(
        ["backup"], settings, backup_root=backup_root, storage_root=storage_root
    )

    manifest, directory = manifest_of(created)
    entries = {entry["key"]: entry for entry in manifest["attachments"]}
    assert set(entries) == {KEY_ONE, KEY_TWO}
    assert entries[KEY_ONE]["sha256"] == hashlib.sha256(b"first attachment payload").hexdigest()
    assert entries[KEY_ONE]["size"] == len(b"first attachment payload")
    archived = directory / "attachments" / KEY_ONE
    assert archived.read_bytes() == b"first attachment payload"
    assert archived.stat().st_mode & 0o777 == 0o600

    verified = run_attachment_ops(
        ["verify", manifest["id"]], settings, backup_root=backup_root, storage_root=storage_root
    )

    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert payload(verified)["attachments"]["count"] == 2


def test_verify_fails_when_one_attachment_byte_is_tampered(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    storage_root = tmp_path / "attachments"
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    create_blob(storage_root, KEY_ONE, b"attachment payload to tamper")
    created = run_attachment_ops(
        ["backup"], settings, backup_root=backup_root, storage_root=storage_root
    )
    manifest, directory = manifest_of(created)
    archived = directory / "attachments" / KEY_ONE
    archived.chmod(0o600)
    archived.write_bytes(b"attachment payload to tamperX")

    verified = run_attachment_ops(
        ["verify", manifest["id"]], settings, backup_root=backup_root, storage_root=storage_root
    )

    assert verified.returncode == 1
    result = payload(verified)
    assert result["verified"] is False
    assert result["attachments"]["missing"] == []
    joined = json.dumps(result["attachments"])
    assert KEY_ONE in joined
    assert "does not match the manifest" in joined


def test_restore_returns_attachment_bytes_to_a_fresh_data_path(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    storage_root = tmp_path / "attachments"
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    create_blob(storage_root, KEY_ONE, b"first attachment payload")
    create_blob(storage_root, KEY_TWO, b"second attachment payload")
    created = run_attachment_ops(
        ["backup"], settings, backup_root=backup_root, storage_root=storage_root
    )
    manifest, _directory = manifest_of(created)

    fresh_database = tmp_path / "fresh" / "app.db"
    fresh_database.parent.mkdir()
    fresh_storage = tmp_path / "fresh" / "attachments"
    resumed = run_attachment_ops(
        [
            "restore",
            manifest["id"],
            "--target-file",
            str(fresh_database),
            "--target-attachments",
            str(fresh_storage),
        ],
        settings,
        backup_root=backup_root,
        storage_root=storage_root,
    )

    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    payload_json = payload(resumed)
    assert payload_json["attachments"]["restored"][0]["count"] == 2
    assert (fresh_storage / KEY_ONE).read_bytes() == b"first attachment payload"
    assert (fresh_storage / KEY_TWO).read_bytes() == b"second attachment payload"
    assert (fresh_storage / KEY_ONE).stat().st_mode & 0o777 == 0o600
    connection = sqlite3.connect(fresh_database)
    try:
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    finally:
        connection.close()
    assert revision is not None


def test_restore_refuses_a_populated_attachment_path_without_consent(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    storage_root = tmp_path / "attachments"
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    create_blob(storage_root, KEY_ONE, b"first attachment payload")
    created = run_attachment_ops(
        ["backup"], settings, backup_root=backup_root, storage_root=storage_root
    )
    manifest, _directory = manifest_of(created)
    target = tmp_path / "existing"
    target.mkdir()
    (target / "kept-by-operator").write_bytes(b"keep me")

    refused = run_attachment_ops(
        [
            "restore",
            manifest["id"],
            "--target-attachments",
            str(target),
        ],
        settings,
        backup_root=backup_root,
        storage_root=storage_root,
    )

    assert refused.returncode == 3
    assert "--replace-live" in payload(refused)["error"]
    assert (target / "kept-by-operator").read_bytes() == b"keep me"
    assert not (target / KEY_ONE).exists()
