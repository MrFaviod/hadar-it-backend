"""End-to-end SQLite ops coverage: backup, verify, restore, retention, status.

Every check drives the real ``python -m itsm.ops`` process against isolated
SQLite files, so the artifacts, exit codes and JSON payloads are the ones an
operator would see. External engines are covered by pure builders plus opt-in
live tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from itsm.config import Settings
from itsm.database import migration_head
from tests.conftest import BACKEND_ROOT, run_migrations, worker_environment

OPS = "itsm.ops"
LIVE_PASSWORD = "ops-live-secret-2026"


def ops_env(settings: Settings, backup_root: Path, **extra: str) -> dict[str, str]:
    env = worker_environment(settings)
    env["ITSM_OPS_BACKUP_ROOT"] = str(backup_root)
    env.update(extra)
    return env


def run_ops(
    args: list[str],
    settings: Settings,
    backup_root: Path,
    *,
    extra_env: dict[str, str] | None = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", OPS, *args],
        cwd=BACKEND_ROOT,
        env=ops_env(settings, backup_root, **(extra_env or {})),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def payload(result: subprocess.CompletedProcess[str]) -> dict:
    stream = result.stdout.strip() or result.stderr.strip()
    return json.loads(stream.splitlines()[-1])


def migrated(settings_factory: Callable[..., Settings]) -> Settings:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    return settings


def add_marker_rows(settings: Settings, count: int) -> None:
    """Add rows the backup must carry so a restore can be compared."""
    connection = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    try:
        connection.execute("CREATE TABLE ops_marker (value TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO ops_marker (value) VALUES (?)",
            [(f"row-{index}",) for index in range(count)],
        )
        connection.commit()
    finally:
        connection.close()


def database_fingerprint(path: Path) -> tuple[str | None, dict[str, int]]:
    connection = sqlite3.connect(path)
    try:
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        counts = {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        }
    finally:
        connection.close()
    return (None if revision is None else str(revision[0])), counts


def single_backup(settings: Settings, backup_root: Path) -> dict:
    created = run_ops(["backup"], settings, backup_root)
    assert created.returncode == 0, created.stdout + created.stderr
    created_json = payload(created)
    return {**created_json["backup"], "path": created_json["path"]}


def test_backup_writes_a_private_artifact_with_a_complete_manifest(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"

    created = run_ops(["backup"], settings, backup_root)

    assert created.returncode == 0, created.stdout + created.stderr
    payload_json = payload(created)
    backup = payload_json["backup"]
    directory = Path(payload_json["path"])
    dump = directory / "database.db"
    manifest = json.loads((directory / "manifest.json").read_text())
    assert directory.parent == backup_root
    assert backup["id"] == directory.name
    assert backup["engine"] == "sqlite"
    assert backup["format"] == "sqlite"
    assert backup["dumpFile"] == "database.db"
    assert backup["alembicRevision"] == migration_head(settings)
    assert backup["appVersion"] == "0.1.0"
    assert backup["database"].startswith("sqlite:///")
    assert backup["verified"] is None
    assert backup["toolVersions"]["sqlite"].startswith("sqlite ")
    assert manifest["sha256"] == hashlib.sha256(dump.read_bytes()).hexdigest()
    assert manifest["size"] == dump.stat().st_size
    assert manifest["createdAt"] == backup["createdAt"]
    assert (dump.stat().st_mode & 0o777) == 0o600
    assert ((directory / "manifest.json").stat().st_mode & 0o777) == 0o600
    assert (directory.stat().st_mode & 0o777) == 0o700


def test_verify_accepts_an_intact_backup_and_status_reports_it(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)

    verified = run_ops(["verify", backup["id"]], settings, backup_root)

    assert verified.returncode == 0, verified.stdout + verified.stderr
    checked = payload(verified)
    assert checked["status"] == "ok"
    assert checked["checks"] == {"checksum": True, "size": True, "integrity": "ok"}
    assert checked["verified"] is True
    status = payload(run_ops(["status"], settings, backup_root))
    assert status["lastBackup"]["id"] == backup["id"]
    assert status["lastBackup"]["verified"] is True
    assert status["lastBackup"]["sha256"] == backup["sha256"]
    assert status["backupCount"] == 1


def test_verify_rejects_a_backup_whose_dump_changed(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    dump = Path(backup["path"]) / backup["dumpFile"]
    dump.write_bytes(dump.read_bytes() + b"tampered")

    rejected = run_ops(["verify", backup["id"]], settings, backup_root)

    assert rejected.returncode == 1
    checked = payload(rejected)
    assert checked["status"] == "failed"
    assert checked["checks"]["checksum"] is False
    assert "checksum" in checked["error"]


def test_verify_rejects_a_corrupted_sqlite_file_even_with_a_matching_checksum(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    directory = Path(backup["path"])
    dump = directory / backup["dumpFile"]
    dump.write_bytes(b"not a sqlite database" * 32)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["sha256"] = hashlib.sha256(dump.read_bytes()).hexdigest()
    manifest["size"] = dump.stat().st_size
    (directory / "manifest.json").write_text(json.dumps(manifest))

    rejected = run_ops(["verify", backup["id"]], settings, backup_root)

    assert rejected.returncode == 1
    checked = payload(rejected)
    assert checked["checks"]["checksum"] is True
    assert checked["checks"]["integrity"] == "failed"
    assert "integrity" in checked["error"]


def test_restore_into_a_new_file_matches_row_counts_and_revision(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    add_marker_rows(settings, 3)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    target = tmp_path / "restored.db"

    restored = run_ops(
        ["restore", backup["id"], "--target-file", str(target)], settings, backup_root
    )

    assert restored.returncode == 0, restored.stdout + restored.stderr
    restored_json = payload(restored)
    source_revision, source_counts = database_fingerprint(Path(settings.database_url[10:]))
    target_revision, target_counts = database_fingerprint(target)
    assert restored_json["restored"]["revision"] == source_revision == target_revision
    assert restored_json["restored"]["revision"] == migration_head(settings)
    assert target_counts == source_counts
    assert target_counts["ops_marker"] == 3
    assert restored_json["restored"]["rows"] == sum(source_counts.values())
    assert restored_json["live"] is False
    assert (target.stat().st_mode & 0o777) == 0o600


def test_restore_refuses_to_overwrite_the_live_database_without_confirmation(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    add_marker_rows(settings, 2)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    live = Path(settings.database_url.removeprefix("sqlite:///"))
    before = hashlib.sha256(live.read_bytes()).hexdigest()

    refused = run_ops(["restore", backup["id"], "--target-file", str(live)], settings, backup_root)
    assert refused.returncode == 3
    assert payload(refused)["status"] == "refused"
    assert hashlib.sha256(live.read_bytes()).hexdigest() == before

    wrong_token = run_ops(
        [
            "restore",
            backup["id"],
            "--target-file",
            str(live),
            "--replace-live",
            "--confirm",
            "another-backup",
        ],
        settings,
        backup_root,
    )
    assert wrong_token.returncode == 3
    assert hashlib.sha256(live.read_bytes()).hexdigest() == before

    replaced = run_ops(
        [
            "restore",
            backup["id"],
            "--target-file",
            str(live),
            "--replace-live",
            "--confirm",
            backup["id"],
        ],
        settings,
        backup_root,
    )
    assert replaced.returncode == 0, replaced.stdout + replaced.stderr
    assert payload(replaced)["live"] is True
    revision, counts = database_fingerprint(live)
    assert revision == migration_head(settings)
    assert counts["ops_marker"] == 2


def test_restore_refuses_an_existing_target_file(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    target = tmp_path / "occupied.db"
    target.write_bytes(b"do not overwrite me")

    refused = run_ops(
        ["restore", backup["id"], "--target-file", str(target)], settings, backup_root
    )
    assert refused.returncode == 3
    assert target.read_bytes() == b"do not overwrite me"

    missing = run_ops(
        ["restore", "sqlite-20990101T000000Z-000000", "--target-file", str(tmp_path / "x.db")],
        settings,
        backup_root,
    )
    assert missing.returncode == 1
    assert "not found" in payload(missing)["error"]


def test_prune_keeps_the_newest_verified_backup_and_removes_older_ones(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    identifiers = []
    for _ in range(3):
        identifiers.append(single_backup(settings, backup_root)["id"])
    newest = identifiers[-1]
    for identifier in identifiers:
        assert run_ops(["verify", identifier], settings, backup_root).returncode == 0

    pruned = run_ops(["prune", "--keep", "1"], settings, backup_root)

    assert pruned.returncode == 0, pruned.stdout + pruned.stderr
    result = payload(pruned)
    assert result["kept"] == [newest]
    assert sorted(result["deleted"]) == sorted(identifiers[:-1])
    assert result["protected"] == [newest]
    assert sorted(path.name for path in backup_root.iterdir()) == [newest]
    assert payload(run_ops(["status"], settings, backup_root))["backupCount"] == 1

    again = run_ops(["prune", "--keep", "1"], settings, backup_root)
    assert again.returncode == 0
    assert payload(again)["deleted"] == []
    assert payload(again)["protected"] == [newest]


def test_prune_requires_a_retention_rule(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    single_backup(settings, backup_root)

    result = run_ops(["prune"], settings, backup_root)

    assert result.returncode == 2
    assert "retention" in payload(result)["error"]


def test_prune_by_age_never_removes_the_newest_backup_or_the_newest_verified_one(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    identifiers = [single_backup(settings, backup_root)["id"] for _ in range(3)]
    verified = run_ops(["verify", identifiers[1]], settings, backup_root)
    assert verified.returncode == 0

    result = run_ops(["prune", "--max-age-days", "0"], settings, backup_root)

    assert result.returncode == 0, result.stdout + result.stderr
    pruned = payload(result)
    assert pruned["deleted"] == [identifiers[0]]
    assert pruned["kept"] == [identifiers[2], identifiers[1]]
    assert pruned["protected"] == [identifiers[2], identifiers[1]]


def test_status_reports_failures_and_keeps_passwords_out_of_output(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    dump = Path(backup["path"]) / backup["dumpFile"]
    shutil.copyfile(dump, tmp_path / "copy.db")
    dump.write_bytes(b"broken")
    assert run_ops(["verify", backup["id"]], settings, backup_root).returncode == 1

    status = payload(run_ops(["status"], settings, backup_root))

    assert status["status"] == "ok"
    assert status["engine"] == "sqlite"
    assert status["lastBackup"]["id"] == backup["id"]
    assert status["lastBackup"]["verified"] is False
    assert status["failures"][-1]["operation"] == "verify"
    assert LIVE_PASSWORD not in json.dumps(status)


def test_failing_external_backup_never_prints_the_password(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    backup_root = tmp_path / "backups"
    url = f"postgresql+psycopg://itsm:{LIVE_PASSWORD}@127.0.0.1:1/itsm"

    result = run_ops(
        ["backup"], settings, backup_root, extra_env={"ITSM_DATABASE_URL": url}, timeout=90
    )

    combined = result.stdout + result.stderr
    assert result.returncode == 1
    assert LIVE_PASSWORD not in combined
    if shutil.which("pg_dump") is None:
        assert result.stdout == ""
        assert json.loads(result.stderr) == {
            "error": "pg_dump is not available on this host",
            "status": "failed",
        }
    else:
        assert "127.0.0.1:1" in combined
    assert not list(backup_root.glob("*-*-*"))


def test_status_ignores_engine_metadata_for_a_missing_database(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory(database_url=f"sqlite:///{tmp_path / 'absent.db'}")
    backup_root = tmp_path / "backups"

    result = run_ops(["status"], settings, backup_root)

    assert result.returncode == 0
    status = payload(result)
    assert status["lastBackup"] is None
    assert status["backupCount"] == 0


def test_engine_is_reported_for_a_configured_postgres_target(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    result = run_ops(
        ["status"],
        settings,
        tmp_path / "backups",
        extra_env={"ITSM_DATABASE_URL": "postgresql+psycopg://itsm@db.internal:5432/itsm_prod"},
    )

    assert result.returncode == 0
    status = payload(result)
    assert status["engine"] == "postgresql"
    assert status["database"] == "postgresql://itsm@db.internal:5432/itsm_prod"


def test_missing_backup_root_is_reported_without_a_traceback(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    root = tmp_path / "unwritable"
    root.write_text("not a directory")

    result = run_ops(["backup"], settings, root)

    assert result.returncode == 1
    assert payload(result)["status"] == "failed"
    assert "Traceback" not in result.stderr


def test_verify_rejects_an_unknown_backup_id(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"

    result = run_ops(["verify", "sqlite-20990101T000000Z-abcdef"], settings, backup_root)

    assert result.returncode == 1
    assert "not found" in payload(result)["error"]
    assert os.stat(backup_root).st_mode & 0o700 == 0o700


def test_a_live_restore_is_refused_while_the_api_holds_the_database(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """R4-F5: replacing a live file under a running API silently loses writes."""
    from fastapi.testclient import TestClient
    from itsm.main import create_app

    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    live = Path(settings.database_url.removeprefix("sqlite:///"))
    arguments = [
        "restore",
        backup["id"],
        "--target-file",
        str(live),
        "--replace-live",
        "--confirm",
        backup["id"],
    ]

    with TestClient(create_app(settings)) as api:
        assert api.get("/api/v1/health/ready").status_code == 200
        before = hashlib.sha256(live.read_bytes()).hexdigest()
        refused = run_ops(arguments, settings, backup_root)

    assert refused.returncode == 3
    body = payload(refused)
    assert body["status"] == "refused"
    assert "stop the api and the worker" in body["error"].lower()
    assert hashlib.sha256(live.read_bytes()).hexdigest() == before

    allowed = run_ops(arguments, settings, backup_root)

    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert payload(allowed)["live"] is True


def test_the_api_revalidates_deployment_identity_after_the_database_changes(
    settings_factory: Callable[..., Settings], monkeypatch
) -> None:
    """R4-F5: identity used to be validated once for the process lifetime."""
    from fastapi.testclient import TestClient
    from itsm.main import create_app

    monkeypatch.setattr("itsm.main.IDENTITY_REVALIDATE_SECONDS", 0.0)
    settings = migrated(settings_factory)
    live = Path(settings.database_url.removeprefix("sqlite:///"))

    with TestClient(create_app(settings)) as api:
        assert api.get("/api/v1/health/ready").status_code == 200
        assert api.get("/api/v1/assets").status_code in {401, 403}

        # A restore brought back a database owned by another release mode.
        connection = sqlite3.connect(live)
        try:
            connection.execute("UPDATE deployment_identity SET release_mode = 'demo'")
            connection.commit()
        finally:
            connection.close()

        refused = api.get("/api/v1/assets")

    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "release_identity_unavailable"


def test_interrupted_backups_are_reported_and_reclaimable(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """R4-F11: leftover .partial-* directories must be visible and reclaimable."""
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    backup = single_backup(settings, backup_root)
    partial = backup_root / ".partial-sqlite-interrupted"
    partial.mkdir()
    (partial / "database.db").write_bytes(b"x" * 2048)
    stale = time.time() - 5 * 86400
    os.utime(partial, (stale, stale))

    reported = payload(run_ops(["status"], settings, backup_root))

    entry = next(item for item in reported["partials"] if item["name"] == partial.name)
    assert entry["bytes"] == 2048
    assert entry["ageDays"] > 4

    dry = run_ops(
        ["prune", "--keep", "1", "--partials-older-than", "1", "--dry-run"], settings, backup_root
    )
    assert dry.returncode == 0, dry.stderr
    assert payload(dry)["reclaimedPartials"] == [partial.name]
    assert partial.is_dir()

    reclaimed = run_ops(
        ["prune", "--keep", "1", "--partials-older-than", "1"], settings, backup_root
    )

    assert reclaimed.returncode == 0, reclaimed.stderr
    assert payload(reclaimed)["reclaimedPartials"] == [partial.name]
    assert not partial.exists()
    assert (backup_root / backup["id"]).is_dir()
