"""Guarded upgrade coverage: preflight, backup-first, failure, lock and status.

The happy path and the refusal paths drive the real ``python -m itsm.ops``
process. The injected migration failure drives the public ``run_upgrade``
function with a failing step, because a broken migration must be simulated
without corrupting a real revision.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from itsm.config import Settings
from itsm.database import migration_head
from itsm.ops import service, store, upgrade
from tests.conftest import BACKEND_ROOT, run_migrations, worker_environment

EARLIER_REVISION = "0027_native_extensions"
LIVE_PASSWORD = "upgrade-live-secret-2026"


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
    timeout: float = 180.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "itsm.ops", *args],
        cwd=BACKEND_ROOT,
        env=ops_env(settings, backup_root, **(extra_env or {})),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def payload(result: subprocess.CompletedProcess[str]) -> dict:
    stream = result.stdout.strip() or result.stderr.strip()
    return json.loads(stream.splitlines()[-1])


def migrate_command(settings: Settings, target: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(BACKEND_ROOT / "alembic.ini"),
            "upgrade",
            target,
        ],
        cwd=BACKEND_ROOT,
        env=worker_environment(settings),
        capture_output=True,
        text=True,
        timeout=180,
    )


def add_marker_rows(settings: Settings, count: int) -> None:
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


def marker_rows(settings: Settings) -> int:
    connection = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    try:
        return int(connection.execute("SELECT COUNT(*) FROM ops_marker").fetchone()[0])
    finally:
        connection.close()


def current_revision(settings: Settings) -> str:
    connection = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    try:
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    finally:
        connection.close()
    assert row is not None
    return str(row[0])


def table_names(settings: Settings) -> set[str]:
    connection = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    try:
        return {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        connection.close()


def database_at_earlier_revision(settings_factory: Callable[..., Settings]) -> Settings:
    settings = settings_factory()
    applied = migrate_command(settings, EARLIER_REVISION)
    assert applied.returncode == 0, applied.stderr
    add_marker_rows(settings, 4)
    return settings


def test_upgrade_from_an_earlier_revision_backs_up_then_reaches_head(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    backup_root = tmp_path / "backups"

    result = run_ops(["upgrade"], settings, backup_root)

    assert result.returncode == 0, result.stdout + result.stderr
    outcome = payload(result)
    assert outcome["status"] == "upgraded"
    assert outcome["fromRevision"] == EARLIER_REVISION
    assert outcome["toRevision"] == migration_head(settings)
    assert outcome["backupId"]
    assert "python -m itsm.ops restore" in outcome["restoreCommand"]
    assert outcome["backupId"] in outcome["restoreCommand"]

    manifest = json.loads((Path(outcome["backupPath"]) / "manifest.json").read_text())
    assert manifest["alembicRevision"] == EARLIER_REVISION
    assert manifest["verified"] is True
    assert manifest["size"] > 0

    assert current_revision(settings) == migration_head(settings)
    assert "demo_installation" in table_names(settings)
    assert marker_rows(settings) == 4

    status = payload(run_ops(["status"], settings, backup_root))
    assert status["lastBackup"]["id"] == outcome["backupId"]
    assert status["lastBackup"]["verified"] is True
    assert status["lastUpgrade"]["status"] == "upgraded"
    assert status["lastUpgrade"]["toRevision"] == migration_head(settings)


def test_upgrade_when_already_at_head_creates_no_backup(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    backup_root = tmp_path / "backups"

    result = run_ops(["upgrade"], settings, backup_root)

    assert result.returncode == 0, result.stdout + result.stderr
    outcome = payload(result)
    assert outcome["status"] == "up to date"
    assert outcome["currentRevision"] == migration_head(settings)
    assert outcome["backupId"] is None
    assert payload(run_ops(["status"], settings, backup_root))["backupCount"] == 0


def test_upgrade_with_a_failing_migration_keeps_data_and_reports_the_restore(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    backup_root = tmp_path / "backups"
    context = service.OpsContext(settings=settings, backup_root=backup_root)

    def failing_migration() -> None:
        raise RuntimeError("injected migration failure")

    outcome = upgrade.run_upgrade(context, apply_migrations=failing_migration)

    assert outcome.exit_code == 1
    assert outcome.payload["status"] == "failed"
    assert outcome.payload["stage"] == "migration"
    assert outcome.payload["fromRevision"] == EARLIER_REVISION
    assert outcome.payload["observedRevision"] == EARLIER_REVISION
    assert outcome.payload["headRevision"] == migration_head(settings)
    assert "data preserved" in outcome.payload["message"]
    assert outcome.payload["backupId"]
    assert Path(outcome.payload["backupPath"]).is_dir()
    assert outcome.payload["backupId"] in outcome.payload["restoreCommand"]
    assert "--replace-live" in outcome.payload["restoreCommand"]
    assert LIVE_PASSWORD not in json.dumps(outcome.payload)

    # The live database is untouched: same revision, same rows, no downgrade.
    assert current_revision(settings) == EARLIER_REVISION
    assert marker_rows(settings) == 4
    assert "demo_installation" not in table_names(settings)

    status = payload(run_ops(["status"], settings, backup_root))
    assert status["lastUpgrade"]["status"] == "failed"
    assert status["failures"][-1]["operation"] == "upgrade"
    assert status["lastBackup"]["verified"] is True


def test_a_concurrent_upgrader_is_refused_by_the_lock(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    lock = backup_root / store.LOCK_NAME
    lock.write_text(
        json.dumps(
            {"pid": os.getpid(), "token": "held-by-test", "startedAt": "2026-01-01T00:00:00Z"}
        )
    )

    result = run_ops(["upgrade"], settings, backup_root)

    assert result.returncode == 3
    outcome = payload(result)
    assert outcome["status"] == "refused"
    assert "lock" in outcome["error"]
    assert current_revision(settings) == EARLIER_REVISION
    assert not list(backup_root.glob("*T*Z-*"))


def test_a_stale_lock_from_a_dead_process_is_reclaimed(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    finished = subprocess.Popen([sys.executable, "-c", "pass"])
    finished.wait()
    (backup_root / store.LOCK_NAME).write_text(
        json.dumps({"pid": finished.pid, "token": "dead", "startedAt": "2026-01-01T00:00:00Z"})
    )

    result = run_ops(["upgrade"], settings, backup_root)

    assert result.returncode == 0, result.stdout + result.stderr
    assert payload(result)["status"] == "up to date"
    assert not (backup_root / store.LOCK_NAME).exists()


def test_upgrade_refuses_a_revision_this_code_does_not_know(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    connection = sqlite3.connect(settings.database_url.removeprefix("sqlite:///"))
    try:
        connection.execute("UPDATE alembic_version SET version_num = '9999_from_the_future'")
        connection.commit()
    finally:
        connection.close()
    backup_root = tmp_path / "backups"

    result = run_ops(["upgrade"], settings, backup_root)

    assert result.returncode == 1
    outcome = payload(result)
    assert outcome["status"] == "failed"
    assert outcome["stage"] == "preflight"
    assert "unknown" in outcome["error"] or "newer" in outcome["error"]
    assert current_revision(settings) == "9999_from_the_future"
    assert not list(backup_root.glob("*T*Z-*"))


def test_upgrade_refuses_an_unreachable_database(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    backup_root = tmp_path / "backups"

    result = run_ops(
        ["upgrade"],
        settings,
        backup_root,
        extra_env={
            "ITSM_DATABASE_URL": f"postgresql+psycopg://itsm:{LIVE_PASSWORD}@127.0.0.1:1/itsm"
        },
    )

    assert result.returncode == 1
    outcome = payload(result)
    assert outcome["status"] == "failed"
    assert outcome["stage"] == "preflight"
    assert LIVE_PASSWORD not in result.stdout + result.stderr
    assert "127.0.0.1:1" in outcome["error"]
    assert not list(backup_root.glob("*T*Z-*"))


def test_upgrade_refuses_without_free_space_for_a_backup(
    settings_factory: Callable[..., Settings], tmp_path: Path, monkeypatch
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    backup_root = tmp_path / "backups"
    context = service.OpsContext(settings=settings, backup_root=backup_root)
    monkeypatch.setattr(
        upgrade.shutil, "disk_usage", lambda _path: type("Usage", (), {"free": 1024})()
    )

    outcome = upgrade.run_upgrade(context)

    assert outcome.exit_code == 1
    assert outcome.payload["stage"] == "preflight"
    assert "space" in outcome.payload["error"]
    assert current_revision(settings) == EARLIER_REVISION
    assert not list(backup_root.glob("*T*Z-*"))


def test_upgrade_refuses_a_broken_backup_root_and_preserves_the_database(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    broken_root = tmp_path / "unwritable"
    broken_root.write_text("not a directory")
    context = service.OpsContext(settings=settings, backup_root=broken_root)

    outcome = upgrade.run_upgrade(context)

    assert outcome.exit_code == 1
    assert outcome.payload["stage"] == "preflight"
    assert "not a directory" in outcome.payload["error"]
    assert "data preserved" in outcome.payload["message"]
    assert current_revision(settings) == EARLIER_REVISION


def partial_migration(settings: Settings) -> Callable[[], None]:
    """A migration that commits one DDL statement and then fails."""
    database = settings.database_url.removeprefix("sqlite:///")

    def apply() -> None:
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE probe_partial (id INTEGER PRIMARY KEY)")
            connection.commit()
        finally:
            connection.close()
        raise RuntimeError("injected failure after the first DDL statement")

    return apply


def test_a_partially_applied_migration_is_detected_and_a_silent_rerun_is_refused(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    backup_root = tmp_path / "backups"
    context = service.OpsContext(settings=settings, backup_root=backup_root)

    first = upgrade.run_upgrade(context, apply_migrations=partial_migration(settings))

    assert first.exit_code == 1
    assert first.payload["stage"] == "migration"
    assert first.payload["schemaStatus"] == "partial"
    assert "probe_partial" in table_names(settings)

    # A plain re-run would fail on "table probe_partial already exists" and hide
    # the real state, so it must be refused with the restore instruction.
    second = upgrade.run_upgrade(context)

    assert second.exit_code == 1
    assert second.payload["stage"] == "preflight"
    assert second.payload["schemaStatus"] == "partial"
    assert "partial" in second.payload["error"]
    assert first.payload["backupId"] in second.payload["error"]
    assert "--replace-live" in second.payload["error"]
    assert current_revision(settings) == EARLIER_REVISION
    assert marker_rows(settings) == 4
    assert len(list(backup_root.glob("*T*Z-*"))) == 1

    status = payload(run_ops(["status"], settings, backup_root))
    assert status["upgradeAttempt"]["schemaStatus"] == "partial"


def test_restoring_the_pre_upgrade_backup_clears_the_partial_state(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = database_at_earlier_revision(settings_factory)
    backup_root = tmp_path / "backups"
    context = service.OpsContext(settings=settings, backup_root=backup_root)
    first = upgrade.run_upgrade(context, apply_migrations=partial_migration(settings))
    assert first.payload["schemaStatus"] == "partial"
    database = settings.database_url.removeprefix("sqlite:///")

    restored = run_ops(
        [
            "restore",
            first.payload["backupId"],
            "--target-file",
            database,
            "--replace-live",
            "--confirm",
            first.payload["backupId"],
        ],
        settings,
        backup_root,
    )

    assert restored.returncode == 0, restored.stdout + restored.stderr
    assert "probe_partial" not in table_names(settings)
    retry = run_ops(["upgrade"], settings, backup_root)
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert payload(retry)["status"] == "upgraded"
    assert payload(run_ops(["status"], settings, backup_root))["upgradeAttempt"] is None
