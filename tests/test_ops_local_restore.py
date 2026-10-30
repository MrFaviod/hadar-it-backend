"""Opt-in live backup -> verify -> new-database restore proof for the ops CLI.

This harness never starts, configures or cleans up a database server. It
consumes a disposable, isolated database URL supplied by the operator and drives
the public ``python -m itsm.ops`` commands exactly as
``docs/ops-backup-restore.md`` documents them. The operator is responsible for
providing matching client tools on ``PATH`` (for example wrappers that execute
``pg_dump``/``pg_restore`` inside an owned PostgreSQL container) because the
host client major must match the server major.

Without both the URL and the matching tools, the test skips with an explicit
reason. A skip is missing proof, never a pass.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

import pytest
from itsm.config import Settings, settings_for
from itsm.database import migration_head
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from tests.conftest import run_cli, run_migrations

# The S9 proof is pinned to the migration that introduced the demo cycle; a
# later head is acceptable, an older one means the proof predates it.
MINIMUM_HEAD = "0030_demo_cycle"
MARKER_TABLE = "ops_restore_marker"
MARKER_ROWS = 3
OPS_TIMEOUT_SECONDS = 300.0

ENGINE_CASES = [
    pytest.param(
        "postgresql",
        "ITSM_TEST_OPS_RESTORE_POSTGRES_URL",
        ("pg_dump", "pg_restore"),
        id="postgresql",
    ),
    pytest.param(
        "mysql",
        "ITSM_TEST_OPS_RESTORE_MARIADB_URL",
        ("mariadb-dump", "mysqldump"),
        id="mariadb",
    ),
]


def opt_in_url(variable: str) -> str:
    url = os.environ.get(variable, "").strip()
    if not url:
        pytest.skip(f"{variable} not configured: live ops restore not validated")
    return url


def require_client_tools(engine: str, candidates: tuple[str, ...]) -> None:
    """Skip when the engine client tools that match the server are unavailable."""
    if engine == "mysql":
        clients = ("mariadb", "mysql")
        dump_tool = next((tool for tool in candidates if shutil.which(tool)), None)
        client_tool = next((tool for tool in clients if shutil.which(tool)), None)
        if dump_tool is None or client_tool is None:
            pytest.skip(
                "mariadb-dump/mysqldump and mariadb/mysql clients are not on PATH: "
                "live MariaDB restore not validated"
            )
        return
    missing = [tool for tool in candidates if not shutil.which(tool)]
    if missing:
        pytest.skip(f"{', '.join(missing)} not on PATH: live {engine} backup/restore not validated")


def prepare_database(url: str) -> str:
    """Migrate through the explicit Alembic CLI, then seed marker rows."""
    settings: Settings = settings_for(database_url=url)
    completed = run_migrations(settings)
    assert completed.returncode == 0, completed.stderr
    revision = migration_head(settings)
    assert revision is not None
    assert revision >= MINIMUM_HEAD
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text(f"DROP TABLE IF EXISTS {MARKER_TABLE}"))
            connection.execute(
                text(f"CREATE TABLE {MARKER_TABLE} (id INTEGER PRIMARY KEY, value VARCHAR(32))")
            )
            for index in range(MARKER_ROWS):
                connection.execute(
                    text(f"INSERT INTO {MARKER_TABLE} (id, value) VALUES (:id, :value)"),
                    {"id": index + 1, "value": f"row-{index}"},
                )
    finally:
        engine.dispose()
    return revision


def database_revision(url: str) -> str | None:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()
    finally:
        engine.dispose()


def marker_rows(url: str) -> list[tuple[int, str]]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text(f"SELECT id, value FROM {MARKER_TABLE} ORDER BY id")
            ).all()
    finally:
        engine.dispose()
    return [(int(row[0]), str(row[1])) for row in rows]


def run_ops(settings: Settings, backup_root: Path, *arguments: str) -> dict[str, Any]:
    """Run one real ops CLI command and return its single JSON object."""
    completed = run_cli(
        ["-m", "itsm.ops", *arguments, "--backup-root", str(backup_root)],
        settings,
        timeout=OPS_TIMEOUT_SECONDS,
    )
    payload = completed.stdout or completed.stderr
    try:
        result: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - diagnostic path
        raise AssertionError(
            f"ops CLI did not emit JSON (exit {completed.returncode}): {payload!r}"
        ) from exc
    assert completed.returncode == 0, result
    assert result["status"] == "ok", result
    return result


def disposable_target_url(url: str, engine: str, database: str) -> str:
    parsed = make_url(url)
    return parsed.set(database=database).render_as_string(hide_password=False)


def admin_engine(url: str, engine: str) -> Engine:
    parsed = make_url(url)
    # MariaDB has no administrative database to reach; the existing database is
    # a valid session and CREATE DATABASE only needs the grant.
    database = "postgres" if engine == "postgresql" else parsed.database
    return create_engine(parsed.set(database=database), isolation_level="AUTOCOMMIT")


def live_engine(engine: str, variable: str, tools: tuple[str, ...]) -> tuple[str, str]:
    """Resolve one opt-in engine, skipping explicitly when prerequisites are absent."""
    url = opt_in_url(variable)
    require_client_tools(engine, tools)
    assert settings_for(database_url=url).database_url == url
    return engine, url


def backup_artifact(settings: Settings, backup_root: Path) -> tuple[str, dict[str, Any]]:
    """Create and verify one backup through the public CLI."""
    created = run_ops(settings, backup_root, "backup")
    manifest = created["backup"]
    identifier = str(manifest["id"])
    verified = run_ops(settings, backup_root, "verify", identifier)
    assert verified["verified"] is True, verified
    assert verified["checks"]["integrity"] == "ok", verified
    return identifier, manifest


@pytest.mark.parametrize("engine,url_variable,client_tools", ENGINE_CASES)
def test_ops_cli_backup_verify_and_status(
    engine: str, url_variable: str, client_tools: tuple[str, ...], tmp_path: Path
) -> None:
    engine_name, url = live_engine(engine, url_variable, client_tools)
    revision = prepare_database(url)
    settings: Settings = settings_for(database_url=url)
    backup_root = tmp_path / "backups"

    identifier, manifest = backup_artifact(settings, backup_root)

    assert manifest["engine"] == engine_name
    assert manifest["alembicRevision"] == revision
    assert manifest["size"] > 0
    assert manifest["toolVersions"]
    assert all(value != "unavailable" for value in manifest["toolVersions"].values())
    dump_path = Path(manifest["dumpFile"])
    artifact_directory = backup_root / identifier
    assert artifact_directory.is_dir()
    dump = artifact_directory / dump_path
    assert dump.is_file()
    assert (dump.stat().st_mode & 0o777) == 0o600

    reported = run_ops(settings, backup_root, "status")
    assert reported["engine"] == engine_name
    assert reported["lastBackup"]["verified"] is True
    assert reported["backupCount"] == 1

    print(
        json.dumps(
            {
                "engine": engine_name,
                "backup": identifier,
                "revision": manifest["alembicRevision"],
                "size": manifest["size"],
                "toolVersions": manifest["toolVersions"],
                "verified": True,
            },
            sort_keys=True,
        ),
        flush=True,
    )


@pytest.mark.parametrize("engine,url_variable,client_tools", ENGINE_CASES)
def test_ops_cli_restore_into_new_database(
    engine: str, url_variable: str, client_tools: tuple[str, ...], tmp_path: Path
) -> None:
    engine_name, url = live_engine(engine, url_variable, client_tools)
    revision = prepare_database(url)
    settings: Settings = settings_for(database_url=url)
    backup_root = tmp_path / "backups"
    source_rows = marker_rows(url)
    assert len(source_rows) == MARKER_ROWS

    identifier, _ = backup_artifact(settings, backup_root)

    target_database = f"ops_restore_{uuid.uuid4().hex[:8]}"
    quote = '"' if engine_name == "postgresql" else "`"
    admin = admin_engine(url, engine_name)
    with admin.connect() as connection:
        connection.execute(text(f"CREATE DATABASE {quote}{target_database}{quote}"))
    try:
        restored = run_ops(
            settings,
            backup_root,
            "restore",
            identifier,
            "--target-database",
            target_database,
        )
        assert restored["engine"] == engine_name
        assert restored["target"] == target_database
        assert restored["live"] is False
        assert restored["restored"]["revision"] == revision

        target_url = disposable_target_url(url, engine_name, target_database)
        assert database_revision(target_url) == revision
        restored_rows = marker_rows(target_url)
        assert restored_rows == source_rows
        assert len(restored_rows) == MARKER_ROWS

        # The source database is untouched by a restore into a new target.
        assert marker_rows(url) == source_rows
        assert database_revision(url) == revision

        print(
            json.dumps(
                {
                    "engine": engine_name,
                    "backup": identifier,
                    "target": target_database,
                    "targetRevision": revision,
                    "targetRows": restored_rows,
                    "sourceRevision": database_revision(url),
                    "sourceRows": len(marker_rows(url)),
                    "live": False,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    finally:
        with admin.connect() as connection:
            connection.execute(text(f"DROP DATABASE IF EXISTS {quote}{target_database}{quote}"))
        admin.dispose()
