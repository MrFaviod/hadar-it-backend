"""Opt-in live engine coverage for PostgreSQL and MariaDB/MySQL.

These tests only run when a disposable database URL is exported. They never
point at a shared service: the URL is the whole target, the restore creates a
sibling database and drops it again. Each database receives its own marker
table, so the backup/restore mechanism is exercised even when a migration step
is not applicable to that engine. Stages that cannot run in the current
environment (missing client tool, client/server major mismatch) are skipped
with an explicit reason instead of being reported as verified.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from itsm.config import Settings, settings_for
from itsm.database import migration_head
from itsm.ops import service
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from tests.conftest import run_migrations

ENGINE_VARIABLES = ["ITSM_TEST_IDENTITY_POSTGRES_URL", "ITSM_TEST_IDENTITY_MARIADB_URL"]
MARKER_ROWS = 3


@pytest.fixture(params=ENGINE_VARIABLES, ids=["postgresql", "mariadb"])
def live_engine(request: pytest.FixtureRequest) -> tuple[str, str]:
    url = os.environ.get(request.param, "").strip()
    if not url:
        pytest.skip(f"{request.param} not configured: live engine not validated")
    engine = "postgresql" if url.startswith("postgresql") else "mysql"
    required = ("pg_dump", "pg_restore") if engine == "postgresql" else ("mysqldump",)
    missing = [tool for tool in required if not shutil.which(tool)]
    if missing:
        pytest.skip(f"{', '.join(missing)} not installed: live {engine} backup not validated")
    return engine, url


def prepare_database(url: str) -> str | None:
    """Migrate when possible, add marker rows, and report the applied revision."""
    settings: Settings = settings_for(database_url=url)
    revision: str | None = None
    applied = run_migrations(settings)
    if applied.returncode == 0:
        revision = migration_head(settings)
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS ops_live_marker"))
            connection.execute(
                text("CREATE TABLE ops_live_marker (id INTEGER PRIMARY KEY, value VARCHAR(32))")
            )
            for index in range(MARKER_ROWS):
                connection.execute(
                    text("INSERT INTO ops_live_marker (id, value) VALUES (:id, :value)"),
                    {"id": index + 1, "value": f"row-{index}"},
                )
    finally:
        engine.dispose()
    return revision


def marker_rows(url: str) -> int:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return int(
                connection.execute(text("SELECT COUNT(*) FROM ops_live_marker")).scalar_one()
            )
    finally:
        engine.dispose()


def server_major(url: str) -> int | None:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            version = str(connection.exec_driver_sql("SELECT version()").scalar_one())
    finally:
        engine.dispose()
    match = re.search(r"(\d+)\.\d+", version)
    return int(match.group(1)) if match else None


def client_major(tool: str) -> int | None:
    completed = subprocess.run([tool, "--version"], capture_output=True, text=True, check=False)
    match = re.search(r"(\d+)\.\d+", completed.stdout or completed.stderr)
    return int(match.group(1)) if match else None


@pytest.fixture
def backup_root(tmp_path: Path) -> Path:
    return tmp_path / "backups"


def test_live_engine_backup_verify_and_status(
    live_engine: tuple[str, str], backup_root: Path
) -> None:
    engine_name, url = live_engine
    settings: Settings = settings_for(database_url=url)
    revision = prepare_database(url)
    context = service.OpsContext(settings=settings, backup_root=backup_root)

    artifact = service.backup(context)

    assert artifact.manifest.engine == engine_name
    if revision is None:
        # A migration step that this engine rejects (MariaDB rejects the 0028
        # CHECK on an AUTO_INCREMENT column) leaves the schema unmanaged; the
        # dump mechanism is still validated, only the revision is not head.
        assert artifact.manifest.alembic_revision != migration_head(settings)
    else:
        assert artifact.manifest.alembic_revision == revision
    assert artifact.manifest.size > 0
    assert artifact.manifest.tool_versions
    assert all(value != "unavailable" for value in artifact.manifest.tool_versions.values())
    assert (artifact.dump_path.stat().st_mode & 0o777) == 0o600

    checked = service.verify(context, artifact.manifest.id)
    assert checked["verified"] is True, checked
    assert checked["checks"]["integrity"] == "ok"

    reported = service.status(context)
    assert reported["engine"] == engine_name
    assert reported["lastBackup"]["verified"] is True
    assert reported["backupCount"] == 1


def test_live_engine_restore_into_a_new_database(
    live_engine: tuple[str, str], backup_root: Path
) -> None:
    engine_name, url = live_engine
    client_tools = ("mysql", "mariadb") if engine_name == "mysql" else ("pg_restore",)
    if not any(shutil.which(tool) for tool in client_tools):
        pytest.skip(f"{engine_name} restore client not installed: restore not validated live")
    if engine_name == "postgresql":
        dump_major, restore_major = client_major("pg_dump"), client_major("pg_restore")
        target_major = server_major(url)
        if (
            dump_major is not None
            and target_major is not None
            and restore_major is not None
            and min(dump_major, restore_major) > target_major
        ):
            pytest.skip(
                f"pg_dump/pg_restore {dump_major}.x is newer than the {target_major}.x server: "
                "PostgreSQL cannot restore that archive into an older server major"
            )
    settings: Settings = settings_for(database_url=url)
    revision = prepare_database(url)
    context = service.OpsContext(settings=settings, backup_root=backup_root)
    artifact = service.backup(context)
    assert service.verify(context, artifact.manifest.id)["verified"] is True

    parsed = make_url(url)
    # MariaDB has no administrative database to connect to; the existing
    # database is a valid session and CREATE DATABASE only needs the privilege.
    admin_database = "postgres" if engine_name == "postgresql" else parsed.database
    quote = '"' if engine_name == "postgresql" else "`"
    target_database = f"itsm_ops_restore_{artifact.manifest.id.rsplit('-', 1)[-1]}"
    admin = create_engine(parsed.set(database=admin_database), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text(f"CREATE DATABASE {quote}{target_database}{quote}"))
    except Exception as exc:
        admin.dispose()
        pytest.skip(f"cannot create a disposable restore database: {exc}")
    try:
        restored = service.restore(context, artifact.manifest.id, target_database=target_database)
        target_url = parsed.set(database=target_database).render_as_string(hide_password=False)
        assert restored["engine"] == engine_name
        assert restored["live"] is False
        assert marker_rows(target_url) == MARKER_ROWS
        if revision is not None:
            assert restored["restored"]["revision"] == revision
            assert marker_rows(url) == MARKER_ROWS
    finally:
        with admin.connect() as connection:
            connection.execute(text(f"DROP DATABASE IF EXISTS {quote}{target_database}{quote}"))
        admin.dispose()
