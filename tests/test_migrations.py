"""Alembic infrastructure migration through the explicit CLI."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from itsm.config import Settings
from sqlalchemy import create_engine, inspect
from tests.conftest import BACKEND_ROOT, run_cli, run_migrations


def test_upgrade_creates_infrastructure_table_and_records_revision(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()

    result = run_migrations(settings)

    assert result.returncode == 0, result.stderr
    engine = create_engine(settings.database_url)
    try:
        inspector = inspect(engine)
        assert inspector.has_table("itsm_infrastructure")
        columns = {column["name"] for column in inspector.get_columns("itsm_infrastructure")}
        assert {"id", "name", "value", "updated_at"} <= columns
        assert inspector.has_table("alembic_version")
    finally:
        engine.dispose()


def test_upgrade_is_idempotent(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0

    second = run_migrations(settings)

    assert second.returncode == 0, second.stderr


def test_current_revision_matches_the_single_head(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0

    current = run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), "current"],
        settings,
    )
    heads = run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), "heads"],
        settings,
    )

    assert current.returncode == 0, current.stderr
    assert heads.returncode == 0, heads.stderr
    head_revision = heads.stdout.strip().split()[0]
    assert head_revision in current.stdout
    assert " (head)" in heads.stdout


def probe_migrations_ini(tmp_path: Path) -> Path:
    """Copy the migration tree and add one probe revision after the real head."""
    import shutil

    migrations = tmp_path / "probe-migrations"
    shutil.copytree(BACKEND_ROOT / "migrations", migrations)
    ini = tmp_path / "probe-alembic.ini"
    ini.write_text(
        "[alembic]\n"
        f"script_location = {migrations}\n"
        f"prepend_sys_path = {BACKEND_ROOT}\n"
        "path_separator = os\n"
    )
    return ini


def write_probe_revision(tmp_path: Path, name: str, body: str) -> None:
    versions = tmp_path / "probe-migrations" / "versions"
    # Chain after whatever the tree's current head is: a new migration must not
    # turn the probe into a second head and crash every other migration test.
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(
        Config(str(tmp_path / "probe-alembic.ini"))
    ).get_current_head()
    assert head
    (versions / f"0099_{name}.py").write_text(
        '"""Probe revision (test only)."""\n\n'
        "from alembic import op\n\n"
        'revision = "0099_probe"\n'
        f'down_revision = "{head}"\n'
        "branch_labels = None\n"
        "depends_on = None\n\n\n"
        f"def upgrade() -> None:\n{body}\n\n\n"
        "def downgrade() -> None:\n"
        "    pass\n"
    )


def sqlite_state(database_url: str) -> tuple[set[str], str]:
    import sqlite3

    path = database_url.removeprefix("sqlite:///")
    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    finally:
        connection.close()
    assert row is not None
    return tables, str(row[0])


def test_a_failed_sqlite_revision_rolls_back_its_ddl(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    ini = probe_migrations_ini(tmp_path)
    write_probe_revision(
        tmp_path,
        "failing",
        '    op.execute("CREATE TABLE probe_partial (id INTEGER PRIMARY KEY)")\n'
        '    raise RuntimeError("injected DDL failure")',
    )

    result = run_cli(["-m", "alembic", "-c", str(ini), "upgrade", "head"], settings)

    assert result.returncode != 0
    assert "injected DDL failure" in result.stderr
    tables, revision = sqlite_state(settings.database_url)
    assert "probe_partial" not in tables
    assert "itsm_infrastructure" in tables
    assert revision == "0037_extension_core_call_principal"


def test_a_successful_sqlite_revision_commits_its_ddl(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = settings_factory()
    ini = probe_migrations_ini(tmp_path)
    write_probe_revision(
        tmp_path,
        "succeeding",
        '    op.execute("CREATE TABLE probe_complete (id INTEGER PRIMARY KEY)")',
    )

    result = run_cli(["-m", "alembic", "-c", str(ini), "upgrade", "head"], settings)

    assert result.returncode == 0, result.stderr
    tables, revision = sqlite_state(settings.database_url)
    assert "probe_complete" in tables
    assert revision == "0099_probe"


def set_recorded_revision(database_url: str, revision: str) -> None:
    import sqlite3

    connection = sqlite3.connect(database_url.removeprefix("sqlite:///"))
    try:
        connection.execute("UPDATE alembic_version SET version_num = ?", (revision,))
        connection.commit()
    finally:
        connection.close()


def test_business_routes_are_refused_while_migrations_are_pending(
    settings_factory: Callable[..., Settings],
    client: Callable[..., object],
    monkeypatch,
) -> None:
    monkeypatch.setattr("itsm.main.SCHEMA_REVALIDATE_SECONDS", 0.0)
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    set_recorded_revision(settings.database_url, "0035_extension_isolation")

    test_client = client(settings)

    refused = test_client.get("/api/v1/assets")
    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "database_not_migrated"
    assert "python -m itsm.ops upgrade" in refused.json()["error"]["message"]
    ready = test_client.get("/api/v1/health/ready")
    assert ready.status_code == 503
    assert ready.json()["checks"]["migrations"] == "pending"

    set_recorded_revision(settings.database_url, "0037_extension_core_call_principal")

    served = test_client.get("/api/v1/assets")
    assert served.status_code in {401, 403}


def _head_revision(tmp_path: Path) -> str:
    """The tree's current head without the probe revision, for re-run assertions."""

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    versions = ScriptDirectory.from_config(Config(str(tmp_path / "probe-alembic.ini")))
    heads = [head for head in versions.get_heads() if head != "0099_probe"]
    assert len(heads) == 1, heads
    return heads[0]
