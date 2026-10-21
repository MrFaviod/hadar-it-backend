"""Alembic infrastructure migration through the explicit CLI."""

from __future__ import annotations

from collections.abc import Callable

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
