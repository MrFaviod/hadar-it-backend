"""Phase 5 asset organization migration: additive, portable, single-head, idempotent."""

from __future__ import annotations

from collections.abc import Callable

from itsm.config import Settings
from sqlalchemy import create_engine, inspect, text
from tests.conftest import BACKEND_ROOT, run_cli, run_migrations

SettingsFactory = Callable[..., Settings]

ASSET_ID = "33333333-3333-3333-3333-333333333333"
PRE_PHASE5 = "0008_directory_relationships"
HEAD = "0009_asset_directory"

ORGANIZATION_COLUMNS = {
    "site_id",
    "location_id",
    "responsible_person_id",
    "position_x",
    "position_y",
}
ORGANIZATION_INDEXES = {
    "ix_assets_site_id",
    "ix_assets_location_id",
    "ix_assets_responsible_person",
}


def alembic(settings: Settings, *arguments: str) -> object:
    return run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), *arguments],
        settings,
    )


def test_fresh_schema_adds_nullable_asset_organization_columns(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr

    engine = create_engine(settings.database_url)
    try:
        inspector = inspect(engine)
        columns = {column["name"]: column for column in inspector.get_columns("assets")}
        assert set(columns) >= ORGANIZATION_COLUMNS
        for name in ORGANIZATION_COLUMNS:
            assert columns[name]["nullable"] is True
        indexes = {index["name"] for index in inspector.get_indexes("assets")}
        assert indexes >= ORGANIZATION_INDEXES
    finally:
        engine.dispose()


def test_pre_phase5_rows_keep_legacy_text_and_gain_null_references(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()
    before = alembic(settings, "upgrade", PRE_PHASE5)
    assert before.returncode == 0, before.stderr

    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO assets "
                    "(id, quick_code, quick_code_key, name, site, location, responsible, "
                    "status, created_at, updated_at) "
                    "VALUES (:id, 'LEG-001', 'leg-001', 'Equipo heredado', "
                    "'Sede Central', 'Piso 2 - Rack A', 'Matriz NOC', 'in_use', "
                    ":created, :created)"
                ),
                {"id": ASSET_ID, "created": "2026-03-01 08:00:00+00:00"},
            )
    finally:
        engine.dispose()

    upgraded = run_migrations(settings)
    assert upgraded.returncode == 0, upgraded.stderr

    engine = create_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT site, location, responsible, site_id, location_id, "
                    "responsible_person_id, position_x, position_y "
                    "FROM assets WHERE id = :id"
                ),
                {"id": ASSET_ID},
            ).one()
    finally:
        engine.dispose()

    assert row.site == "Sede Central"
    assert row.location == "Piso 2 - Rack A"
    assert row.responsible == "Matriz NOC"
    assert row.site_id is None
    assert row.location_id is None
    assert row.responsible_person_id is None
    assert row.position_x is None
    assert row.position_y is None


def test_single_head_and_repeated_upgrade_is_a_no_op(settings_factory: SettingsFactory) -> None:
    settings = settings_factory()
    heads = alembic(settings, "heads")
    assert heads.returncode == 0, heads.stderr
    assert heads.stdout.strip().split()[0] == HEAD

    first = run_migrations(settings)
    assert first.returncode == 0, first.stderr
    second = run_migrations(settings)
    assert second.returncode == 0, second.stderr
    assert "Running upgrade" not in second.stderr
