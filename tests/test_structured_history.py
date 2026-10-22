"""Additive structured history: migration backfill and portable schema checks."""

from __future__ import annotations

from collections.abc import Callable

from itsm.config import Settings
from sqlalchemy import create_engine, inspect, text
from tests.conftest import BACKEND_ROOT, run_cli, run_migrations

SettingsFactory = Callable[..., Settings]

ASSET_ID = "11111111-1111-1111-1111-111111111111"
HISTORY_ID = "22222222-2222-2222-2222-222222222222"


def test_upgrade_0007_adds_structured_history_and_relationship_tables(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0

    engine = create_engine(settings.database_url)
    try:
        inspector = inspect(engine)
        history_columns = {column["name"] for column in inspector.get_columns("asset_history")}
        assert {
            "source",
            "entity_type",
            "entity_id",
            "effective_at",
            "notes",
        } <= history_columns

        assert inspector.has_table("relationship_types")
        assert inspector.has_table("relationships")
        relationship_columns = {column["name"] for column in inspector.get_columns("relationships")}
        assert {
            "id",
            "type_key",
            "source_id",
            "target_id",
            "reason",
            "notes",
            "effective_at",
            "created_at",
            "updated_at",
        } <= relationship_columns
        type_columns = {column["name"] for column in inspector.get_columns("relationship_types")}
        assert {"key", "forward_label", "inverse_label", "containment", "active"} <= type_columns
    finally:
        engine.dispose()


def test_existing_history_rows_are_backfilled_with_asset_entity_metadata(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()
    old = run_cli(
        [
            "-m",
            "alembic",
            "-c",
            str(BACKEND_ROOT / "alembic.ini"),
            "upgrade",
            "0006_inventory_codes",
        ],
        settings,
    )
    assert old.returncode == 0, old.stderr

    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO assets "
                    "(id, quick_code, quick_code_key, name, status, created_at, updated_at) "
                    "VALUES (:id, 'OLD-001', 'old-001', 'Equipo heredado', 'in_use', "
                    ":created, :created)"
                ),
                {"id": ASSET_ID, "created": "2026-01-01 10:00:00+00:00"},
            )
            connection.execute(
                text(
                    "INSERT INTO asset_history "
                    "(id, sequence, asset_id, action, changes, reason, actor_id, actor_username, "
                    "created_at) VALUES (:id, 1, :asset_id, 'updated', :changes, 'ajuste', "
                    "'actor-1', 'ana', :created)"
                ),
                {
                    "id": HISTORY_ID,
                    "asset_id": ASSET_ID,
                    "changes": '{"name": {"old": "Viejo", "new": "Equipo heredado"}}',
                    "created": "2026-01-02 11:00:00+00:00",
                },
            )
    finally:
        engine.dispose()

    migrated = run_migrations(settings)
    assert migrated.returncode == 0, migrated.stderr

    engine = create_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT source, entity_type, entity_id, effective_at, notes, changes, reason "
                    "FROM asset_history WHERE id = :id"
                ),
                {"id": HISTORY_ID},
            ).one()
    finally:
        engine.dispose()

    assert row.source == "internal"
    assert row.entity_type == "asset"
    assert row.entity_id == ASSET_ID
    assert row.effective_at is None
    assert row.notes is None
    assert '"new": "Equipo heredado"' in row.changes
    assert row.reason == "ajuste"
