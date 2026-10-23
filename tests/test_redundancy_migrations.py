"""Redundancy migration: additive tables, retained data, single head and idempotence."""

from __future__ import annotations

from collections.abc import Callable

from itsm.config import Settings
from sqlalchemy import create_engine, inspect, text
from tests.conftest import BACKEND_ROOT, run_cli, run_migrations

SettingsFactory = Callable[..., Settings]

ASSET_ID = "44444444-4444-4444-8444-444444444444"
HOST_ID = "55555555-5555-4555-8555-555555555555"
RELATIONSHIP_ID = "66666666-6666-4666-8666-666666666666"
PRE_REDUNDANCY = "0009_asset_directory"
HEAD = "0012_workflows"


def alembic(settings: Settings, *arguments: str) -> object:
    return run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), *arguments],
        settings,
    )


def test_fresh_schema_creates_portable_group_and_member_tables(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr

    engine = create_engine(settings.database_url)
    try:
        inspector = inspect(engine)
        assert {"redundancy_groups", "redundancy_group_members"} <= set(inspector.get_table_names())
        groups = {column["name"]: column for column in inspector.get_columns("redundancy_groups")}
        assert set(groups) == {
            "id",
            "name",
            "description",
            "mode",
            "active",
            "created_at",
            "updated_at",
        }
        assert groups["description"]["nullable"] is True
        members = {
            column["name"]: column for column in inspector.get_columns("redundancy_group_members")
        }
        assert set(members) == {
            "id",
            "group_id",
            "asset_id",
            "role",
            "share",
            "created_at",
            "updated_at",
        }
        assert members["role"]["nullable"] is True
        assert members["share"]["nullable"] is True
        assert {
            "ix_redundancy_groups_active",
        } <= {index["name"] for index in inspector.get_indexes("redundancy_groups")}
        assert {
            "ix_redundancy_group_members_asset",
        } <= {index["name"] for index in inspector.get_indexes("redundancy_group_members")}
        foreign_keys = inspector.get_foreign_keys("redundancy_group_members")
        assert {tuple(foreign_key["constrained_columns"]) for foreign_key in foreign_keys} == {
            ("group_id",),
            ("asset_id",),
        }
        assert {foreign_key["referred_table"] for foreign_key in foreign_keys} == {
            "redundancy_groups",
            "assets",
        }
        unique = inspector.get_unique_constraints("redundancy_group_members")
        assert {tuple(item["column_names"]) for item in unique} == {("group_id", "asset_id")}
    finally:
        engine.dispose()


def test_pre_redundancy_data_is_retained_and_no_group_is_seeded(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()
    before = alembic(settings, "upgrade", PRE_REDUNDANCY)
    assert before.returncode == 0, before.stderr

    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            for asset_id, code in ((ASSET_ID, "MIG-001"), (HOST_ID, "MIG-HOST")):
                connection.execute(
                    text(
                        "INSERT INTO assets "
                        "(id, quick_code, quick_code_key, name, status, created_at, updated_at) "
                        "VALUES (:id, :code, :key, :name, 'in_use', :now, :now)"
                    ),
                    {
                        "id": asset_id,
                        "code": code,
                        "key": code.lower(),
                        "name": f"Equipo {code}",
                        "now": "2026-04-01 09:00:00+00:00",
                    },
                )
            connection.execute(
                text(
                    "INSERT INTO relationships "
                    "(id, type_key, source_id, target_id, created_at, updated_at) "
                    "VALUES (:id, 'hosted_in', :source, :target, :now, :now)"
                ),
                {
                    "id": RELATIONSHIP_ID,
                    "source": ASSET_ID,
                    "target": HOST_ID,
                    "now": "2026-04-01 09:00:00+00:00",
                },
            )
    finally:
        engine.dispose()

    upgraded = run_migrations(settings)
    assert upgraded.returncode == 0, upgraded.stderr

    engine = create_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM assets WHERE id IN (:a, :h)"),
                    {"a": ASSET_ID, "h": HOST_ID},
                ).scalar_one()
                == 2
            )
            placement = connection.execute(
                text("SELECT source_id, target_id, type_key FROM relationships WHERE id = :id"),
                {"id": RELATIONSHIP_ID},
            ).one()
            assert placement == (ASSET_ID, HOST_ID, "hosted_in")
            assert (
                connection.execute(text("SELECT COUNT(*) FROM redundancy_groups")).scalar_one() == 0
            )
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM redundancy_group_members")
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()


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
