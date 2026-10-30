"""The preserved reference rows match what the migrations actually insert.

A plain ``reset`` keeps the schema and deletes application rows, but keeps the
rows the migrations inserted (roles, catalog, defaults). If a future migration
seeds a new table, that set must grow; this test fails instead of letting a
reset silently delete the new reference rows.
"""

from __future__ import annotations

from pathlib import Path

from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.devtools.database import MIGRATION_REFERENCE_TABLES, migrate_to_head, table_counts


def test_reference_tables_match_a_freshly_migrated_database(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'fresh.db'}",
    )
    migrate_to_head(settings)
    engine = create_engine_from_settings(settings)
    try:
        counts = table_counts(engine)
    finally:
        engine.dispose()

    assert {name for name, count in counts.items() if count} == set(MIGRATION_REFERENCE_TABLES)
