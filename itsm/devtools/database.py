"""Database operations for the dev maintenance CLI (S3, S4).

Everything here works on reflected tables: the tool never drops a schema or a
server database that it did not create as a file. A plain reset keeps every
table and deletes application rows only; a regenerate deletes the SQLite file
(server engines drop the reflected tables) so migrations rebuild the schema.

The rows inserted by the migrations themselves are reference data (roles and
their policies, the inventory catalog, relationship types, notification and
report defaults, singleton settings and the code-sequence lock). They are kept
through a reset because the canonical installation path expects them, and the
canonical seed cannot recreate them: :data:`MIGRATION_REFERENCE_TABLES` records
them and ``tests/test_devtools_database.py`` fails when a migration seeds a new
table without updating that set.
"""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from sqlalchemy import Connection, Engine, MetaData, Table, func, select
from sqlalchemy.exc import SQLAlchemyError

from itsm.config import Settings
from itsm.database import MIGRATION_TABLE, alembic_config, database_file
from itsm.devtools.guard import DevToolsRefused
from itsm.logging import log_event

logger = logging.getLogger("itsm.devtools")

#: SQLite companion files that belong to one database file.
_SQLITE_SUFFIXES = ("-wal", "-shm", "-journal")

#: Tables whose rows are inserted by the migrations and are therefore part of a
#: freshly initialized schema, not application data. A reset preserves them.
#: Provenance: 0002 (roles, policies, settings), 0004 (inventory catalog),
#: 0006 (code sequence lock), 0007 (relationship types), 0017 (notification
#: defaults), 0021/0023/0024 (profiles and AI usage policy).
MIGRATION_REFERENCE_TABLES: frozenset[str] = frozenset(
    {
        "ai_usage_quota_policy",
        "identity_role_policies",
        "identity_roles",
        "i18n_registry_state",
        "identity_security_settings",
        "inventory_catalog",
        "inventory_code_sequences",
        "notification_channels",
        "notification_rules",
        "notification_runtime_state",
        "relationship_types",
    }
)


def migrate_to_head(settings: Settings) -> None:
    """Apply the canonical migrations to head; never a hidden auto-migration."""
    try:
        with _database_url(settings.database_url):
            command.upgrade(alembic_config(settings), "head")
    except Exception as exc:
        raise DevToolsRefused(
            f"migration to head failed ({type(exc).__name__}); next: re-run with --verbose "
            "and inspect the migration error"
        ) from exc
    log_event(logger, "devtools.migrations.applied", database=settings.safe_database_url())


@contextmanager
def _database_url(url: str) -> Iterator[None]:
    """Point the shared Alembic environment at this settings URL and restore it."""
    previous = os.environ.get("ITSM_DATABASE_URL")
    os.environ["ITSM_DATABASE_URL"] = url
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("ITSM_DATABASE_URL", None)
        else:
            os.environ["ITSM_DATABASE_URL"] = previous


def table_counts(engine: Engine) -> dict[str, int]:
    """Count the rows of every reflected application table."""
    metadata = _reflected(engine)
    counts: dict[str, int] = {}
    with engine.connect() as connection:
        for name in sorted(metadata.tables):
            if name == MIGRATION_TABLE:
                continue
            table = metadata.tables[name]
            counts[name] = int(
                connection.execute(select(func.count()).select_from(table)).scalar_one()
            )
    return counts


def clear_tables(engine: Engine) -> list[str]:
    """Delete the application rows, keeping the schema and the reference rows (reset).

    Rows are deleted children-first (the reverse of the reflected dependency
    order), so the delete is valid with foreign keys enforced and no pragma or
    engine-specific hint is needed.
    """
    metadata = _reflected(engine)
    tables = _application_tables(metadata)
    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            _delete_rows(connection, tables)
        else:
            _truncate_tables(connection, tables)
    names = [table.name for table in tables]
    log_event(logger, "devtools.tables.cleared", tables=len(names))
    return names


def drop_tables(engine: Engine) -> list[str]:
    """Drop every reflected table so migrations can recreate the database (regenerate)."""
    metadata = _reflected(engine)
    names = sorted(metadata.tables)
    try:
        metadata.drop_all(bind=engine, checkfirst=True)
    except SQLAlchemyError as exc:
        raise DevToolsRefused(
            f"dropping the reflected tables failed ({type(exc).__name__}); next: re-run "
            "with --verbose and inspect the database error"
        ) from exc
    log_event(logger, "devtools.tables.dropped", tables=len(names))
    return names


def delete_sqlite_file(settings: Settings) -> str:
    """Delete the configured SQLite database file and its companion journal files."""
    path = database_file(settings)
    if path is None:
        raise DevToolsRefused(
            "regenerate needs a sqlite file database; next: recreate the schema through "
            "reset against a server engine instead"
        )
    resolved = path if path.is_absolute() else (Path.cwd() / path).resolve()
    for candidate in (resolved, *(Path(f"{resolved}{suffix}") for suffix in _SQLITE_SUFFIXES)):
        try:
            candidate.unlink()
        except FileNotFoundError:
            continue
    log_event(logger, "devtools.database.file_deleted", path=str(resolved))
    return str(resolved)


def clear_data_paths(paths: Sequence[Path]) -> list[str]:
    """Empty the attachment directories and delete the task queue files in ``paths``."""
    cleared: list[str] = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_symlink() or child.is_file():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
        else:
            for candidate in (path, *(Path(f"{path}{suffix}") for suffix in _SQLITE_SUFFIXES)):
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    continue
        cleared.append(str(path))
    if cleared:
        log_event(logger, "devtools.data_paths.cleared", paths=cleared)
    return cleared


def _reflected(engine: Engine) -> MetaData:
    metadata = MetaData()
    metadata.reflect(bind=engine)
    return metadata


def _application_tables(metadata: MetaData) -> list[Table]:
    return [
        table
        for table in metadata.sorted_tables
        if table.name != MIGRATION_TABLE and table.name not in MIGRATION_REFERENCE_TABLES
    ]


def _delete_rows(connection: Connection, tables: Sequence[Table]) -> None:
    for table in reversed(list(tables)):
        connection.execute(table.delete())


def _truncate_tables(connection: Connection, tables: Sequence[Table]) -> None:
    dialect = connection.dialect.name
    preparer = connection.dialect.identifier_preparer
    if dialect == "mysql":
        connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=0")
    try:
        for table in reversed(list(tables)):
            quoted = preparer.quote(table.name)
            if dialect == "postgresql":
                connection.exec_driver_sql(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE")
            elif dialect == "mysql":
                connection.exec_driver_sql(f"TRUNCATE TABLE {quoted}")
            else:
                connection.execute(table.delete())
    finally:
        if dialect == "mysql":
            connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=1")
