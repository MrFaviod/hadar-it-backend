"""Portable SQLite primitives shared by the core dump and the extension archives.

``sqlite3.Connection.backup`` is the only online-safe way to read a database
that may be in WAL mode with uncheckpointed writes, so the core dump and every
extension data file go through it. The rest of the module is read-only:
integrity checks and revision/row snapshots never write to the file they read.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from itsm.ops.engines import OpsError


def uri(path: Path, *, read_only: bool) -> str:
    """Return a SQLite URI for one file, optionally opened read-only."""
    suffix = "?mode=ro" if read_only else ""
    return f"file:{path.expanduser().resolve().as_posix()}{suffix}"


def snapshot(path: Path) -> dict[str, Any] | None:
    """Read revision and row totals from a SQLite file without creating it."""
    if not path.is_file():
        return None
    connection = sqlite3.connect(uri(path, read_only=True), uri=True)
    try:
        revision: str | None = None
        try:
            row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
            revision = None if row is None else str(row[0])
        except sqlite3.Error:
            revision = None
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        rows = 0
        for table in tables:
            quoted = table.replace('"', '""')
            rows += int(connection.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0])
    finally:
        connection.close()
    return {"revision": revision, "tables": len(tables), "rows": rows}


def integrity(path: Path) -> str:
    """Return ``ok`` or ``failed`` for one SQLite file, never writing to it."""
    if not path.is_file():
        return "failed"
    try:
        connection = sqlite3.connect(uri(path, read_only=True), uri=True)
    except sqlite3.Error:
        return "failed"
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error:
        return "failed"
    finally:
        connection.close()
    return "ok" if row is not None and str(row[0]).lower() == "ok" else "failed"


def copy_online(source_path: Path, destination: Path, *, label: str = "sqlite") -> None:
    """Copy one SQLite database through the online backup API and check the copy."""
    if not source_path.is_file():
        raise OpsError(f"sqlite database file not found: {source_path}")
    source = sqlite3.connect(uri(source_path, read_only=True), uri=True)
    destination_connection = sqlite3.connect(str(destination))
    try:
        source.backup(destination_connection)
        destination_connection.execute("PRAGMA journal_mode=DELETE")
        destination_connection.commit()
    except sqlite3.Error as exc:
        raise OpsError(f"{label} online backup failed: {exc}") from exc
    finally:
        destination_connection.close()
        source.close()
    if integrity(destination) != "ok":
        raise OpsError(f"{label} backup failed the integrity check")
