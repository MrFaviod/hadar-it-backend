"""Per-module SQLite storage shared by the host and the sandbox runner.

The file belongs to one extension: ``<root>/<id>/data.sqlite3``.  The core
database never stores module business rows.  ``_itsm_records`` is the managed
table behind the SDK ``store``; executable modules may also open their own
connection through ``context.db`` and manage additional tables inside the same
file.  This module is stdlib-only so the runner can import it under ``-I -S``.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:  # script mode (runner) and package mode (host) both resolve
    from protocol import ModuleError, StoreConflict, StoreValidation
except ImportError:  # pragma: no cover - imported as a package submodule
    from itsm.extensions.runtime.protocol import (
        ModuleError,
        StoreConflict,
        StoreValidation,
    )

RECORDS_TABLE = "_itsm_records"
DB_FILENAME = "data.sqlite3"
SNAPSHOT_DIRNAME = "snapshots"
MAX_RECORD_BYTES = 256 * 1024
MAX_PAGE = 200
MAX_OFFSET = 1_000_000
MAX_FILTERS = 20
ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
FILTER_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {RECORDS_TABLE} (
    collection TEXT NOT NULL,
    record_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (collection, record_id)
)
"""


def data_dir(root: Path, extension_id: str) -> Path:
    return Path(root) / extension_id


def database_path(root: Path, extension_id: str) -> Path:
    return data_dir(root, extension_id) / DB_FILENAME


def snapshots_dir(root: Path, extension_id: str) -> Path:
    return data_dir(root, extension_id) / SNAPSHOT_DIRNAME


def _secure(path: Path, mode: int) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


def prepare(root: Path, extension_id: str) -> Path:
    """Create ``<root>/<id>/data.sqlite3`` with private permissions and WAL."""
    directory = data_dir(root, extension_id)
    directory.mkdir(parents=True, exist_ok=True)
    _secure(directory, 0o700)
    Path(root).mkdir(parents=True, exist_ok=True)
    _secure(Path(root), 0o700)
    connection = connect(root, extension_id)
    connection.close()
    return directory


def connect(
    root: Path, extension_id: str, *, timeout: float = 5.0, wal: bool = True
) -> sqlite3.Connection:
    """Open the module file, creating the managed table when missing."""
    path = database_path(root, extension_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    _secure(path.parent, 0o700)
    connection = sqlite3.connect(str(path), timeout=timeout, isolation_level=None)
    if wal:
        connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute(_SCHEMA)
    connection.commit()
    _secure(path, 0o600)
    for suffix in ("-wal", "-shm"):
        companion = path.with_name(path.name + suffix)
        if companion.exists():
            _secure(companion, 0o600)
    return connection


def schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row else 0


def set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute(f"PRAGMA user_version={int(version)}")


def _record_id(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise StoreValidation("record id must be 1-64 characters")
    if any(char not in ID_CHARS for char in value):
        raise StoreValidation("record id contains unsupported characters")
    return value


def _collection(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise StoreValidation("collection must be 1-64 characters")
    if any(char not in ID_CHARS for char in value):
        raise StoreValidation("collection contains unsupported characters")
    return value


def _payload(row: tuple[Any, ...]) -> dict[str, Any]:
    return {"id": row[0], "version": int(row[1]), "data": json.loads(row[2])}


def get(connection: sqlite3.Connection, collection: Any, record_id: Any) -> dict[str, Any] | None:
    name = _collection(collection)
    key = _record_id(record_id)
    row = connection.execute(
        f"SELECT record_id, version, data FROM {RECORDS_TABLE} "
        "WHERE collection = ? AND record_id = ?",
        (name, key),
    ).fetchone()
    return None if row is None else _payload(row)


def list_records(
    connection: sqlite3.Connection,
    collection: Any,
    *,
    limit: Any = 50,
    offset: Any = 0,
    filters: Any = None,
) -> dict[str, Any]:
    name = _collection(collection)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE:
        raise StoreValidation("limit must be an integer between 1 and 200")
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_OFFSET:
        raise StoreValidation("offset must be an integer between 0 and 1000000")
    clauses = ["collection = ?"]
    parameters: list[Any] = [name]
    if filters is not None:
        if not isinstance(filters, Mapping):
            raise StoreValidation("filters must be an object")
        if len(filters) > MAX_FILTERS:
            raise StoreValidation("too many filters")
        for key, value in filters.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 64:
                raise StoreValidation("filter key must be 1-64 characters")
            if any(char not in FILTER_CHARS for char in key):
                raise StoreValidation("filter key contains unsupported characters")
            if value is None or isinstance(value, (dict, list)):
                raise StoreValidation("filter values must be scalar")
            clauses.append("json_extract(data, '$.' || ?) = ?")
            parameters.append(key)
            # json_extract turns JSON booleans into 0/1, so compare in that form.
            parameters.append(int(value) if isinstance(value, bool) else value)
    where = " AND ".join(clauses)
    total = connection.execute(
        f"SELECT COUNT(*) FROM {RECORDS_TABLE} WHERE {where}", tuple(parameters)
    ).fetchone()[0]
    rows = connection.execute(
        f"SELECT record_id, version, data FROM {RECORDS_TABLE} WHERE {where} "
        "ORDER BY record_id LIMIT ? OFFSET ?",
        tuple([*parameters, limit, offset]),
    ).fetchall()
    return {"items": [_payload(row) for row in rows], "total": int(total)}


def put(
    connection: sqlite3.Connection,
    collection: Any,
    record_id: Any,
    data: Any,
    expected_version: Any = None,
    *,
    data_version: int = 1,
) -> dict[str, Any]:
    name = _collection(collection)
    key = _record_id(record_id)
    if expected_version is not None and (
        not isinstance(expected_version, int) or isinstance(expected_version, bool)
    ):
        raise StoreValidation("expected_version must be an integer")
    if not isinstance(data, Mapping):
        raise StoreValidation("record data must be an object")
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
        raise StoreValidation("record data exceeds the size limit")
    now = _now()
    existing = connection.execute(
        f"SELECT version FROM {RECORDS_TABLE} WHERE collection = ? AND record_id = ?",
        (name, key),
    ).fetchone()
    insert = (
        f"INSERT INTO {RECORDS_TABLE} "
        "(collection, record_id, version, data, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    if existing is None:
        if expected_version not in (None, 0):
            raise StoreConflict("record version does not match")
        connection.execute(insert, (name, key, int(data_version), encoded, now, now))
        version = int(data_version)
    else:
        current = int(existing[0])
        if expected_version is not None and int(expected_version) != current:
            raise StoreConflict("record version does not match")
        cursor = connection.execute(
            f"UPDATE {RECORDS_TABLE} SET data = ?, version = ?, updated_at = ? "
            "WHERE collection = ? AND record_id = ? AND version = ?",
            (encoded, current + 1, now, name, key, current),
        )
        if cursor.rowcount != 1:
            raise StoreConflict("record version does not match")
        version = current + 1
    return {"id": key, "version": version, "data": json.loads(encoded)}


def delete(
    connection: sqlite3.Connection,
    collection: Any,
    record_id: Any,
    expected_version: Any = None,
) -> bool:
    name = _collection(collection)
    key = _record_id(record_id)
    if expected_version is None:
        cursor = connection.execute(
            f"DELETE FROM {RECORDS_TABLE} WHERE collection = ? AND record_id = ?",
            (name, key),
        )
    else:
        if not isinstance(expected_version, int) or isinstance(expected_version, bool):
            raise StoreValidation("expected_version must be an integer")
        cursor = connection.execute(
            f"DELETE FROM {RECORDS_TABLE} WHERE collection = ? AND record_id = ? AND version = ?",
            (name, key, int(expected_version)),
        )
    if cursor.rowcount != 1:
        raise StoreConflict("record version does not match or record is missing")
    return True


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


def snapshot(root: Path, extension_id: str, revision: int) -> Path:
    """Copy the module file with the SQLite backup API into ``snapshots/``."""
    directory = snapshots_dir(root, extension_id)
    directory.mkdir(parents=True, exist_ok=True)
    _secure(directory, 0o700)
    target = directory / f"{int(revision)}.sqlite3"
    source = connect(root, extension_id)
    destination = sqlite3.connect(str(target))
    try:
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()
    _secure(target, 0o600)
    return target


def restore(root: Path, extension_id: str, revision: int) -> bool:
    """Restore one snapshot over the live module file; False when absent."""
    source_path = snapshots_dir(root, extension_id) / f"{int(revision)}.sqlite3"
    if not source_path.is_file():
        return False
    target = database_path(root, extension_id)
    source = sqlite3.connect(str(source_path))
    destination = sqlite3.connect(str(target))
    try:
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()
    _secure(target, 0o600)
    return True


def snapshot_versions(root: Path, extension_id: str) -> list[tuple[int, int]]:
    """Return ``(revision, user_version)`` for every stored snapshot."""
    directory = snapshots_dir(root, extension_id)
    if not directory.is_dir():
        return []
    versions: list[tuple[int, int]] = []
    for path in directory.glob("*.sqlite3"):
        try:
            revision = int(path.stem)
        except ValueError:
            continue
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            versions.append((revision, schema_version(connection)))
        except sqlite3.DatabaseError:
            continue
        finally:
            connection.close()
    return sorted(versions)


def size_bytes(root: Path, extension_id: str) -> int:
    directory = data_dir(root, extension_id)
    if not directory.is_dir():
        return 0
    total = 0
    for path in directory.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


def discard(connection: sqlite3.Connection) -> None:
    """Roll back any open transaction on failure paths."""
    with contextlib.suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "DB_FILENAME",
    "MAX_RECORD_BYTES",
    "RECORDS_TABLE",
    "ModuleError",
    "connect",
    "data_dir",
    "database_path",
    "delete",
    "get",
    "list_records",
    "prepare",
    "put",
    "restore",
    "schema_version",
    "set_schema_version",
    "size_bytes",
    "snapshot",
    "snapshot_versions",
    "snapshots_dir",
]
