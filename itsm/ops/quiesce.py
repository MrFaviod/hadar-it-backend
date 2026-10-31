"""Runtime quiesce markers: a restore must not run over a live database.

The API and the worker register a marker next to a SQLite database file when
they start and remove it when they stop. A live restore refuses to replace a
database that a running process still holds: replacing the file under a live
process only makes that process write to an unlinked inode, so its acknowledged
writes vanish without any error. External engines keep their own connection
locks and are not covered by markers; their live restore stays behind the
explicit ``--replace-live --confirm`` consent and the documented stop order.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from itsm.config import Settings
from itsm.ops import engines

RUNTIME_DIR_SUFFIX = ".runtime"
_DIR_MODE = 0o700
_FILE_MODE = 0o600
_BUSY_TIMEOUT_SECONDS = 0.2


def database_file(settings: Settings) -> Path | None:
    try:
        target = engines.database_target(settings.database_url)
    except engines.OpsError:
        return None
    if target.engine != "sqlite":
        return None
    return Path(target.database)


def runtime_directory(settings: Settings) -> Path | None:
    path = database_file(settings)
    if path is None:
        return None
    return path.with_name(path.name + RUNTIME_DIR_SUFFIX)


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def register(settings: Settings, role: str) -> Path | None:
    """Mark this process as using the database; returns the marker to release."""
    directory = runtime_directory(settings)
    if directory is None:
        return None
    try:
        directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        marker = directory / f"{role}-{os.getpid()}.json"
        marker.write_text(json.dumps({"pid": os.getpid(), "role": role}))
        os.chmod(marker, _FILE_MODE)
    except OSError:
        return None
    return marker


def release(marker: Path | None) -> None:
    if marker is None:
        return
    with contextlib.suppress(OSError):
        marker.unlink()


def holders(settings: Settings) -> list[dict[str, Any]]:
    """Return the live processes using this database; stale markers are removed."""
    directory = runtime_directory(settings)
    if directory is None or not directory.is_dir():
        return []
    found: list[dict[str, Any]] = []
    with contextlib.suppress(OSError):
        for marker in sorted(directory.glob("*.json")):
            try:
                data = json.loads(marker.read_text())
            except OSError, ValueError:
                continue
            pid = data.get("pid") if isinstance(data, dict) else None
            role = data.get("role") if isinstance(data, dict) else None
            if isinstance(pid, int) and _process_alive(pid):
                found.append({"pid": pid, "role": str(role or "unknown")})
                continue
            with contextlib.suppress(OSError):
                marker.unlink()
    return found


def database_busy(settings: Settings) -> bool:
    """True when another connection holds the SQLite file exclusively."""
    path = database_file(settings)
    if path is None or not path.is_file():
        return False
    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=rw", uri=True, timeout=_BUSY_TIMEOUT_SECONDS
        )
    except sqlite3.Error:
        return False
    try:
        connection.execute("BEGIN EXCLUSIVE")
        connection.rollback()
    except sqlite3.OperationalError:
        return True
    finally:
        connection.close()
    return False


def refusal(settings: Settings) -> str | None:
    """Return the actionable reason a live restore must be refused."""
    active = holders(settings)
    if active:
        described = ", ".join(f"{item['role']} pid {item['pid']}" for item in active)
        return (
            f"the database is in use by {described}; stop the API and the worker, "
            "restore, and start them again"
        )
    if database_busy(settings):
        return (
            "the database file is held by another process; stop the API and the "
            "worker, restore, and start them again"
        )
    return None
