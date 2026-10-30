"""Contained SQLite reset implementation; caller owns the API quiescence lock."""

from __future__ import annotations

import secrets
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

from sqlalchemy import Engine, MetaData
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.database import database_file
from itsm.demo.cycle import DemoCycle, cycle_status
from itsm.demo.seed import seed
from itsm.devtools.database import MIGRATION_REFERENCE_TABLES
from itsm.identity.clock import utcnow
from itsm.release_identity import DeploymentIdentityError, read_identity
from itsm.release_mode import read_release_mode


def _owned(path: Path, root: Path) -> Path:
    absolute = path.absolute()
    if not absolute.is_relative_to(root) or absolute == root:
        raise DeploymentIdentityError("demo reset requires owned paths")
    if any(parent.is_symlink() for parent in (absolute, *absolute.parents)):
        raise DeploymentIdentityError("demo reset requires owned paths without symlinks")
    if not absolute.resolve().is_relative_to(root.resolve()):
        raise DeploymentIdentityError("demo reset requires owned paths")
    return absolute


def validate_reset_paths(settings: Settings) -> tuple[Path, Path]:
    """Reject unsafe storage before changing the database or any filesystem state."""
    if read_release_mode() != "demo" or settings.demo_data_directory is None:
        raise DeploymentIdentityError("demo reset requires explicit owned data directory")
    root = settings.demo_data_directory.absolute()
    if not root.is_dir() or any(p.is_symlink() for p in (root, *root.parents)):
        raise DeploymentIdentityError("demo reset requires owned directory without symlinks")
    database = database_file(settings)
    if database is None or settings.task_storage != "sqlite":
        raise DeploymentIdentityError("demo reset requires owned SQLite database and jobs")
    db_path = _owned(database, root)
    attachments = _owned(settings.attachment_storage_path, root)
    tasks = _owned(settings.task_sqlite_path, root)
    paths = (db_path, attachments, tasks)
    if any(
        a == b or a.is_relative_to(b) or b.is_relative_to(a)
        for i, a in enumerate(paths)
        for b in paths[i + 1 :]
    ):
        raise DeploymentIdentityError("demo reset requires separate owned storage paths")
    if attachments.exists() and (
        not attachments.is_dir() or any(p.is_symlink() for p in attachments.rglob("*"))
    ):
        raise DeploymentIdentityError("demo reset refuses non-owned attachment links")
    for suffix in ("-wal", "-shm", "-journal"):
        for path in (db_path, tasks):
            _owned(Path(str(path) + suffix), root)
    return attachments, tasks


def reset_demo(settings: Settings, engine: Engine) -> None:
    """Reset a demo only; preserve a durable unavailable flag on any partial failure."""
    attachments, tasks = validate_reset_paths(settings)
    if engine.dialect.name != "sqlite":
        raise DeploymentIdentityError("demo reset only supports owned SQLite")
    with Session(engine) as session:
        owner = read_identity(session)
        if owner is None or owner.release_mode != "demo":
            raise DeploymentIdentityError("demo reset requires demo-owned database")
        cycle_status(session)
        row = session.get(DemoCycle, 1)
        assert row is not None
        if row.resetting:
            raise DeploymentIdentityError("demo reset requires recovery after previous failure")
        generation = row.generation
        row.resetting = True
        session.commit()
    # Keep deployment ownership/cycle and migration-provided reference rows.
    metadata = MetaData()
    metadata.reflect(bind=engine)
    preserved = MIGRATION_REFERENCE_TABLES | {
        "alembic_version",
        "deployment_identity",
        "demo_cycle",
    }
    with engine.begin() as connection:
        for table in reversed(metadata.sorted_tables):
            if table.name not in preserved:
                connection.execute(table.delete())
    if attachments.exists():
        for child in attachments.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        attachments.mkdir(parents=True, mode=0o700)
    if tasks.exists():
        # Preserve open storage handles; delete task/result rows instead of replacing the file.
        with sqlite3.connect(tasks) as queue:
            names = queue.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for (name,) in names:
                quoted = '"' + name.replace('"', '""') + '"'
                queue.execute(f"DELETE FROM {quoted}")
    with Session(engine) as session:
        seed(session, settings, "admin", secrets.token_urlsafe(32))
        row = session.get(DemoCycle, 1)
        assert row is not None
        row.generation = generation + 1
        row.next_reset_at = utcnow() + timedelta(minutes=60)
        row.resetting = False
        session.commit()
