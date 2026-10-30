"""Commands of the development maintenance CLI (S3, S4, S5).

``init`` creates a dev database: migrations to head, the ``dev`` deployment
identity, an explicit administrator and a fictitious dataset built by the
canonical :mod:`itsm.demo.seed`. ``status`` reports the environment as JSON
without changing anything. ``reset`` clears the application data and reseeds it,
and ``reset --regenerate`` recreates a SQLite file from scratch.

The destructive paths are guarded in :mod:`itsm.devtools.guard` and only touch
the database named by ``ITSM_DATABASE_URL`` plus the attachment and task paths
inside a development data directory.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.database import create_session_factory, migration_head, migration_state
from itsm.demo.seed import seed
from itsm.demo.state import DemoInstallation
from itsm.devtools import database as devdb
from itsm.devtools import guard
from itsm.devtools.guard import RESET_FLAG, DatabaseTarget, DevToolsRefused, dev_data_dir
from itsm.identity.models import Identity
from itsm.identity.service import IdentityError
from itsm.release_identity import (
    claim_identity,
    database_is_empty,
    has_demo_marker,
    identity_table_available,
    read_identity,
)

SEED_SOURCE = "itsm.demo.seed"


def initialize(
    settings: Settings,
    username: str,
    password: str,
    *,
    password_source: str,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Create or complete a development database and seed it once.

    Args:
        settings: Runtime settings read from the process environment.
        username: Explicit username of the dev superadmin.
        password: Administrator password (environment value or generated).
        password_source: ``environment`` or ``generated``; a generated password
            is reported once so it can be used to sign in.
        environ: Environment holding ``RELEASE_MODE``; defaults to the process.

    Returns:
        A JSON-ready summary. A second run on an initialized database returns
        ``status: unchanged`` and touches nothing.
    """
    guard.require_dev_mode(environ)
    guard.require_local(settings)
    guard.require_dev_startup(settings)
    target = guard.database_target(settings)

    with guard.engine_for(settings) as engine:
        guard.require_initialisable(engine)

    devdb.migrate_to_head(settings)

    with guard.engine_for(settings) as engine, create_session_factory(engine)() as session:
        identity = read_identity(session)
        if identity is None:
            if not database_is_empty(session):
                raise DevToolsRefused(
                    "database gained data while it was being initialised; next: "
                    "inspect it with 'status' and use a new development database"
                )
            claim_identity(session, guard.DEV_MODE)
            session.commit()
        if _identity_count(session):
            payload = _snapshot(settings, engine, session, status="unchanged", target=target)
            payload["admin"] = _admin(username, password, password_source, "unchanged")
            payload["next"] = [
                "run 'python -m itsm.devtools status' to inspect the environment",
                f"reset it with 'reset {RESET_FLAG} --confirm {target.name}'",
            ]
            return payload
        dataset = _seed(session, settings, username, password)
        session.commit()
        payload = _snapshot(settings, engine, session, status="initialized", target=target)
        payload["dataset"] = dataset
        payload["admin"] = _admin(username, password, password_source, "initialized")
        payload["next"] = [
            "start the API with RELEASE_MODE=dev",
            f"reset it with 'reset {RESET_FLAG} --confirm {target.name}'",
        ]
        return payload


def inspect_database(
    settings: Settings,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Report mode, database, identity, schema, counts and reset decision as JSON.

    The command changes nothing: it never claims an identity and never migrates.
    An unreachable database is reported honestly instead of failing, so the
    operator can diagnose a wrong URL (S4).
    """
    guard.require_dev_mode(environ)
    guard.require_local(settings)
    target = guard.database_target(settings)
    payload: dict[str, Any] = {
        "status": "status",
        "mode": guard.DEV_MODE,
        "target": target.name,
        "database": {**target.as_dict(), "reachable": False},
        "identity": _identity(None),
        "demoMarker": None,
        "schema": {"current": None, "head": migration_head(settings), "status": "unavailable"},
        "counts": {},
        "reset": {
            "allowed": False,
            "reasons": ["database is unreachable; next: verify ITSM_DATABASE_URL"],
            "target": target.name,
            "requires": [RESET_FLAG, f"--confirm {target.name}"],
        },
    }
    try:
        with guard.engine_for(settings) as engine:
            with engine.connect() as connection:
                connection.execute(select(1))
            with create_session_factory(engine)() as session:
                identity = read_identity(session) if identity_table_available(engine) else None
                marker = has_demo_marker(session)
            state = migration_state(engine, settings)
            blockers = guard.reset_blockers(settings, engine, dev_data_dir(environ))
            counts = devdb.table_counts(engine)
    except SQLAlchemyError:
        return payload
    payload.update(
        {
            "database": {**target.as_dict(), "reachable": True},
            "identity": _identity(identity),
            "demoMarker": marker,
            "schema": state.as_dict(),
            "counts": counts,
            "reset": {
                "allowed": not blockers,
                "reasons": blockers,
                "target": target.name,
                "requires": [RESET_FLAG, f"--confirm {target.name}"],
            },
        }
    )
    return payload


def reset(
    settings: Settings,
    username: str,
    password: str,
    *,
    password_source: str,
    confirm: str | None,
    regenerate: bool,
    reset_flag: bool,
    data_dir: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Delete the development data and rebuild it (keep schema or regenerate).

    Args:
        settings: Runtime settings read from the process environment.
        username: Username of the dev superadmin recreated by the seed.
        password: Administrator password (environment value or generated).
        password_source: ``environment`` or ``generated``.
        confirm: Value the operator passed to ``--confirm``; must match the target.
        regenerate: Delete the SQLite file (or drop reflected tables) instead of
            clearing rows.
        reset_flag: Whether ``--yes-reset-dev-database`` was passed.
        data_dir: ``ITSM_DEV_DATA_DIR``, or ``None`` when unset.
        environ: Environment holding ``RELEASE_MODE``; defaults to the process.

    Returns:
        A JSON-ready summary of what was cleared and rebuilt.
    """
    guard.require_dev_mode(environ)
    guard.require_local(settings)
    target = guard.database_target(settings)
    guard.require_confirmation(target, confirm=confirm, reset_flag=reset_flag)
    paths = guard.require_dev_data_paths(settings, data_dir)
    with guard.engine_for(settings) as engine:
        guard.require_dev_identity(engine)
    guard.require_dev_startup(settings)

    cleared: dict[str, Any] = {}
    if regenerate and target.is_sqlite:
        cleared["databaseFile"] = devdb.delete_sqlite_file(settings)
    else:
        with guard.engine_for(settings) as engine:
            if regenerate:
                cleared["droppedTables"] = devdb.drop_tables(engine)
            else:
                cleared["clearedTables"] = devdb.clear_tables(engine)
    cleared["dataPaths"] = devdb.clear_data_paths(paths)
    devdb.migrate_to_head(settings)

    with guard.engine_for(settings) as engine, create_session_factory(engine)() as session:
        identity = read_identity(session)
        if identity is None:
            claim_identity(session, guard.DEV_MODE)
            session.commit()
        elif identity.release_mode != guard.DEV_MODE:
            raise DevToolsRefused(
                f"database is marked '{identity.release_mode}'; next: use a dev "
                "database (nothing was changed)"
            )
        if _identity_count(session):
            raise DevToolsRefused(
                "reset left existing accounts in place; next: inspect the database "
                "with 'status' and migrate it manually"
            )
        dataset = _seed(session, settings, username, password)
        session.commit()
        status = "regenerated" if regenerate else "reset"
        payload = _snapshot(settings, engine, session, status=status, target=target)
        payload["dataset"] = dataset
        payload["cleared"] = cleared
        payload["admin"] = _admin(username, password, password_source, status)
        payload["next"] = [
            "run 'python -m itsm.devtools status' to confirm the new state",
            f"reset again with 'reset {RESET_FLAG} --confirm {target.name}'",
        ]
        return payload


def _seed(
    session: Session,
    settings: Settings,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Build the fictional dataset with the canonical demo seed.

    The canonical seed writes the durable demo marker before any service
    commit; demo code is out of this task's edit surface, so the marker is kept
    and reported instead of removed. A marker can never be promoted to
    production, so the safety direction is unchanged, but the database reports
    ``demoMarker: true`` in ``status``.
    """
    try:
        seeded = seed(session, settings, username, password)
    except IdentityError as exc:
        raise DevToolsRefused(
            f"the dev administrator could not be created: {exc}; next: choose a "
            "username that is not taken and a password of at least 12 characters"
        ) from None
    return {
        **seeded,
        "mode": guard.DEV_MODE,
        "seed": SEED_SOURCE,
        "demoMarker": True,
    }


def _snapshot(
    settings: Settings,
    engine: Engine,
    session: Session,
    *,
    status: str,
    target: DatabaseTarget,
) -> dict[str, Any]:
    return {
        "status": status,
        "mode": guard.DEV_MODE,
        "target": target.name,
        "database": {**target.as_dict(), "reachable": True},
        "identity": _identity(read_identity(session)),
        "demoMarker": session.get(DemoInstallation, 1) is not None,
        "schema": migration_state(engine, settings).as_dict(),
        "counts": devdb.table_counts(engine),
        "dataset": None,
    }


def _identity(row: Any) -> dict[str, Any]:
    return {
        "marker": None if row is None else row.release_mode,
        "instanceId": None if row is None else row.instance_id,
        "createdAt": None if row is None else row.created_at.isoformat(),
    }


def _admin(
    username: str,
    password: str,
    password_source: str,
    status: str,
) -> dict[str, Any]:
    admin: dict[str, Any] = {"username": username, "passwordSource": password_source}
    if password_source == "generated" and status != "unchanged":
        admin["password"] = password
    return admin


def _identity_count(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(Identity)) or 0)
