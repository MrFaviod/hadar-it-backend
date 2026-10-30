"""Deployment identity: which release mode owns one database.

A database may only ever serve the release mode that claimed it. The singleton
row ``deployment_identity(id = 1)`` records that claim; a process compares its
own mode with the recorded one at startup and refuses to run against a database
owned by another mode, without ever rewriting the row (S19).

Startup policy, in order:

* No row and an empty database (no identity accounts, no demo marker): the
  current mode claims the database.
* No row and a non-empty database: this is the documented installer flow, where
  the first administrator exists before the API starts. ``prod`` adopts it and
  logs the adoption explicitly. ``dev`` starts, logs a warning and does **not**
  claim it, because a development process must never make an irreversible
  ownership decision about data it did not create (S5). ``demo`` refuses unless
  the database carries the durable demo marker, in which case it claims it.
* A row naming another mode: always refused, with both modes in the message.
* A demo-marked database: only ``demo`` may claim or run it. ``dev`` may inspect
  it locally without claiming it; ``prod`` refuses it, so fictional data can
  never be promoted to production.

The ``dev`` mode additionally requires a local database (a SQLite file or a
loopback host). That single guard is what stops a development process from
pointing at, and resetting, a production database over the network (S5).

Migrations stay an explicit prerequisite: when the ``deployment_identity``
table or the database itself is not reachable yet, startup continues and
``/health/ready`` reports the real state, so the API never races migrations.

Public interface:

* :func:`enforce_startup` — the startup gate; used by the API lifespan, the
  worker startup handler and any CLI (``itsm.demo``) that needs the same check.
* :func:`read_identity` — read the claim, if any.
* :func:`claim_identity` — write the claim for an installation being created.
* :func:`ensure_identity` — apply the policy against one open session.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Engine, Integer, String, func, inspect, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from itsm.config import Settings, get_settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo.state import DemoInstallation
from itsm.identity.clock import utcnow
from itsm.identity.models import Identity
from itsm.logging import log_event
from itsm.release_mode import (
    ModeCapabilities,
    ReleaseMode,
    ReleaseModeError,
    capabilities_for,
    read_release_mode,
)

logger = logging.getLogger("itsm.release")

TABLE_NAME = "deployment_identity"

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class DeploymentIdentityError(ReleaseModeError):
    """Startup is refused: this process may not use this database."""


class DeploymentBase(DeclarativeBase):
    """Declarative base for deployment-level, non-domain tables."""


class DeploymentIdentity(DeploymentBase):
    """The single row that records the mode owning this database."""

    __tablename__ = TABLE_NAME

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    release_mode: Mapped[str] = mapped_column(String(8), nullable=False)
    instance_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


@dataclass(frozen=True)
class StartupMode:
    """Result of a successful startup gate."""

    mode: ReleaseMode
    capabilities: ModeCapabilities


def read_identity(session: Session) -> DeploymentIdentity | None:
    """Return the recorded deployment identity, if the database has one."""
    return session.scalar(select(DeploymentIdentity).where(DeploymentIdentity.id == 1))


def _present_tables(session: Session) -> set[str]:
    """Schema present right now; a partially migrated database is not an error."""
    return set(inspect(session.get_bind()).get_table_names())


def has_demo_marker(session: Session) -> bool:
    """Return whether the durable demo dataset marker is present.

    A database without the marker table has no marker: startup must not fail on
    a partially migrated schema, and readiness reports the schema state.
    """
    if DemoInstallation.__tablename__ not in _present_tables(session):
        return False
    return session.scalar(select(DemoInstallation.id).where(DemoInstallation.id == 1)) == 1


def database_is_empty(session: Session) -> bool:
    """Return whether the database holds no accounts and no demo marker."""
    tables = _present_tables(session)
    accounts = 0
    if Identity.__tablename__ in tables:
        accounts = session.scalar(select(func.count()).select_from(Identity)) or 0
    if accounts:
        return False
    if DemoInstallation.__tablename__ not in tables:
        return True
    return not has_demo_marker(session)


def claim_identity(
    session: Session,
    mode: ReleaseMode,
    *,
    instance_id: str | None = None,
) -> DeploymentIdentity:
    """Write the identity row for ``mode``; an existing different claim wins.

    Args:
        session: Open session; the caller owns the commit.
        mode: Mode claiming the database.
        instance_id: Optional stable identifier; a random one is generated.

    Returns:
        The existing or newly created identity row.

    Raises:
        DeploymentIdentityError: The database is already claimed by another mode.
    """
    existing = read_identity(session)
    if existing is not None:
        if existing.release_mode != mode:
            raise DeploymentIdentityError(_mismatch_message(existing.release_mode, mode))
        return existing
    row = DeploymentIdentity(
        id=1,
        release_mode=mode,
        instance_id=instance_id or uuid4().hex,
        created_at=utcnow(),
    )
    session.add(row)
    session.flush()
    return row


def ensure_identity(
    session: Session,
    mode: ReleaseMode,
    *,
    instance_id: str | None = None,
) -> DeploymentIdentity | None:
    """Apply the ownership policy, claiming only when it is safe.

    Args:
        session: Open session; the caller owns the commit.
        mode: Mode of the running process.
        instance_id: Optional identifier stored with a new claim.

    Returns:
        The identity row claiming this database, or ``None`` when a ``dev``
        process runs against a non-empty, unclaimed local database.

    Raises:
        DeploymentIdentityError: The database belongs to another mode, or demo
            mode was given a database that is neither empty nor marked demo.
    """
    existing = read_identity(session)
    if existing is not None:
        if existing.release_mode != mode:
            raise DeploymentIdentityError(_mismatch_message(existing.release_mode, mode))
        return existing
    if database_is_empty(session):
        claimed = claim_identity(session, mode, instance_id=instance_id)
        log_event(logger, "release.identity.claimed", mode=mode, instance_id=claimed.instance_id)
        return claimed
    if has_demo_marker(session):
        if mode == "demo":
            claimed = claim_identity(session, mode, instance_id=instance_id)
            log_event(logger, "release.identity.claimed", mode=mode, demo_marked=True)
            return claimed
        if mode == "dev":
            log_event(
                logger,
                "release.identity.unclaimed",
                level=logging.WARNING,
                mode=mode,
                demo_marked=True,
                reason="local development runs without claiming the database",
            )
            return None
        raise DeploymentIdentityError(
            "database carries the demo dataset marker and is marked for release mode 'demo' "
            f"but this process runs '{mode}'; refusing to start"
        )
    if mode == "prod":
        adopted = claim_identity(session, mode, instance_id=instance_id)
        log_event(
            logger,
            "release.identity.adopted",
            level=logging.WARNING,
            mode=mode,
            reason="unmarked non-empty database adopted by an explicit production start",
        )
        return adopted
    if mode == "dev":
        log_event(
            logger,
            "release.identity.unclaimed",
            level=logging.WARNING,
            mode=mode,
            reason="non-empty database without a deployment identity is not claimed by dev",
        )
        return None
    raise DeploymentIdentityError(
        "demo mode requires an empty database or one marked as a demo installation; "
        f"this database is unmarked and not empty, so '{mode}' refuses to start"
    )


def require_local_database(settings: Settings, mode: ReleaseMode) -> None:
    """Refuse a non-local database for release modes confined to this host.

    Args:
        settings: Runtime settings holding the database URL.
        mode: Mode whose restrictions apply.

    Raises:
        DeploymentIdentityError: The URL points outside this host.
    """
    url = make_url(settings.database_url)
    if url.drivername.startswith("sqlite"):
        return
    host = (url.host or "").strip().lower()
    if host in LOOPBACK_HOSTS:
        return
    raise DeploymentIdentityError(
        f"release mode '{mode}' requires a local database: a sqlite file or a loopback host; "
        "remote databases are refused so local work cannot target production"
    )


def identity_table_available(engine: Engine) -> bool:
    """Return whether migrations created the identity table, tolerating outages."""
    try:
        return TABLE_NAME in inspect(engine).get_table_names()
    except SQLAlchemyError:
        log_event(
            logger,
            "release.identity.unavailable",
            level=logging.WARNING,
            reason="deployment identity cannot be read; readiness reports the database state",
        )
        return False


def enforce_startup(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
    environ: Mapping[str, str] | None = None,
) -> StartupMode:
    """Validate the release mode and the deployment identity before serving.

    Args:
        settings: Settings snapshot; defaults to the process environment.
        engine: Existing engine to inspect; a temporary one is built and disposed
            when omitted.
        environ: Environment holding ``RELEASE_MODE``; defaults to the process.

    Returns:
        The effective mode and its frozen capabilities.

    Raises:
        ReleaseModeError: The mode is absent or invalid.
        DeploymentIdentityError: The mode may not use this database.
    """
    settings = settings or get_settings()
    mode = read_release_mode(environ)
    if mode == "dev":
        require_local_database(settings, mode)
    own_engine = engine is None
    resolved = engine or create_engine_from_settings(settings)
    try:
        if identity_table_available(resolved):
            with create_session_factory(resolved)() as session:
                ensure_identity(session, mode)
                session.commit()
        else:
            log_event(
                logger,
                "release.identity.pending_migrations",
                level=logging.WARNING,
                mode=mode,
                database=settings.safe_database_url(),
            )
    finally:
        if own_engine:
            resolved.dispose()
    log_event(logger, "release.mode.active", mode=mode, database=settings.safe_database_url())
    return StartupMode(mode=mode, capabilities=capabilities_for(mode))


def _mismatch_message(recorded: str, mode: ReleaseMode) -> str:
    return (
        f"database is claimed by release mode '{recorded}' but this process runs '{mode}'; "
        "refusing to start and leaving the existing identity untouched"
    )
