"""The installation completion marker, readable without importing the setup app.

Completion is stored in the application database, not only in the private setup
state directory, so a restored bootstrap snapshot can never reopen a finished
installation. This module owns the single row of ``installation_setup`` and the
read helpers that both the setup process and the normal API use. It never
imports ``itsm.setup``.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Integer,
    String,
    inspect,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

TABLE_NAME = "installation_setup"
IDENTITY_TABLE = "identity_identities"
STATE_COMPLETE = "complete"
SETUP_CONTRACT_VERSION = "1"


class InstallationBase(DeclarativeBase):
    """Declarative base kept private to installation-level state."""


class InstallationSetup(InstallationBase):
    """One row recording that this database finished onboarding."""

    __tablename__ = TABLE_NAME
    __table_args__ = (CheckConstraint("id = 1", name="ck_installation_setup_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    instance_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    setup_contract_version: Mapped[str] = mapped_column(String(16), nullable=False)
    report_digest: Mapped[str] = mapped_column(String(64), nullable=False)


@dataclass(frozen=True)
class InstallationState:
    """What the database says about this installation right now."""

    reachable: bool = False
    complete: bool = False
    installed: bool = False
    instance_id: str | None = None
    completed_at: str | None = None
    completed_by: str | None = None
    setup_contract_version: str | None = None
    report_digest: str | None = None

    @property
    def label(self) -> str:
        if self.complete:
            return "complete"
        if self.installed:
            return "installed"
        return "new" if self.reachable else "unknown"


UNKNOWN = InstallationState()


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def canonical_report(report: Mapping[str, Any]) -> str:
    """Stable JSON used for the digest; never contains raw secrets."""

    return json.dumps(dict(report), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def report_digest(report: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_report(report).encode("utf-8")).hexdigest()


def _tables(session: Session) -> set[str]:
    return set(inspect(session.get_bind()).get_table_names())


def _identities_present(session: Session, tables: set[str]) -> bool:
    if IDENTITY_TABLE not in tables:
        return False
    count = session.scalar(text(f"SELECT COUNT(*) FROM {IDENTITY_TABLE}"))
    return bool(count)


def read_row(session: Session) -> InstallationSetup | None:
    if TABLE_NAME not in _tables(session):
        return None
    return session.scalar(select(InstallationSetup).where(InstallationSetup.id == 1))


def state_from_session(session: Session) -> InstallationState:
    """Read the marker and whether any identity already exists."""

    tables = _tables(session)
    row = read_row(session)
    installed = row is not None or _identities_present(session, tables)
    if row is None:
        return InstallationState(reachable=True, installed=installed)
    return InstallationState(
        reachable=True,
        complete=row.state == STATE_COMPLETE,
        installed=True,
        instance_id=row.instance_id,
        completed_at=_iso(row.completed_at),
        completed_by=row.completed_by,
        setup_contract_version=row.setup_contract_version,
        report_digest=row.report_digest,
    )


def state_from_engine(engine: Any) -> InstallationState:
    try:
        with Session(engine) as session:
            return state_from_session(session)
    except SQLAlchemyError:
        return UNKNOWN
    except Exception:  # defensive: a driver may raise its own error type
        return UNKNOWN


def safe_state_from_session(session: Session) -> InstallationState:
    """Never break readiness because the marker could not be read."""

    try:
        return state_from_session(session)
    except SQLAlchemyError:
        return UNKNOWN


def database_configured(environ: Mapping[str, str] | None = None) -> bool:
    """True when the operator already named a database for this installation.

    Without one, the default URL points at a server that does not exist yet; the
    setup process must not open (or create) it just to read a marker.
    """

    source = os.environ if environ is None else environ
    if str(source.get("ITSM_DATABASE_URL") or "").strip():
        return True
    from itsm.config import InstallationConfigError, installation_config_path

    try:
        path = installation_config_path(source)
    except InstallationConfigError:
        return False
    if path is None or not path.exists():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return False
    if not isinstance(payload, dict):
        return False
    return bool(str(payload.get("database_url") or "").strip())


_ROW_COLUMNS = (
    "state, completed_at, completed_by, instance_id, setup_contract_version, report_digest"
)


def _state_from_values(
    row: tuple[Any, ...] | None, *, reachable: bool, installed: bool
) -> InstallationState:
    if row is None:
        return InstallationState(reachable=reachable, installed=installed)
    state, completed_at, completed_by, instance_id, contract, digest = row
    return InstallationState(
        reachable=True,
        complete=state == STATE_COMPLETE,
        installed=True,
        instance_id=instance_id,
        completed_at=_iso(completed_at),
        completed_by=completed_by,
        setup_contract_version=contract,
        report_digest=digest,
    )


def _read_sqlite_marker(database: str) -> InstallationState:
    import sqlite3

    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2)
    try:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        row = None
        if TABLE_NAME in tables:
            row = connection.execute(
                f"SELECT {_ROW_COLUMNS} FROM {TABLE_NAME} WHERE id = 1"
            ).fetchone()
        installed = row is not None
        if not installed and IDENTITY_TABLE in tables:
            installed = connection.execute(f"SELECT 1 FROM {IDENTITY_TABLE} LIMIT 1").fetchone()
        return _state_from_values(row, reachable=True, installed=bool(installed))
    finally:
        connection.close()


def _read_postgres_marker(url: Any) -> InstallationState:
    import psycopg

    options = {
        "host": url.host,
        "port": url.port,
        "user": url.username,
        "password": url.password,
        "dbname": url.database,
        "connect_timeout": 3,
    }
    with (
        psycopg.connect(
            **{key: value for key, value in options.items() if value is not None}
        ) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s",
            (TABLE_NAME,),
        )
        has_marker = cursor.fetchone() is not None
        row = None
        if has_marker:
            cursor.execute(f"SELECT {_ROW_COLUMNS} FROM {TABLE_NAME} WHERE id = 1")
            row = cursor.fetchone()
        installed = row is not None
        if not installed:
            cursor.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = current_schema() AND table_name = %s",
                (IDENTITY_TABLE,),
            )
            if cursor.fetchone() is not None:
                cursor.execute(f"SELECT 1 FROM {IDENTITY_TABLE} LIMIT 1")
                installed = cursor.fetchone() is not None
        return _state_from_values(row, reachable=True, installed=bool(installed))


def state_from_environ(environ: Mapping[str, str] | None = None) -> InstallationState:
    """Read the marker from the configured installation database.

    Any unreadable or unreachable database answers ``reachable=False``; callers
    treat that as unknown, never as a fresh installation. The read uses a plain
    driver connection, so importing the setup app never creates a SQLAlchemy
    Engine (or imports ``itsm.database``) just to answer status.
    """

    source = dict(os.environ) if environ is None else dict(environ)
    if not database_configured(source):
        return UNKNOWN
    from sqlalchemy.engine import make_url

    from itsm.config import resolve_settings_sources

    try:
        settings = resolve_settings_sources(source)
        url = make_url(settings.database_url)
        backend = url.get_backend_name()
        if backend == "sqlite" and url.database:
            return _read_sqlite_marker(url.database)
        if backend.startswith("postgresql"):
            return _read_postgres_marker(url)
    except Exception:
        return UNKNOWN
    return UNKNOWN


def write_completion(
    session: Session,
    *,
    completed_by: str | None,
    instance_id: str | None,
    setup_contract_version: str,
    digest: str,
    completed_at: datetime | None = None,
) -> InstallationSetup:
    """Insert the singleton marker once; a concurrent writer keeps the first row."""

    existing = read_row(session)
    if existing is not None:
        return existing
    row = InstallationSetup(
        id=1,
        state=STATE_COMPLETE,
        completed_at=completed_at or datetime.now(UTC),
        completed_by=completed_by,
        instance_id=instance_id,
        setup_contract_version=setup_contract_version,
        report_digest=digest,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        existing = read_row(session)
        if existing is None:  # pragma: no cover - defensive re-read
            raise
        return existing
    return row


__all__ = [
    "SETUP_CONTRACT_VERSION",
    "TABLE_NAME",
    "UNKNOWN",
    "InstallationSetup",
    "InstallationState",
    "canonical_report",
    "database_configured",
    "read_row",
    "report_digest",
    "safe_state_from_session",
    "state_from_engine",
    "state_from_environ",
    "state_from_session",
    "write_completion",
]
