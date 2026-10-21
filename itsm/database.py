"""Portable SQLAlchemy engine, session factory and readiness probes."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from itsm.config import Settings

MIGRATION_TABLE = "alembic_version"


class DatabaseUnavailable(RuntimeError):
    """Raised when the database cannot answer a portable probe."""


@dataclass(frozen=True)
class MigrationState:
    current: str | None
    head: str | None

    @property
    def status(self) -> str:
        if self.current is None:
            return "pending"
        if self.head is None:
            return "unavailable"
        return "ok" if self.current == self.head else "pending"

    @property
    def is_current(self) -> bool:
        return self.status == "ok"

    def as_dict(self) -> dict[str, str | None]:
        return {"current": self.current, "head": self.head, "status": self.status}


@dataclass(frozen=True)
class Readiness:
    database: str
    migrations: MigrationState | None
    task_storage: str

    @property
    def is_ready(self) -> bool:
        return (
            self.database == "ok"
            and self.migrations is not None
            and self.migrations.is_current
            and self.task_storage == "ok"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "ok" if self.is_ready else "unavailable",
            "checks": {
                "database": self.database,
                "migrations": self.migrations.status if self.migrations else "unavailable",
                "tasks": self.task_storage,
            },
            "migrations": self.migrations.as_dict() if self.migrations else None,
        }


def _connect_args(settings: Settings) -> dict[str, Any]:
    """Driver-specific connection arguments that keep probes bounded."""
    url = make_url(settings.database_url)
    if url.drivername.startswith("sqlite"):
        return {"check_same_thread": False, "timeout": 5.0}
    if url.drivername.startswith("postgresql"):
        return {"connect_timeout": settings.database_connect_timeout_seconds}
    if url.drivername.startswith("mysql"):
        return {"connect_timeout": settings.database_connect_timeout_seconds}
    return {}


def create_engine_from_settings(settings: Settings) -> Engine:
    """Create the application engine; no connection is opened until used."""
    return create_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_pre_ping=True,
        connect_args=_connect_args(settings),
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Yield a session that always commits or rolls back cleanly."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def probe_database(engine: Engine) -> None:
    """Run a portable connectivity probe."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # SQLAlchemy wraps driver errors
        raise DatabaseUnavailable("database probe failed") from exc


def alembic_config(settings: Settings) -> Config:
    path = settings.alembic_config_path
    if not path.is_file():
        raise DatabaseUnavailable(f"alembic configuration not found at {path}")
    return Config(str(path))


def migration_head(settings: Settings) -> str | None:
    script = ScriptDirectory.from_config(alembic_config(settings))
    return script.get_current_head()


def current_revision(engine: Engine) -> str | None:
    inspector = inspect(engine)
    if not inspector.has_table(MIGRATION_TABLE):
        return None
    with engine.connect() as connection:
        row = connection.execute(text(f"SELECT version_num FROM {MIGRATION_TABLE}")).first()
    return None if row is None else str(row[0])


def migration_state(engine: Engine, settings: Settings) -> MigrationState:
    return MigrationState(current=current_revision(engine), head=migration_head(settings))


def check_readiness(
    engine: Engine,
    settings: Settings,
    task_storage_ok: bool,
) -> Readiness:
    """Combine required checks; optional services are never probed here."""
    try:
        probe_database(engine)
    except DatabaseUnavailable:
        return Readiness(
            database="unavailable",
            migrations=None,
            task_storage="ok" if task_storage_ok else "unavailable",
        )
    return Readiness(
        database="ok",
        migrations=migration_state(engine, settings),
        task_storage="ok" if task_storage_ok else "unavailable",
    )


def database_file(settings: Settings) -> Path | None:
    url = make_url(settings.database_url)
    if not url.drivername.startswith("sqlite") or not url.database:
        return None
    return Path(url.database)
