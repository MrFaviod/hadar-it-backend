"""Typed configuration for the ITSM backend foundation.

Settings come from process environment variables with the ``ITSM_`` prefix.
No ``.env`` file is loaded or committed: deployment supplies values through the
container environment or a secret manager.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

BACKEND_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_DATABASE_URL = "postgresql+psycopg://itsm@localhost:5432/itsm"

SUPPORTED_DATABASE_DRIVERS = frozenset(
    {
        "postgresql+psycopg",
        "sqlite",
        "sqlite+pysqlite",
        "mysql+pymysql",
        "mssql+pyodbc",
    }
)

LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"})


class Settings(BaseSettings):
    """Runtime configuration for the API and the worker processes."""

    model_config = SettingsConfigDict(
        env_prefix="ITSM_",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "itsm-backend"
    environment: Literal["development", "test", "production"] = "development"
    api_prefix: str = "/api/v1"

    database_url: str = DEFAULT_DATABASE_URL
    database_echo: bool = False
    database_connect_timeout_seconds: int = Field(default=5, ge=1, le=60)

    task_storage: Literal["sqlite", "redis", "postgres"] = "sqlite"
    task_sqlite_path: Path = Path("/data/tasks/huey.db")
    task_redis_url: str = "redis://127.0.0.1:6379/0"
    task_postgres_dsn: str = ""
    task_retries: int = Field(default=2, ge=0, le=10)
    task_retry_delay_seconds: float = Field(default=1.0, ge=0.0, le=30.0)

    demo_message_max_length: int = Field(default=200, ge=1, le=1000)
    demo_max_delay_seconds: int = Field(default=30, ge=0, le=300)
    demo_periodic_minutes: int = Field(default=0, ge=0, le=60)

    log_level: str = "INFO"

    prometheus_url: str | None = None
    meilisearch_url: str | None = None
    service_redis_url: str | None = None

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: str) -> str:
        try:
            url = make_url(value)
        except ArgumentError as exc:  # pragma: no cover - defensive
            raise ValueError("database_url is not a valid SQLAlchemy URL") from exc
        if url.drivername not in SUPPORTED_DATABASE_DRIVERS:
            supported = ", ".join(sorted(SUPPORTED_DATABASE_DRIVERS))
            raise ValueError(
                f"database_url driver '{url.drivername}' is not supported (supported: {supported})"
            )
        if not url.database and url.drivername != "sqlite":
            raise ValueError("database_url must include a database name")
        return value

    @field_validator("task_redis_url")
    @classmethod
    def _validate_task_redis_url(cls, value: str) -> str:
        if not value:
            return value
        try:
            url = make_url(value)
        except ArgumentError as exc:  # pragma: no cover - defensive
            raise ValueError("task_redis_url is not a valid URL") from exc
        if url.drivername not in {"redis", "rediss"}:
            raise ValueError("task_redis_url must use the redis:// or rediss:// scheme")
        return value

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(LOG_LEVELS)}")
        return level

    @model_validator(mode="after")
    def _validate_task_storage(self) -> Settings:
        if self.task_storage == "redis" and not self.task_redis_url:
            raise ValueError("task_storage=redis requires task_redis_url")
        if self.task_storage == "postgres" and not self.task_postgres_dsn:
            raise ValueError("task_storage=postgres requires task_postgres_dsn")
        if self.task_storage == "sqlite":
            self._reject_shared_sqlite_file()
        return self

    def _reject_shared_sqlite_file(self) -> None:
        url = make_url(self.database_url)
        if not url.drivername.startswith("sqlite") or not url.database:
            return
        app_path = Path(url.database).resolve()
        queue_path = Path(self.task_sqlite_path).resolve()
        if app_path == queue_path:
            raise ValueError(
                "task_sqlite_path must not be the same file as the SQLite application database"
            )

    @property
    def alembic_config_path(self) -> Path:
        return BACKEND_ROOT / "alembic.ini"

    def safe_database_url(self) -> str:
        """Return the application database URL with any password removed."""
        try:
            url: URL = make_url(self.database_url)
        except ArgumentError:  # pragma: no cover - validated earlier
            return "<unparsable database url>"
        return url.render_as_string(hide_password=True)

    def sensitive_values(self) -> tuple[str, ...]:
        """Return substrings that must never appear in logs or API responses."""
        values: set[str] = {self.database_url}
        if self.task_postgres_dsn:
            values.add(self.task_postgres_dsn)
        if self.task_redis_url:
            values.add(self.task_redis_url)
        if self.service_redis_url:
            values.add(self.service_redis_url)
        for raw in (self.database_url, self.task_postgres_dsn, self.task_redis_url):
            if not raw:
                continue
            password = _url_password(raw)
            if password:
                values.add(password)
        return tuple(sorted(value for value in values if value))


def _url_password(raw: str) -> str | None:
    try:
        url = make_url(raw)
    except ArgumentError:
        return None
    return url.password


def get_settings() -> Settings:
    """Build settings from the current process environment."""
    return Settings(_env_file=None)


def settings_for(**overrides: Any) -> Settings:
    """Build explicit settings, used by tests and tooling."""
    return Settings(_env_file=None, **overrides)
