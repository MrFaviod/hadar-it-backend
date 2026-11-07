"""Typed configuration for the ITSM backend foundation.

Settings come from process environment variables with the ``ITSM_`` prefix.
No ``.env`` file is loaded or committed: deployment supplies values through the
container environment or a secret manager.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
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

# Provider credentials are read by the provider SDKs from the process environment;
# they are never modeled as ITSM_ settings and never accepted from a request.
PROVIDER_SECRET_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")

COOKIE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


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

    attachment_storage_path: Path = Path("/data/attachments")
    attachment_max_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=50 * 1024 * 1024)

    report_base_url: str = "http://localhost:18080"
    report_retention_days: int = Field(default=7, ge=1, le=3650)
    report_max_assets: int = Field(default=1000, ge=1, le=10000)
    report_max_document_bytes: int = Field(default=50 * 1024 * 1024, ge=1, le=200 * 1024 * 1024)
    report_render_timeout_seconds: int = Field(default=120, ge=1, le=600)
    report_render_memory_mb: int = Field(default=512, ge=64, le=4096)

    demo_message_max_length: int = Field(default=200, ge=1, le=1000)
    demo_max_delay_seconds: int = Field(default=30, ge=0, le=300)
    demo_periodic_minutes: int = Field(default=0, ge=0, le=60)

    # Identity and authentication. ``auth_origin`` is the browser origin allowed
    # to call the API with cookies; ``auth_cookie_secure`` must be disabled
    # explicitly for plain-HTTP local development.
    auth_origin: str = "http://localhost:18080"
    auth_cookie_secure: bool = True
    auth_cookie_name: str = "itsm_session"
    auth_session_minutes_default: int = Field(default=480, ge=5, le=1440)
    auth_login_max_attempts: int = Field(default=5, ge=1, le=100)
    auth_login_window_minutes: int = Field(default=15, ge=1, le=1440)
    auth_password_min_length: int = Field(default=12, ge=8, le=128)
    auth_password_max_length: int = Field(default=128, ge=16, le=1024)

    log_level: str = "INFO"

    # Conversational agent. The provider/model pair is server configuration;
    # an empty value means the agent is explicitly unavailable (HTTP 503).
    agent_model: str = ""
    agent_max_steps: int = Field(default=8, ge=1, le=16)
    agent_max_history_messages: int = Field(default=20, ge=0, le=50)
    agent_max_output_tokens: int = Field(default=1024, ge=64, le=4096)
    agent_message_max_length: int = Field(default=4000, ge=1, le=8000)
    agent_openai_base_url: str | None = None

    prometheus_url: str | None = None
    prometheus_token: SecretStr | None = None
    alertmanager_url: str | None = None
    alertmanager_token: SecretStr | None = None
    monitoring_ingest_token: SecretStr | None = None
    monitoring_discovery_token: SecretStr | None = None
    monitoring_http_timeout_seconds: int = Field(default=10, ge=1, le=60)
    monitoring_secrets: dict[str, SecretStr] = Field(default_factory=dict)
    monitoring_public_url: str = "http://localhost:18080"
    monitoring_poll_seconds: int = Field(default=60, ge=60, le=3600)
    notification_retention_days: int = Field(default=90, ge=1, le=3650)
    meilisearch_url: str | None = None
    service_redis_url: str | None = None

    @field_validator("report_base_url")
    @classmethod
    def _validate_report_base_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        try:
            parts = urlsplit(normalized)
            port = parts.port
        except ValueError as exc:
            raise ValueError("report base URL must use http(s)") from exc
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or "?" in normalized
            or "#" in normalized
            or "\\" in normalized
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in normalized)
            or parts.netloc.endswith(":")
            or (port is not None and port < 1)
        ):
            raise ValueError("report base URL must use http(s) without credentials, query or fragment")
        return normalized

    @field_validator("prometheus_url", "alertmanager_url", "monitoring_public_url")
    @classmethod
    def _validate_monitoring_endpoint(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        if not normalized and info.field_name != "monitoring_public_url":
            return None
        try:
            parts = urlsplit(normalized)
            port = parts.port
        except ValueError as exc:
            raise ValueError("monitoring endpoint must be an http(s) URL") from exc
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or any(character.isspace() for character in normalized)
            or (port is not None and port < 1)
        ):
            raise ValueError(
                "monitoring endpoint must use http(s) without credentials, query or fragment"
            )
        return normalized

    @field_validator(
        "prometheus_token",
        "alertmanager_token",
        "monitoring_ingest_token",
        "monitoring_discovery_token",
        mode="before",
    )
    @classmethod
    def _normalize_monitoring_token(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value

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

    @field_validator("agent_model")
    @classmethod
    def _validate_agent_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            return ""
        provider, separator, model = normalized.partition(":")
        if not separator or not provider or not model:
            raise ValueError("agent_model must use the 'provider:model' form")
        if provider not in {"openai", "anthropic"}:
            raise ValueError("agent_model provider must be openai or anthropic")
        if any(character.isspace() for character in model):
            raise ValueError("agent_model must not contain whitespace")
        return normalized

    @field_validator("agent_openai_base_url")
    @classmethod
    def _validate_agent_base_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        normalized = value.strip()
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("agent_openai_base_url must be an http(s) URL")
        return normalized

    @field_validator("auth_origin")
    @classmethod
    def _validate_auth_origin(cls, value: str) -> str:
        origin = value.strip().rstrip("/")
        parts = urlsplit(origin)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("auth_origin must be an http(s) origin such as http://localhost:18080")
        if parts.path or parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("auth_origin must not contain a path, query, fragment or credentials")
        return origin

    @field_validator("auth_cookie_name")
    @classmethod
    def _validate_cookie_name(cls, value: str) -> str:
        name = value.strip()
        if not COOKIE_NAME_PATTERN.match(name):
            raise ValueError("auth_cookie_name must be a valid cookie token")
        return name

    @model_validator(mode="after")
    def _validate_task_storage(self) -> Settings:
        if self.task_storage == "redis" and not self.task_redis_url:
            raise ValueError("task_storage=redis requires task_redis_url")
        if self.task_storage == "postgres" and not self.task_postgres_dsn:
            raise ValueError("task_storage=postgres requires task_postgres_dsn")
        if self.task_storage == "sqlite":
            self._reject_shared_sqlite_file()
        if self.auth_password_max_length <= self.auth_password_min_length:
            raise ValueError("auth_password_max_length must exceed auth_password_min_length")
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
        for secret in (
            self.prometheus_token,
            self.alertmanager_token,
            self.monitoring_ingest_token,
            self.monitoring_discovery_token,
            *self.monitoring_secrets.values(),
        ):
            if secret is not None:
                raw = secret.get_secret_value()
                if raw:
                    values.add(raw)
                    try:
                        parts = urlsplit(raw)
                    except ValueError:
                        continue
                    if parts.password:
                        values.add(parts.password)
                    if parts.scheme == "tgram" and parts.netloc:
                        values.add(parts.netloc)
        for raw in (self.database_url, self.task_postgres_dsn, self.task_redis_url):
            if not raw:
                continue
            password = _url_password(raw)
            if password:
                values.add(password)
        if self.agent_openai_base_url:
            password = _url_password(self.agent_openai_base_url)
            if password:
                values.add(password)
        for name in PROVIDER_SECRET_ENV:
            secret = os.environ.get(name)
            if secret:
                values.add(secret)
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
