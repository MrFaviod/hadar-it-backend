"""Typed configuration for the ITSM backend foundation.

Settings come from process environment variables with the ``ITSM_`` prefix.
No ``.env`` file is loaded or committed: deployment supplies values through the
container environment or a secret manager.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
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

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class PersonalPrivateEndpoint:
    """One deployment-authorized private destination for personal providers.

    An entry is either a network (a CIDR or a single address) or an exact
    hostname with an optional port. Matching is always performed against the
    address this process resolved, never against a caller-supplied label.
    """

    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    host: str | None = None
    port: int | None = None

    def contains(self, address: str) -> bool:
        """True when the resolved address falls inside this network entry."""
        if self.network is None:
            return False
        parsed = _address(address)
        if parsed is None:
            return False
        return parsed in self.network

    def matches_host(self, host: str, port: int | None) -> bool:
        """True for the exact hostname (case-insensitive) and allowed port."""
        if self.host is None or self.host != host.rstrip(".").lower():
            return False
        return self.port is None or self.port == port

    def describe(self) -> str:
        """Canonical text used in configuration errors and diagnostics."""
        if self.network is not None:
            return str(self.network)
        return f"{self.host}:{self.port}" if self.port is not None else str(self.host)


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


def _endpoint_port(value: str | None) -> int | None:
    if value is None:
        return None
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError("port is outside 1-65535")
    return int(value)


def _parse_endpoint_entry(entry: str) -> PersonalPrivateEndpoint:
    try:
        return PersonalPrivateEndpoint(network=ipaddress.ip_network(entry, strict=False))
    except ValueError:
        pass
    if entry.count(":") > 1:
        # Unbracketed IPv6 with a port is ambiguous and never silently guessed.
        raise ValueError("an IPv6 entry must be a bare address or CIDR")
    host, separator, port_text = entry.partition(":")
    port = _endpoint_port(port_text if separator else None)
    normalized = host.rstrip(".").lower()
    labels = normalized.split(".")
    if (
        not normalized
        or len(normalized) > 253
        or not all(_HOST_LABEL.match(label) for label in labels)
    ):
        raise ValueError("entry is neither a CIDR, an address nor an exact hostname")
    return PersonalPrivateEndpoint(host=normalized, port=port)


def parse_personal_private_endpoints(raw: str) -> tuple[PersonalPrivateEndpoint, ...]:
    """Parse ``ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS``; an exact blank disables it.

    Entries are comma-separated CIDRs, single addresses or exact
    ``hostname[:port]`` values. Empty or malformed entries fail closed instead
    of silently widening the deployment's private destination policy.
    """
    text = raw.strip()
    if not text:
        return ()
    entries: list[PersonalPrivateEndpoint] = []
    for position, item in enumerate(text.split(","), start=1):
        entry = item.strip()
        if not entry:
            raise ValueError(f"ai_personal_private_endpoints entry {position} is empty")
        try:
            parsed = _parse_endpoint_entry(entry)
        except ValueError as exc:
            raise ValueError(
                f"ai_personal_private_endpoints entry {position} is not a CIDR, "
                "address or hostname[:port]"
            ) from exc
        if parsed not in entries:
            entries.append(parsed)
    return tuple(entries)


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
    demo_data_directory: Path | None = None

    # Public demo exposure limits. They are only built when the release mode
    # capability set is the public demo (``itsm.limits``); ``prod`` and ``dev``
    # never construct a limiter, so these values cannot change their behaviour.
    # ``trusted_proxy`` is the single opt-in for honouring ``X-Forwarded-For``:
    # without it the header is attacker-controlled and ignored.
    demo_rate_limit_per_minute: int = Field(default=180, ge=1, le=100_000)
    demo_rate_limit_burst: int = Field(default=60, ge=1, le=100_000)
    demo_login_rate_per_minute: int = Field(default=10, ge=1, le=10_000)
    demo_login_rate_burst: int = Field(default=5, ge=1, le=10_000)
    demo_max_request_body_bytes: int = Field(default=1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    demo_attachment_max_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    demo_attachment_quota_bytes: int = Field(default=100 * 1024 * 1024, ge=0, le=1024 * 1024 * 1024)
    demo_max_active_sessions: int = Field(default=50, ge=1, le=10_000)
    demo_max_in_flight: int = Field(default=8, ge=1, le=1024)
    trusted_proxy: bool = False

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
    agent_engine_timeout_seconds: int = Field(default=15, ge=1, le=120)
    agent_run_timeout_seconds: int = Field(default=180, ge=10, le=900)
    agent_install_timeout_seconds: int = Field(default=120, ge=10, le=600)
    agent_daily_token_budget: int = Field(default=200_000, ge=0, le=100_000_000)
    # Optional operator-declared upper bound for input billed tokens per call.
    # No bound means honest admission-only control, not strict token counting.
    agent_context_token_bound: int | None = Field(default=None, ge=1, le=100_000_000)
    agent_session_max_context_messages: int = Field(default=40, ge=0, le=50)
    agent_extension_modules: list[str] = Field(default_factory=list)
    extension_workspace_path: Path = Path("/data/extensions/workspaces")
    extension_data_path: Path = Path("/data/extensions/data")
    extension_validator_image: str = "itsm-extension-validator:1"
    extension_validation_timeout_seconds: int = Field(default=60, ge=5, le=300)
    # Optional fixed host validator: application containers never receive Docker authority.
    extension_validator_url: str | None = None
    extension_validator_token: SecretStr | None = None
    # Ordinary human roles run Pydantic AI in a container owned by this broker.
    # The API never receives container authority; the URL and token must be
    # configured together or the isolated path is explicitly unavailable.
    ai_broker_url: str | None = None
    ai_broker_token: SecretStr | None = None
    # Disposable managed engines are opt-in; no fallback to shared native state.
    ai_managed_hermes_binary: str | None = None
    ai_managed_opencode_binary: str | None = None
    ai_managed_profile_root: str | None = None
    ai_managed_gateway_url: str | None = None
    ai_managed_startup_timeout_seconds: int = Field(default=30, ge=1, le=120)
    ai_managed_shutdown_timeout_seconds: int = Field(default=10, ge=1, le=60)
    # Fixed host launch inspector, separate from engine credentials and user input.
    hermes_inspector_url: str | None = None
    hermes_inspector_token: SecretStr | None = None
    # Externally supplied Fernet key ring for provider credentials, as a
    # comma-separated list where the first entry encrypts and the rest only
    # decrypt. Absent or blank means credential writing is honestly unavailable;
    # the process never generates a key or stores one in the database.
    ai_credential_keys: SecretStr | None = None
    # Legacy single key, kept for deployments and rows that still use it: it is
    # appended to the ring as a decryption-only key when not already present.
    ai_credential_key: SecretStr | None = None
    # Private destinations a personal provider may reach; empty keeps the
    # public-HTTPS-only default. CIDRs, single addresses or exact
    # hostname[:port] values, matched against the resolved address.
    ai_personal_private_endpoints: str = ""

    # Operator-configured external executor. ITSM never receives host, shell or
    # container authority; it only calls fixed actions on this trusted endpoint.
    system_executor_url: str = ""
    system_executor_token: SecretStr | None = None
    system_executor_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    # Optional maintenance-published backup summary. The API only reads this
    # small JSON file: it never runs backup tools, never opens an engine socket
    # and never mutates an artifact. Unset means the summary is honestly
    # unavailable instead of fabricated.
    backup_status_path: Path | None = None

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
    meilisearch_api_key: SecretStr | None = None
    meilisearch_http_timeout_seconds: int = Field(default=5, ge=1, le=60)
    search_index_name: str = Field(default="itsm_entities", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    search_sync_batch_size: int = Field(default=100, ge=1, le=500)
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
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in normalized
            )
            or parts.netloc.endswith(":")
            or (port is not None and port < 1)
        ):
            raise ValueError(
                "report base URL must use http(s) without credentials, query or fragment"
            )
        return normalized

    @field_validator(
        "prometheus_url", "alertmanager_url", "monitoring_public_url", "meilisearch_url"
    )
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
        "meilisearch_api_key",
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

    @field_validator("extension_workspace_path", "extension_data_path")
    @classmethod
    def _validate_extension_storage_path(cls, value: Path) -> Path:
        resolved = Path(value).expanduser().resolve()
        backend = BACKEND_ROOT.resolve()
        if resolved == backend or backend in resolved.parents:
            raise ValueError(
                "extension storage must not live inside the backend source tree; "
                "the build environment cannot write the core repository"
            )
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

    @field_validator(
        "ai_broker_url",
        "ai_broker_token",
        "hermes_inspector_url",
        "hermes_inspector_token",
        mode="before",
    )
    @classmethod
    def _empty_optional_runtime_adapter(cls, value: Any) -> Any:
        """Compose exports empty optional adapter variables when disabled."""
        return None if value == "" else value

    @field_validator("hermes_inspector_url")
    @classmethod
    def _validate_hermes_inspector_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or re.search(r"\s", normalized)
        ):
            raise ValueError("hermes_inspector_url must be an http(s) URL without credentials")
        return normalized

    @field_validator("extension_validator_url")
    @classmethod
    def _validate_extension_validator_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.path
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or re.search(r"\s", normalized)
        ):
            raise ValueError("extension_validator_url must be an http(s) URL without credentials")
        return normalized

    @field_validator("extension_validator_token", mode="before")
    @classmethod
    def _normalize_extension_validator_token(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("ai_broker_url")
    @classmethod
    def _validate_ai_broker_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("ai_broker_url must not be blank")
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            raise ValueError("ai_broker_url must be a ws(s) URL with a host")
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or re.search(r"\s", normalized)
        ):
            raise ValueError("ai_broker_url must not contain credentials, query or whitespace")
        return normalized

    @field_validator("ai_broker_token", "hermes_inspector_token", "extension_validator_token")
    @classmethod
    def _validate_ai_broker_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value()
        if len(raw) < 32:
            raise ValueError("service token must contain at least 32 characters")
        if any(character.isspace() for character in raw):
            raise ValueError("service token must not contain whitespace")
        return value

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

    @field_validator("ai_personal_private_endpoints")
    @classmethod
    def _validate_personal_private_endpoints(cls, value: str) -> str:
        """Reject malformed allowlist entries at configuration time."""
        parse_personal_private_endpoints(value)
        return value.strip()

    @field_validator("ai_credential_key")
    @classmethod
    def _normalize_ai_credential_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        return value if value.get_secret_value().strip() else None

    @field_validator("ai_credential_keys")
    @classmethod
    def _validate_ai_credential_keys(cls, value: SecretStr | None) -> SecretStr | None:
        """Reject a malformed ring by position without echoing any key text.

        Compose exports an empty optional variable when the feature is disabled,
        so an exactly blank value means ``disabled`` rather than an error.
        """
        if value is None:
            return None
        raw = value.get_secret_value().strip()
        if not raw:
            return None
        for position, entry in enumerate((part.strip() for part in raw.split(",")), start=1):
            if not entry:
                raise ValueError(f"ai_credential_keys entry {position} is empty")
            try:
                Fernet(entry.encode("ascii"))
            except ValueError, TypeError, UnicodeEncodeError:
                raise ValueError(
                    f"ai_credential_keys entry {position} is not a valid Fernet key"
                ) from None
        return value

    @field_validator("system_executor_url")
    @classmethod
    def _validate_system_executor_url(cls, value: str) -> str:
        if not value:
            return ""
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("system_executor_url must be an http(s) URL with a host")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("system_executor_url must not contain credentials or query")
        if re.search(r"\s", value):
            raise ValueError("system_executor_url must not contain whitespace")
        return value.rstrip("/")

    @field_validator("system_executor_token")
    @classmethod
    def _validate_system_executor_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value()
        if raw and len(raw) < 16:
            raise ValueError("system_executor_token must contain at least 16 characters")
        return value

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
        self._reject_extension_core_overlap()
        if self.auth_password_max_length <= self.auth_password_min_length:
            raise ValueError("auth_password_max_length must exceed auth_password_min_length")
        if (self.ai_broker_url is None) != (self.ai_broker_token is None):
            raise ValueError("ai_broker_url and ai_broker_token must be configured together")
        if (self.hermes_inspector_url is None) != (self.hermes_inspector_token is None):
            raise ValueError(
                "hermes_inspector_url and hermes_inspector_token must be configured together"
            )
        if (self.extension_validator_url is None) != (self.extension_validator_token is None):
            raise ValueError(
                "extension_validator_url and extension_validator_token must be configured together"
            )
        return self

    def _reject_extension_core_overlap(self) -> None:
        """Keep extension storage and workspace strictly outside the core DB file."""
        url = make_url(self.database_url)
        if not url.drivername.startswith("sqlite") or not url.database:
            return
        core_path = Path(url.database).resolve()
        for label, raw in (
            ("extension_data_path", self.extension_data_path),
            ("extension_workspace_path", self.extension_workspace_path),
        ):
            path = Path(raw).expanduser().resolve()
            if path == core_path or path in core_path.parents or core_path in path.parents:
                raise ValueError(
                    f"{label} must not equal, contain or live inside the core SQLite database file"
                )

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
        if self.ai_credential_keys is not None:
            raw_ring = self.ai_credential_keys.get_secret_value()
            if raw_ring:
                values.add(raw_ring)
                values.update(part.strip() for part in raw_ring.split(",") if part.strip())
        for secret in (
            self.prometheus_token,
            self.alertmanager_token,
            self.monitoring_ingest_token,
            self.monitoring_discovery_token,
            self.system_executor_token,
            self.meilisearch_api_key,
            self.ai_credential_key,
            self.ai_broker_token,
            self.hermes_inspector_token,
            self.extension_validator_token,
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
