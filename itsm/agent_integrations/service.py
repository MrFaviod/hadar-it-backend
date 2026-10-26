"""Control plane for agent engines, sessions, preferences and integrations.

The service owns persisted state and the public behavior behind
``/api/v1/agent``. It never implements business authorization itself: every
operation resolves a trusted principal, delegates decisions to
``IdentityService``/Casbin and only invokes the pure engine adapters, the
catalog and the installer through their frozen boundaries.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
from sqlalchemy.orm import Session

from itsm.agent_integrations.models import (
    AgentDailyUsage,
    AgentInstallation,
    AgentInstallationPreference,
    AgentInstance,
    AgentModuleState,
    AgentPreference,
    AgentRun,
    AgentSession,
)
from itsm.agents.runtime import (
    AgentUnavailable,
    AgentUsage,
    ChatRequest,
    ConversationTurn,
)
from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.identity.permissions import (
    HUMAN_ACTOR_KIND,
    MACHINE_ACTOR_KINDS,
    ROLE_ADMIN,
    ROLE_SUPERADMIN,
)
from itsm.identity.service import (
    AuthenticationFailed,
    Conflict,
    IdentityService,
    NotFound,
    PermissionDenied,
    Principal,
    ValidationFailed,
)

logger = logging.getLogger("itsm.agent_integrations")

PYDANTIC_INSTANCE_ID = "pydantic"
PYDANTIC_ENGINE = "pydantic"
EXTERNAL_ENGINES = frozenset({"opencode", "hermes"})
INSTALLABLE_ENGINES = EXTERNAL_ENGINES
ENGINE_NAMES = frozenset({PYDANTIC_ENGINE, *EXTERNAL_ENGINES})
OPERATIONS = frozenset({"install", "verify", "update", "repair", "disable", "uninstall"})
INSTALL_STATUSES = frozenset(
    {"verified", "configured", "conflict", "disabled", "removed", "failed"}
)
INSTALLATION_PREFERENCE_ID = "installation"
SECRET_REF_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MAX_TEXT = 4000
_MAX_MESSAGE = 20000
_MAX_TOOL_JSON = 4000
_REDACTED = "[redacted]"
_REDACT_KEYS = frozenset(
    {
        "authorization",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "secret",
        "password",
        "cookie",
        "set-cookie",
        "headers",
    }
)
_DONE = object()


class BudgetExhausted(Exception):
    """The local daily policy is spent; no engine call is attempted."""

    code = "budget_exhausted"

    def __init__(self, message: str = "the daily token budget is exhausted") -> None:
        super().__init__(message)
        self.message = message


class IntegrationUnavailable(Exception):
    """The selected engine, catalog or installer cannot serve the request."""

    code = "unavailable"

    def __init__(self, message: str = "the agent integration is unavailable") -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class InstanceSnapshot:
    id: str
    name: str
    engine: str
    base_url: str | None
    secret_ref: str | None
    username: str | None
    profile: str | None
    directory: str | None
    enabled: bool
    default_model: str | None
    integration_identity_id: str | None


@dataclass
class _SessionSnapshot:
    id: str
    owner_id: str
    instance_id: str
    engine: str
    model: str
    external_session_id: str | None
    messages: list[dict[str, Any]]
    capabilities: dict[str, bool]
    asset_id: str | None


@dataclass
class Turn:
    """One claimed run; the HTTP layer only turns ``stream()`` into SSE."""

    service: AgentIntegrationService
    principal: Principal
    session: _SessionSnapshot
    instance: InstanceSnapshot
    message: str
    asset_id: str | None
    engine: Any = None
    external_session_id: str | None = None
    cancel_sent: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def stream(self) -> AsyncIterator[dict[str, Any]]:
        return self.service._stream(self)


def usage_day(now: datetime | None = None) -> str:
    return (now or utcnow()).date().isoformat()


def _tokens(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationFailed(f"{field} must be an integer")
    if value < 0:
        raise ValidationFailed(f"{field} must not be negative")
    return min(value, 1_000_000_000)


def record_usage(
    session: Session,
    day: str,
    owner_id: str,
    *,
    measured: int = 0,
    reported: int = 0,
) -> None:
    """Accumulate one run's tokens exactly once into the owner's daily row."""
    measured = max(0, int(measured))
    reported = max(0, int(reported))
    if not measured and not reported:
        return
    identifier = f"{day}:{owner_id}"
    row = session.get(AgentDailyUsage, identifier)
    if row is None:
        row = AgentDailyUsage(
            id=identifier,
            owner_id=owner_id,
            day=day,
            measured_tokens=measured,
            reported_tokens=reported,
            updated_at=utcnow(),
        )
        session.add(row)
    else:
        row.measured_tokens = int(row.measured_tokens or 0) + measured
        row.reported_tokens = int(row.reported_tokens or 0) + reported
        row.updated_at = utcnow()


def _usage_totals(session: Session, day: str, owner_id: str) -> tuple[int, int]:
    row = session.get(AgentDailyUsage, f"{day}:{owner_id}")
    if row is None:
        return 0, 0
    return int(row.measured_tokens or 0), int(row.reported_tokens or 0)


def _clean(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(char for char in value if char in "\n\t" or ord(char) >= 32).strip()
    if not cleaned:
        return None
    return cleaned[:limit]


def _label(value: Any, *, limit: int = 200) -> str | None:
    text = _clean(value, limit)
    if text is None:
        return None
    return text


def _http_url(value: Any, field_name: str) -> str:
    text = _clean(value, 2048)
    if text is None:
        raise ValidationFailed(f"{field_name} is required")
    if any(char in text for char in (" ", "\\")) or any(ord(char) < 32 for char in text):
        raise ValidationFailed(f"{field_name} must be a valid http(s) URL")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValidationFailed(f"{field_name} must be a valid http(s) URL")
    if parts.username or parts.password:
        raise ValidationFailed(f"{field_name} must not include credentials")
    if parts.query or parts.fragment:
        raise ValidationFailed(f"{field_name} must not include a query or fragment")
    try:
        _ = parts.port
    except ValueError:
        raise ValidationFailed(f"{field_name} must use a valid port") from None
    return text.rstrip("/")


def _absolute_path(value: Any, field_name: str) -> str:
    text = _clean(value, 1024)
    if text is None:
        raise ValidationFailed(f"{field_name} is required")
    if any(ord(char) < 32 for char in text):
        raise ValidationFailed(f"{field_name} must be an absolute path")
    windows = re.match(r"^[A-Za-z]:[\\/]", text)
    if not text.startswith("/") and windows is None:
        raise ValidationFailed(f"{field_name} must be an absolute path")
    return text


def _optional_text(value: Any, field_name: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed(f"{field_name} must be text")
    text = _clean(value, limit)
    if text is None:
        return None
    if any(ord(char) < 32 for char in text):
        raise ValidationFailed(f"{field_name} must not contain control characters")
    return text


def _uuid_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationFailed(f"{field_name} must be a UUID")
    try:
        UUID(value)
    except ValueError:
        raise ValidationFailed(f"{field_name} must be a UUID") from None
    return value


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    """Bound and redact engine-provided tool payloads before they reach a browser."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2000]
    if depth >= 4:
        return _REDACTED
    if isinstance(value, list):
        return [_safe_value(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 30:
                break
            name = str(key)[:80]
            if name.lower() in _REDACT_KEYS:
                result[name] = _REDACTED
            else:
                result[name] = _safe_value(item, depth=depth + 1)
        return result
    return _REDACTED


def _bounded_payload(value: Any) -> Any:
    safe = _safe_value(value)
    try:
        encoded = json.dumps(safe, ensure_ascii=False)
    except TypeError, ValueError:
        return _REDACTED
    if len(encoded) > _MAX_TOOL_JSON:
        return "[truncated]"
    return safe


def _engine_error(exc: BaseException) -> tuple[str, str, bool] | None:
    """Read the public EngineError shape without importing the adapter package."""
    code = getattr(exc, "code", None)
    message = getattr(exc, "message", None)
    retryable = getattr(exc, "retryable", None)
    if isinstance(code, str) and isinstance(message, str) and isinstance(retryable, bool):
        return code, message, retryable
    return None


class AgentIntegrationService:
    """Engine-independent orchestration with human-owned, persisted sessions."""

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session],
        *,
        runtime: Any = None,
        engine_factory: Callable[[InstanceSnapshot, str | None], Any] | None = None,
        installer: Any = None,
        catalog: Any = None,
        extension_sync: Callable[[], None] | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._runtime = runtime
        self._engine_factory = engine_factory
        self._installer = installer
        self._catalog = catalog
        self._extension_sync = extension_sync
        self._run_timeout_seconds = settings.agent_run_timeout_seconds
        self._stale_after_seconds = settings.agent_run_timeout_seconds + 60
        self._active: dict[str, Turn] = {}
        self._active_lock = threading.Lock()

    # ------------------------------------------------------------- infrastructure
    @contextmanager
    def _session(self) -> Any:
        session = self._session_factory()
        try:
            yield session
        finally:
            session.close()

    def initialize(self) -> None:
        """Seed the built-in instance and replay persisted module toggles.

        Liveness must not depend on the database. A live process may start
        before an operator runs migrations, or with a temporarily unreachable
        database, so initialization leaves the schema untouched and defers its
        persisted work until the next start. Readiness continues to report the
        database and migration state.
        """
        required = {AgentInstance.__tablename__, AgentModuleState.__tablename__}
        try:
            with self._session() as db:
                tables = set(inspect(db.get_bind()).get_table_names())
                if not required <= tables:
                    logger.warning(
                        "agent integrations initialization deferred: "
                        "database schema is not migrated"
                    )
                    return
                self._ensure_builtin(db)
        except (OperationalError, InterfaceError) as exc:
            logger.warning(
                "agent integrations initialization deferred: database unavailable (%s)",
                type(exc).__name__,
            )
            return
        self.apply_module_states()

    def _ensure_builtin(self, db: Session) -> AgentInstance:
        row = db.get(AgentInstance, PYDANTIC_INSTANCE_ID)
        if row is not None:
            return row
        row = AgentInstance(
            id=PYDANTIC_INSTANCE_ID,
            name="Pydantic AI",
            engine=PYDANTIC_ENGINE,
            enabled=True,
            default_model=self._settings.agent_model or None,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.get(AgentInstance, PYDANTIC_INSTANCE_ID)
            if existing is None:
                raise
            return existing
        return row

    def _require_human(self, principal: Principal) -> None:
        if principal.kind != HUMAN_ACTOR_KIND:
            raise ValidationFailed("the conversational agent is available to signed-in people")

    def _require_admin(
        self,
        db: Session,
        principal: Principal,
        resource: str,
        permission: str = "system.providers",
        *,
        human_only: bool = False,
    ) -> IdentityService:
        """Use the canonical reserved-permission boundary, never a second role gate."""
        from itsm.system.authorization import require_system_authority

        identity = IdentityService(db, self._settings)
        if human_only and principal.kind != HUMAN_ACTOR_KIND:
            raise PermissionDenied("installation changes require a signed-in installation owner")
        require_system_authority(db, self._settings, principal, permission, resource)
        return identity

    def _instance(self, db: Session, instance_id: str) -> AgentInstance:
        row = db.get(AgentInstance, instance_id)
        if row is None:
            raise NotFound("agent instance not found")
        return row

    @staticmethod
    def _snapshot(row: AgentInstance) -> InstanceSnapshot:
        return InstanceSnapshot(
            id=row.id,
            name=row.name,
            engine=row.engine,
            base_url=row.base_url,
            secret_ref=row.secret_ref,
            username=row.username,
            profile=row.profile,
            directory=row.directory,
            enabled=bool(row.enabled),
            default_model=row.default_model,
            integration_identity_id=row.integration_identity_id,
        )

    def _secret(self, row: AgentInstance) -> str | None:
        if not row.secret_ref:
            return None
        value = os.environ.get(row.secret_ref)
        if not value:
            raise IntegrationUnavailable("the engine credential is not configured")
        return value

    def _admin_instance(self, row: AgentInstance) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "engine": row.engine,
            "baseUrl": row.base_url,
            "secretRef": row.secret_ref,
            "secretConfigured": bool(row.secret_ref and os.environ.get(row.secret_ref)),
            "username": row.username,
            "profile": row.profile,
            "directory": row.directory,
            "enabled": bool(row.enabled),
            "defaultModel": row.default_model,
            "integrationIdentityId": row.integration_identity_id,
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }

    def _public_instance(
        self,
        row: AgentInstance,
        *,
        models: list[dict[str, Any]],
        version: str | None,
        capabilities: dict[str, bool],
        error: str | None,
    ) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "engine": row.engine,
            "profile": row.profile,
            "enabled": bool(row.enabled),
            "capabilities": capabilities,
            "version": version,
            "models": models,
            "error": error,
        }

    # ------------------------------------------------------------------ discovery
    def _build_engine(self, row: InstanceSnapshot) -> Any:
        secret = os.environ.get(row.secret_ref) if row.secret_ref else None
        if row.secret_ref and not secret:
            raise IntegrationUnavailable("the engine credential is not configured")
        if self._engine_factory is not None:
            return self._engine_factory(row, secret)
        try:
            from itsm.agents.engines import EngineConfig
            from itsm.agents.hermes import HermesEngine
            from itsm.agents.opencode import OpenCodeEngine

            config = EngineConfig(
                base_url=row.base_url or "",
                token=secret if row.engine != "opencode" else None,
                username=row.username or ("opencode" if row.engine == "opencode" else None),
                password=secret if row.engine == "opencode" else None,
                directory=row.directory,
                profile=row.profile,
            )
            adapter = OpenCodeEngine if row.engine == "opencode" else HermesEngine
            return adapter(config)
        except ImportError:
            raise IntegrationUnavailable(
                f"the {row.engine} engine adapter is not available"
            ) from None

    def _redact(self, value: str, row: InstanceSnapshot) -> str:
        text = value
        if row.base_url:
            text = text.replace(row.base_url, _REDACTED)
        secret = os.environ.get(row.secret_ref) if row.secret_ref else None
        if secret:
            text = text.replace(secret, _REDACTED)
        text = re.sub(r"Bearer\s+\S+", "Bearer " + _REDACTED, text)
        text = re.sub(
            r"(?i)\b(token|secret|password|api[_-]?key)\b\s*[:=]?\s+[^\s,;]+",
            lambda match: f"{match.group(1)} {_REDACTED}",
            text,
        )
        return _clean(text, 1000) or _REDACTED

    async def _discover(self, row: InstanceSnapshot) -> dict[str, Any]:
        if row.engine == PYDANTIC_ENGINE:
            runtime = self._runtime
            configured = (
                bool(getattr(runtime, "configured", True))
                if runtime
                else bool(self._settings.agent_model)
            )
            if not configured:
                raise IntegrationUnavailable("agent model is not configured")
            model = self._settings.agent_model
            models: list[dict[str, Any]] = []
            if model:
                provider = model.split(":", 1)[0] if ":" in model else "configured"
                models.append({"id": model, "name": model, "provider": provider, "free": None})
            return {
                "version": _package_version("pydantic-ai-slim"),
                "models": models,
                "capabilities": {
                    "streaming": False,
                    "sessions": True,
                    "model_switch": False,
                    "cancel": False,
                    "tools": True,
                    "usage": True,
                    "history": True,
                },
            }
        engine = self._build_engine(row)
        try:
            async with asyncio.timeout(self._settings.agent_engine_timeout_seconds):
                info = await engine.discover()
        except Exception as exc:
            public = _engine_error(exc)
            if public is not None:
                raise IntegrationUnavailable(self._redact(public[1], row)) from None
            logger.warning("engine discovery failed: %s", type(exc).__name__)
            raise IntegrationUnavailable("engine discovery failed") from None
        finally:
            await _quiet_close(engine)
        models = []
        for item in getattr(info, "models", []) or []:
            data = item.as_dict() if hasattr(item, "as_dict") else item
            if not isinstance(data, Mapping):
                continue
            identifier = _label(data.get("id"), limit=200)
            if identifier is None:
                continue
            free = data.get("free")
            models.append(
                {
                    "id": identifier,
                    "name": _label(data.get("name"), limit=200) or identifier,
                    "provider": _label(data.get("provider"), limit=80) or "unknown",
                    "free": free if isinstance(free, bool) else None,
                }
            )
        capabilities = {
            str(key)[:40]: bool(value)
            for key, value in dict(getattr(info, "capabilities", {}) or {}).items()
        }
        version = _label(getattr(info, "version", None), limit=64)
        return {"version": version, "models": models, "capabilities": capabilities}

    async def _safe_discover(self, row: InstanceSnapshot) -> dict[str, Any]:
        try:
            return await self._discover(row)
        except IntegrationUnavailable as exc:
            return {
                "version": None,
                "models": [],
                "capabilities": {},
                "error": str(exc),
            }

    async def _validate_model(self, row: InstanceSnapshot, model: Any) -> str:
        value = _label(model, limit=200)
        if value is None:
            raise ValidationFailed("model is required")
        info = await self._discover(row)
        available = {item["id"] for item in info["models"]}
        if value not in available:
            raise ValidationFailed("the selected model is not available on this instance")
        return value

    # ------------------------------------------------------------------- history
    def _preference(
        self, db: Session, owner_id: str
    ) -> tuple[AgentPreference | None, AgentInstallationPreference | None]:
        return (
            db.get(AgentPreference, owner_id),
            db.get(AgentInstallationPreference, INSTALLATION_PREFERENCE_ID),
        )

    def _effective_preference(
        self,
        db: Session,
        principal: Principal,
    ) -> tuple[str | None, str | None]:
        personal, installation = self._preference(db, principal.actor_id)
        for candidate in (personal, installation):
            if candidate is not None and candidate.instance_id:
                row = db.get(AgentInstance, candidate.instance_id)
                if row is not None and row.enabled:
                    return candidate.instance_id, candidate.model
        return None, None

    def _budget(self, db: Session, principal: Principal) -> dict[str, Any]:
        measured, reported = _usage_totals(db, usage_day(), principal.actor_id)
        return {
            "dailyLimit": self._settings.agent_daily_token_budget,
            "usedMeasured": measured,
            "usedReported": reported,
            "strictExternal": False,
        }

    def _budget_remaining(self, db: Session, principal: Principal) -> int | None:
        limit = self._settings.agent_daily_token_budget
        if limit <= 0:
            return None
        measured, reported = _usage_totals(db, usage_day(), principal.actor_id)
        return max(0, limit - measured - reported)

    def _check_budget(self, db: Session, principal: Principal) -> None:
        remaining = self._budget_remaining(db, principal)
        if remaining == 0:
            raise BudgetExhausted()

    # ------------------------------------------------------------- public engine API
    async def engines(self, principal: Principal) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            self._ensure_builtin(db)
            rows = db.execute(select(AgentInstance).order_by(AgentInstance.created_at)).scalars()
            snapshots = [self._snapshot(row) for row in rows]
            preference = self._effective_preference(db, principal)
            budget = self._budget(db, principal)
        instances: list[dict[str, Any]] = []
        for snapshot in snapshots:
            if not snapshot.enabled:
                instances.append(
                    self._public_instance(
                        snapshot,
                        models=[],
                        version=None,
                        capabilities={},
                        error=None,
                    )
                )
                continue
            info = await self._safe_discover(snapshot)
            instances.append(
                self._public_instance(
                    snapshot,
                    models=info["models"],
                    version=info["version"],
                    capabilities=info["capabilities"],
                    error=info.get("error"),
                )
            )
        return {
            "instances": instances,
            "preference": {"instanceId": preference[0], "model": preference[1]},
            "budget": budget,
        }

    async def save_preference(
        self, principal: Principal, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require_human(principal)
        instance_id = _label(payload.get("instanceId"), limit=36)
        if instance_id is None:
            raise ValidationFailed("instanceId is required")
        model = payload.get("model")
        if model is not None and _label(model, limit=200) is None:
            raise ValidationFailed("model must be text")
        with self._session() as db:
            self._ensure_builtin(db)
            row = db.get(AgentInstance, instance_id)
            if row is None:
                raise ValidationFailed("unknown instance")
            if not row.enabled:
                raise ValidationFailed("the selected instance is disabled")
            snapshot = self._snapshot(row)
        value: str | None = None
        if model is not None:
            if snapshot.engine == PYDANTIC_ENGINE:
                if model != self._settings.agent_model:
                    raise ValidationFailed("the built-in instance uses the server-configured model")
                value = str(model)
            else:
                value = await self._validate_model(snapshot, model)
        with self._session() as db:
            preference = db.get(AgentPreference, principal.actor_id)
            if preference is None:
                preference = AgentPreference(owner_id=principal.actor_id)
                db.add(preference)
            preference.instance_id = instance_id
            preference.model = value
            preference.updated_at = utcnow()
            db.commit()
        return {"instanceId": instance_id, "model": value}

    # -------------------------------------------------------------- admin: instances
    def admin_snapshot(self, principal: Principal) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "agent:integrations", human_only=True)
            self._ensure_builtin(db)
            instances = list(
                db.execute(select(AgentInstance).order_by(AgentInstance.created_at)).scalars()
            )
            installations = list(
                db.execute(
                    select(AgentInstallation).order_by(AgentInstallation.updated_at.desc())
                ).scalars()
            )
            installation_preference = db.get(
                AgentInstallationPreference, INSTALLATION_PREFERENCE_ID
            )
        return {
            "instances": [self._admin_instance(row) for row in instances],
            "installations": [self._installation_dto(row) for row in installations],
            "defaults": {
                "instanceId": installation_preference.instance_id
                if installation_preference
                else None,
                "model": installation_preference.model if installation_preference else None,
            },
        }

    def _instance_values(
        self,
        db: Session,
        identity: IdentityService,
        payload: Mapping[str, Any],
        *,
        engine: str,
        existing: AgentInstance | None = None,
    ) -> dict[str, Any]:
        values: dict[str, Any] = {}
        if "name" in payload or existing is None:
            name = _label(payload.get("name"), limit=120)
            if name is None:
                raise ValidationFailed("name is required")
            values["name"] = name
        if "enabled" in payload:
            enabled = payload.get("enabled")
            if not isinstance(enabled, bool):
                raise ValidationFailed("enabled must be a boolean")
            values["enabled"] = enabled
        if "defaultModel" in payload:
            values["default_model"] = _optional_text(
                payload.get("defaultModel"), "defaultModel", 200
            )

        if engine == PYDANTIC_ENGINE:
            forbidden = {
                "baseUrl",
                "secretRef",
                "username",
                "profile",
                "directory",
                "integrationIdentityId",
            }
            if forbidden & set(payload):
                raise ValidationFailed(
                    "the built-in instance does not accept engine connection fields"
                )
            return values

        if "baseUrl" in payload or existing is None:
            values["base_url"] = _http_url(payload.get("baseUrl"), "baseUrl")
        if "secretRef" in payload:
            reference = _optional_text(payload.get("secretRef"), "secretRef", 128)
            if reference is not None:
                if not SECRET_REF_PATTERN.fullmatch(reference):
                    raise ValidationFailed("secretRef must be an environment variable name")
                if not os.environ.get(reference):
                    raise ValidationFailed(
                        f"secretRef {reference} does not resolve to a configured secret"
                    )
            values["secret_ref"] = reference
        if "username" in payload:
            values["username"] = _optional_text(payload.get("username"), "username", 200)
        if "profile" in payload:
            values["profile"] = _optional_text(payload.get("profile"), "profile", 200)
        if "directory" in payload:
            directory = payload.get("directory")
            values["directory"] = (
                None if directory is None else _absolute_path(directory, "directory")
            )
        if "integrationIdentityId" in payload:
            identity_id = payload.get("integrationIdentityId")
            if identity_id is None:
                values["integration_identity_id"] = None
            else:
                identity_id = _uuid_text(identity_id, "integrationIdentityId")
                try:
                    machine = identity.resolve_actor(str(identity_id))
                except PermissionDenied:
                    raise ValidationFailed(
                        "integrationIdentityId must be an active machine identity"
                    ) from None
                if machine.kind not in MACHINE_ACTOR_KINDS:
                    raise ValidationFailed(
                        "integrationIdentityId must be an active machine identity"
                    )
                if machine.role_id in (ROLE_ADMIN, ROLE_SUPERADMIN):
                    raise ValidationFailed("machine identities cannot use an administrator role")
                values["integration_identity_id"] = identity_id
        return values

    def create_instance(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._session() as db:
            identity = self._require_admin(db, principal, "agent:integrations", human_only=True)
            engine = _label(payload.get("engine"), limit=32)
            if engine not in EXTERNAL_ENGINES:
                raise ValidationFailed("engine must be one of: hermes, opencode")
            values = self._instance_values(db, identity, payload, engine=engine)
            row = AgentInstance(id=str(uuid4()), engine=engine, **values)
            db.add(row)
            db.commit()
            db.refresh(row)
            return self._admin_instance(row)

    def update_instance(
        self, principal: Principal, instance_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._session() as db:
            identity = self._require_admin(db, principal, "agent:integrations", human_only=True)
            row = self._instance(db, instance_id)
            requested = payload.get("engine")
            if requested is not None and requested != row.engine:
                raise ValidationFailed("an instance engine cannot be changed")
            values = self._instance_values(db, identity, payload, engine=row.engine, existing=row)
            if row.engine != PYDANTIC_ENGINE and not values.get("base_url", row.base_url):
                raise ValidationFailed("baseUrl is required")
            for key, value in values.items():
                setattr(row, key, value)
            row.updated_at = utcnow()
            db.commit()
            db.refresh(row)
            return self._admin_instance(row)

    async def set_defaults(
        self, principal: Principal, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "agent:integrations", human_only=True)
            self._ensure_builtin(db)
            instance_id = payload.get("instanceId")
            if instance_id is None:
                instance_id = None
            elif _label(instance_id, limit=36) is None:
                raise ValidationFailed("instanceId is required")
            model = payload.get("model")
            if instance_id is not None:
                row = self._instance(db, str(instance_id))
                if not row.enabled:
                    raise ValidationFailed("the selected instance is disabled")
                snapshot = self._snapshot(row)
                if model is not None:
                    if snapshot.engine == PYDANTIC_ENGINE:
                        if model != self._settings.agent_model:
                            raise ValidationFailed(
                                "the built-in instance uses the server-configured model"
                            )
                    else:
                        model = await self._validate_model(snapshot, model)
                instance_id = row.id
            elif model is not None:
                raise ValidationFailed("model requires an instanceId")
            preference = db.get(AgentInstallationPreference, INSTALLATION_PREFERENCE_ID)
            if preference is None:
                preference = AgentInstallationPreference(id=INSTALLATION_PREFERENCE_ID)
                db.add(preference)
            preference.instance_id = instance_id
            preference.model = model
            preference.updated_at = utcnow()
            db.commit()
        return {"instanceId": instance_id, "model": model}

    # ------------------------------------------------------------------ sessions
    def _owned(self, db: Session, principal: Principal, session_id: str) -> AgentSession:
        row = db.get(AgentSession, session_id)
        if row is None or row.owner_id != principal.actor_id:
            raise NotFound("agent session not found")
        return row

    def _session_dto(self, row: AgentSession) -> dict[str, Any]:
        return {
            "id": row.id,
            "instanceId": row.instance_id,
            "engine": row.engine,
            "model": row.model,
            "status": row.status,
            "messages": list(row.messages or []),
            "actions": list(row.actions or []),
            "results": list(row.results or []),
            "approvalPending": bool(row.approval_pending),
            "assetId": row.asset_id,
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }

    def _session_summary(self, row: AgentSession) -> dict[str, Any]:
        return {
            "id": row.id,
            "instanceId": row.instance_id,
            "engine": row.engine,
            "model": row.model,
            "status": row.status,
            "messageCount": len(row.messages or []),
            "assetId": row.asset_id,
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }

    def list_sessions(self, principal: Principal) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            rows = db.execute(
                select(AgentSession)
                .where(AgentSession.owner_id == principal.actor_id)
                .order_by(AgentSession.updated_at.desc())
            ).scalars()
            return {"sessions": [self._session_summary(row) for row in rows]}

    def get_session(self, principal: Principal, session_id: str) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            return self._session_dto(self._owned(db, principal, session_id))

    def _context_messages(self, context: Any) -> list[dict[str, str]]:
        if context is None:
            return []
        if not isinstance(context, list):
            raise ValidationFailed("context must be a list of messages")
        if len(context) > self._settings.agent_session_max_context_messages:
            raise ValidationFailed("context has too many messages")
        messages: list[dict[str, str]] = []
        for item in context:
            if not isinstance(item, Mapping):
                raise ValidationFailed("context messages must be objects")
            if set(item) - {"role", "content"}:
                raise ValidationFailed("context messages accept only role and content")
            role = item.get("role")
            if role not in {"user", "assistant"}:
                raise ValidationFailed("context role must be user or assistant")
            content = item.get("content")
            if not isinstance(content, str) or not content.strip():
                raise ValidationFailed("context content is required")
            if len(content) > 8000:
                raise ValidationFailed("context content is too long")
            messages.append({"role": role, "content": content})
        return messages

    @staticmethod
    def _instance_runtime_binding(row: AgentInstance, target: Any) -> dict[str, Any]:
        return {
            "engine": row.engine,
            "baseUrl": row.base_url,
            "secretRef": row.secret_ref,
            "username": row.username,
            "profile": row.profile,
            "directory": target.path,
            "integrationIdentityId": row.integration_identity_id,
        }

    def _installation_matches_instance(
        self, installation: AgentInstallation, row: AgentInstance
    ) -> bool:
        receipt = installation.receipt if isinstance(installation.receipt, Mapping) else {}
        bound = receipt.get("instanceBinding")
        if not isinstance(bound, Mapping):
            return False
        if bound.get("engine") != row.engine:
            return False
        if bound.get("baseUrl") != row.base_url:
            return False
        if bound.get("secretRef") != row.secret_ref:
            return False
        if bound.get("username") != row.username:
            return False
        if bound.get("profile") != row.profile:
            return False
        if bound.get("integrationIdentityId") != row.integration_identity_id:
            return False
        if bound.get("directory") != installation.path:
            return False
        return row.directory is None or bound.get("directory") == row.directory

    def _verified_installation(self, db: Session, row: AgentInstance) -> AgentInstallation | None:
        query = select(AgentInstallation).where(
            AgentInstallation.instance_id == row.id,
            AgentInstallation.engine == row.engine,
            AgentInstallation.status == "verified",
            AgentInstallation.verified.is_(True),
        )
        if row.profile is None:
            query = query.where(AgentInstallation.profile.is_(None))
        else:
            query = query.where(AgentInstallation.profile == row.profile)
        installations = db.execute(query.order_by(AgentInstallation.updated_at.desc())).scalars()
        return next(
            (
                installation
                for installation in installations
                if self._installation_matches_instance(installation, row)
            ),
            None,
        )

    def _profile_verified(self, db: Session, row: AgentInstance) -> bool:
        receipt = self._verified_installation(db, row)
        if receipt is None:
            return False
        if row.integration_identity_id:
            binding = (receipt.receipt or {}).get("identityId")
            if binding is not None and binding != row.integration_identity_id:
                return False
        return True

    def _require_verified_profile(self, db: Session, row: AgentInstance) -> None:
        if row.engine == PYDANTIC_ENGINE:
            return
        if not self._profile_verified(db, row):
            raise Conflict("the integration profile has not been verified by the installer")

    def _assert_binding_ceiling(
        self,
        db: Session,
        identity: IdentityService,
        principal: Principal,
        row: AgentInstance,
    ) -> None:
        if not row.integration_identity_id:
            raise Conflict("the instance is not bound to an integration identity")
        installation = self._verified_installation(db, row)
        if installation is None:
            # The profile gate below reports the missing verified installation.
            return
        mcp = (installation.receipt or {}).get("mcp")
        secret_ref = mcp.get("secretRef") if isinstance(mcp, Mapping) else None
        token = os.environ.get(secret_ref) if isinstance(secret_ref, str) else None
        if not token:
            raise PermissionDenied("the integration credential is not available")
        try:
            context = identity.authenticate_token(token)
        except AuthenticationFailed:
            raise PermissionDenied("the integration credential is not valid") from None
        if context.principal.actor_id != row.integration_identity_id:
            raise PermissionDenied(
                "the integration credential does not belong to the bound identity"
            )
        human_permissions = identity._persisted_permissions(principal)
        machine_permissions = context.permissions
        if machine_permissions - human_permissions:
            raise PermissionDenied(
                "the integration identity has permissions this person does not hold"
            )

    def _session_capabilities(self, engine: str, info: Mapping[str, Any] | None) -> dict[str, bool]:
        if engine == PYDANTIC_ENGINE:
            return {
                "streaming": False,
                "sessions": True,
                "model_switch": False,
                "cancel": False,
                "tools": True,
                "usage": True,
                "history": True,
            }
        return dict((info or {}).get("capabilities") or {})

    async def create_session(
        self, principal: Principal, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require_human(principal)
        instance_id = _label(payload.get("instanceId"), limit=36)
        if instance_id is None:
            raise ValidationFailed("instanceId is required")
        model = _label(payload.get("model"), limit=200)
        if model is None:
            raise ValidationFailed("model is required")
        asset_id = _uuid_text(payload.get("assetId"), "assetId")
        context = self._context_messages(payload.get("context"))

        with self._session() as db:
            self._ensure_builtin(db)
            row = self._instance(db, instance_id)
            if not row.enabled:
                raise ValidationFailed("the selected instance is disabled")
            identity = IdentityService(db, self._settings)
            if row.engine != PYDANTIC_ENGINE:
                self._assert_binding_ceiling(db, identity, principal, row)
                self._require_verified_profile(db, row)
            snapshot = self._snapshot(row)
        capabilities: dict[str, bool] = self._session_capabilities(row.engine, None)
        external_session_id: str | None = None
        if snapshot.engine == PYDANTIC_ENGINE:
            if not self._runtime_configured():
                raise IntegrationUnavailable("agent model is not configured")
            if model != self._settings.agent_model:
                raise ValidationFailed("the built-in instance uses the server-configured model")
        else:
            info = await self._discover(snapshot)
            available = {item["id"] for item in info["models"]}
            if model not in available:
                raise ValidationFailed("the selected model is not available on this instance")
            capabilities = self._session_capabilities(snapshot.engine, info)
            engine = self._build_engine(snapshot)
            try:
                async with asyncio.timeout(self._settings.agent_engine_timeout_seconds):
                    external_session_id = await engine.create_session()
            except Exception as exc:
                public = _engine_error(exc)
                if public is not None:
                    raise IntegrationUnavailable(self._redact(public[1], snapshot)) from None
                logger.warning("engine session creation failed: %s", type(exc).__name__)
                raise IntegrationUnavailable("the engine could not create a session") from None
            finally:
                await _quiet_close(engine)
            if not isinstance(external_session_id, str) or not external_session_id:
                raise IntegrationUnavailable("the engine did not create a session")

        with self._session() as db:
            current = db.get(AgentInstance, instance_id)
            if current is None or not current.enabled:
                raise Conflict("the selected instance changed while starting the session")
            row = AgentSession(
                id=str(uuid4()),
                owner_id=principal.actor_id,
                instance_id=snapshot.id,
                engine=snapshot.engine,
                model=model,
                status="idle",
                external_session_id=external_session_id,
                messages=context,
                actions=[],
                results=[],
                approval_pending=False,
                asset_id=asset_id,
                cancel_requested=False,
                capabilities=capabilities,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            return self._session_dto(row)

    def _runtime_configured(self) -> bool:
        if self._runtime is not None:
            return bool(getattr(self._runtime, "configured", True))
        return bool(self._settings.agent_model)

    async def update_session_model(
        self, principal: Principal, session_id: str, model: Any
    ) -> dict[str, Any]:
        self._require_human(principal)
        value = _label(model, limit=200)
        if value is None:
            raise ValidationFailed("model is required")
        with self._session() as db:
            row = self._owned(db, principal, session_id)
            if row.status == "running":
                raise Conflict("a response is already running in this session")
            instance = self._instance(db, row.instance_id)
            snapshot = self._snapshot(instance)
        capabilities = self._session_capabilities(row.engine, None)
        if row.engine != PYDANTIC_ENGINE and not capabilities.get("model_switch", True):
            raise Conflict("the selected engine does not support changing models")
        if snapshot.engine == PYDANTIC_ENGINE:
            if value != self._settings.agent_model:
                raise ValidationFailed("the built-in instance uses the server-configured model")
        else:
            value = await self._validate_model(snapshot, value)
        with self._session() as db:
            row = self._owned(db, principal, session_id)
            if row.status == "running":
                raise Conflict("a response is already running in this session")
            row.model = value
            row.updated_at = utcnow()
            db.commit()
            return self._session_dto(row)

    async def cancel_session(self, principal: Principal, session_id: str) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            row = self._owned(db, principal, session_id)
            if row.status != "running":
                return {"cancelled": False, "reason": "no active run"}
            capabilities = dict(row.capabilities or {})
            if row.engine == PYDANTIC_ENGINE or not capabilities.get("cancel", False):
                return {"cancelled": False, "reason": "engine does not support cancellation"}
            row.cancel_requested = True
            row.updated_at = utcnow()
            db.commit()
            external_id = row.external_session_id
        with self._active_lock:
            turn = self._active.get(session_id)
        if turn is None or turn.engine is None:
            return {"cancelled": False, "reason": "the run has not reached the engine yet"}
        try:
            await turn.engine.cancel(turn.external_session_id or external_id or "")
        except Exception:
            logger.warning("engine cancellation failed: %s", "engine")
            return {"cancelled": False, "reason": "the engine did not confirm cancellation"}
        turn.cancel_sent = True
        return {"cancelled": True}

    # ---------------------------------------------------------------- run claiming
    def _recover_stale(self, db: Session, now: datetime) -> None:
        threshold = now - timedelta(seconds=self._stale_after_seconds)
        rows = db.execute(
            select(AgentSession)
            .where(AgentSession.status == "running", AgentSession.updated_at < threshold)
            .limit(20)
        ).scalars()
        for row in rows:
            row.status = "idle"
            row.cancel_requested = False
            row.updated_at = now
        runs = db.execute(
            select(AgentRun)
            .where(AgentRun.status == "running", AgentRun.started_at < threshold)
            .limit(50)
        ).scalars()
        for run in runs:
            run.status = "stale"
            run.finished_at = now
        db.commit()

    def prepare_turn(
        self,
        principal: Principal,
        session_id: str,
        message: str,
        asset_id: str | None,
    ) -> Turn:
        self._require_human(principal)
        if not isinstance(message, str) or not message.strip():
            raise ValidationFailed("message is required")
        if len(message) > self._settings.agent_message_max_length:
            raise ValidationFailed(
                f"message must be at most {self._settings.agent_message_max_length} characters"
            )
        asset_id = _uuid_text(asset_id, "assetId")
        now = utcnow()
        with self._session() as db:
            row = self._owned(db, principal, session_id)
            instance = self._instance(db, row.instance_id)
            if not instance.enabled:
                raise Conflict("the selected instance is disabled")
            identity = IdentityService(db, self._settings)
            if row.engine != PYDANTIC_ENGINE:
                self._assert_binding_ceiling(db, identity, principal, instance)
                self._require_verified_profile(db, instance)
            elif not self._runtime_configured():
                raise IntegrationUnavailable("agent model is not configured")
            self._check_budget(db, principal)
            self._recover_stale(db, now)
            if row.status == "running":
                raise Conflict("a response is already running in this session")
            messages = list(row.messages or [])
            messages.append({"role": "user", "content": message})
            row.messages = messages
            row.status = "running"
            row.cancel_requested = False
            row.asset_id = asset_id
            row.updated_at = now
            db.add(
                AgentRun(
                    id=str(uuid4()),
                    session_id=row.id,
                    owner_id=principal.actor_id,
                    status="running",
                    started_at=now,
                )
            )
            db.commit()
            snapshot = _SessionSnapshot(
                id=row.id,
                owner_id=row.owner_id,
                instance_id=row.instance_id,
                engine=row.engine,
                model=row.model,
                external_session_id=row.external_session_id,
                messages=messages,
                capabilities=dict(row.capabilities or {}),
                asset_id=asset_id,
            )
            instance_snapshot = self._snapshot(instance)
        turn = Turn(
            service=self,
            principal=principal,
            session=snapshot,
            instance=instance_snapshot,
            message=message,
            asset_id=asset_id,
            external_session_id=snapshot.external_session_id,
        )
        with self._active_lock:
            self._active[session_id] = turn
        return turn

    # ------------------------------------------------------------------ streaming
    async def _stream(self, turn: Turn) -> AsyncIterator[dict[str, Any]]:
        text = ""
        actions: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        approval = False
        cancelled = False
        error_seen: dict[str, Any] | None = None
        measured = 0
        reported = 0
        completed = False
        try:
            if turn.session.engine != PYDANTIC_ENGINE and turn.engine is None:
                with turn.lock:
                    if turn.engine is None:
                        turn.engine = self._build_engine(turn.instance)
            yield {"type": "session", "sessionId": turn.session.id}
            async for event in self._events(turn):
                kind = event["type"]
                if kind == "delta":
                    text = (text + event["text"])[-_MAX_MESSAGE:]
                elif kind == "usage":
                    tokens = int(event["inputTokens"]) + int(event["outputTokens"])
                    if event["source"] == "measured":
                        measured += tokens
                    else:
                        reported += tokens
                elif kind == "error":
                    error_seen = event
                elif kind == "done":
                    cancelled = bool(event.get("cancelled"))
                    completed = True
                    break
                yield event
        except asyncio.CancelledError:
            cancelled = True
            await self._cancel_engine_quietly(turn)
            raise
        except Exception as exc:
            error_seen = self._exception_event(exc, turn.instance)
            yield error_seen
        finally:
            runtime_usage = getattr(turn, "_usage", None)
            if runtime_usage is not None and not measured:
                measured = runtime_usage.input_tokens + runtime_usage.output_tokens
            if not completed:
                wait = 2.0
                try:
                    async with asyncio.timeout(wait):
                        await self._cancel_engine_quietly(turn)
                except Exception:
                    pass
            self._finish(
                turn,
                text=text,
                actions=actions,
                results=results,
                approval=approval,
                measured=measured,
                reported=reported,
                cancelled=cancelled or not completed,
                failed=error_seen is not None,
            )
        done: dict[str, Any] = {"type": "done", "cancelled": cancelled}
        if turn.session.engine == PYDANTIC_ENGINE:
            reply = getattr(turn, "_reply", None)
            if reply is not None:
                actions = [action.model_dump() for action in reply.actions]
                results = list(reply.results)
                approval = bool(reply.approvalPending)
            done["actions"] = actions
            done["results"] = results
            done["approvalPending"] = approval
        yield done

    async def _events(self, turn: Turn) -> AsyncIterator[dict[str, Any]]:
        if turn.session.engine == PYDANTIC_ENGINE:
            async for event in self._pydantic_events(turn):
                yield event
            return
        async for event in self._external_events(turn):
            yield event

    async def _pydantic_events(self, turn: Turn) -> AsyncIterator[dict[str, Any]]:
        runtime = self._runtime
        if runtime is None:
            from itsm.agents.runtime import AgentRuntime

            runtime = AgentRuntime(self._settings, self._session_factory)
        history = [
            ConversationTurn(role=item["role"], content=item["content"][:8000])
            for item in turn.session.messages[:-1]
            if item.get("role") in {"user", "assistant"}
        ]
        history = history[-self._settings.agent_max_history_messages :]
        if not self._settings.agent_max_history_messages:
            history = []
        request = ChatRequest(
            message=turn.message,
            conversation=history,
            assetId=turn.asset_id,
        )
        with self._session() as db:
            remaining = self._budget_remaining(db, turn.principal)
        usage = AgentUsage()
        if hasattr(runtime, "chat_with_usage"):
            try:
                reply, usage = await asyncio.to_thread(
                    runtime.chat_with_usage,
                    turn.principal,
                    request,
                    credential_digest=None,
                    usage=usage,
                    token_limit=remaining,
                )
            except BaseException:
                turn._usage = usage  # type: ignore[attr-defined]
                raise
        else:
            reply = await asyncio.to_thread(runtime.chat, turn.principal, request)
        turn._usage = usage  # type: ignore[attr-defined]
        turn._reply = reply  # type: ignore[attr-defined]
        if usage.input_tokens or usage.output_tokens:
            yield {
                "type": "usage",
                "inputTokens": usage.input_tokens,
                "outputTokens": usage.output_tokens,
                "source": "measured",
            }
        for action in reply.actions:
            yield {
                "type": "tool",
                "tool": action.tool,
                "status": action.status,
            }
        if reply.message:
            yield {"type": "delta", "text": reply.message}
        yield {"type": "done", "cancelled": False}

    async def _external_events(self, turn: Turn) -> AsyncIterator[dict[str, Any]]:
        with turn.lock:
            engine = turn.engine or self._build_engine(turn.instance)
            turn.engine = engine
        external_id = turn.external_session_id
        try:
            async with asyncio.timeout(self._run_timeout_seconds):
                if not external_id:
                    external_id = await engine.create_session()
                    turn.external_session_id = external_id
                elif self._cancel_requested(turn.session.id) and not turn.cancel_sent:
                    await engine.cancel(external_id)
                history = [
                    {"role": item["role"], "content": item["content"][:8000]}
                    for item in turn.session.messages[:-1]
                    if item.get("role") in {"user", "assistant"}
                ]
                if self._settings.agent_max_history_messages:
                    history = history[-self._settings.agent_max_history_messages :]
                else:
                    history = []
                attempt = 0
                while True:
                    produced = False
                    try:
                        async for raw in engine.stream(
                            turn.message,
                            session_id=external_id,
                            model=turn.session.model,
                            history=history,
                        ):
                            normalized = self._normalize_event(raw, turn)
                            if normalized is None:
                                continue
                            produced = True
                            yield normalized
                            if normalized["type"] == "done":
                                return
                        return
                    except Exception as exc:
                        public = _engine_error(exc)
                        if (
                            public is not None
                            and public[0] in {"not_found", "session_not_found"}
                            and not produced
                            and attempt == 0
                            and external_id
                        ):
                            attempt += 1
                            external_id = await engine.create_session()
                            turn.external_session_id = external_id
                            continue
                        raise
        except TimeoutError:
            yield {
                "type": "error",
                "code": "timeout",
                "message": "the engine did not finish within the configured limit",
                "retryable": True,
            }
        finally:
            await _quiet_close(engine)

    def _cancel_requested(self, session_id: str) -> bool:
        with self._session() as db:
            row = db.get(AgentSession, session_id)
            return bool(row and row.cancel_requested)

    def _normalize_event(self, raw: Any, turn: Turn) -> dict[str, Any] | None:
        if not isinstance(raw, Mapping):
            return None
        kind = raw.get("type")
        if kind == "delta":
            text = raw.get("text")
            if not isinstance(text, str) or not text:
                return None
            return {"type": "delta", "text": text[-_MAX_MESSAGE:]}
        if kind == "tool":
            tool = _label(raw.get("tool"), limit=120)
            if tool is None:
                return None
            status = raw.get("status")
            if status == "error":
                status = "failed"
            elif status not in {"running", "completed", "failed", "denied"}:
                status = "running"
            event: dict[str, Any] = {"type": "tool", "tool": tool, "status": status}
            if "input" in raw:
                event["input"] = _bounded_payload(raw.get("input"))
            if "output" in raw:
                event["output"] = _bounded_payload(raw.get("output"))
            return event
        if kind == "usage":
            source = raw.get("source")
            if source not in {"measured", "reported"}:
                return None
            try:
                input_tokens = _tokens(raw.get("inputTokens", 0), field="inputTokens")
                output_tokens = _tokens(raw.get("outputTokens", 0), field="outputTokens")
            except ValidationFailed:
                return None
            event = {
                "type": "usage",
                "inputTokens": input_tokens,
                "outputTokens": output_tokens,
                "source": source,
            }
            cost = raw.get("cost")
            if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
                event["cost"] = float(cost)
            return event
        if kind == "error":
            code = _label(raw.get("code"), limit=64) or "engine_error"
            message = _clean(raw.get("message"), 1000)
            if message is None:
                message = "the engine reported an error"
            message = self._redact(message, turn.instance)
            retryable = raw.get("retryable")
            return {
                "type": "error",
                "code": code,
                "message": message,
                "retryable": bool(retryable) if isinstance(retryable, bool) else False,
            }
        if kind == "done":
            cancelled = raw.get("cancelled")
            return {
                "type": "done",
                "cancelled": bool(cancelled) if isinstance(cancelled, bool) else False,
            }
        return None

    def _exception_event(self, exc: BaseException, instance: InstanceSnapshot) -> dict[str, Any]:
        import asyncio as _asyncio

        if isinstance(exc, AgentUnavailable):
            return {
                "type": "error",
                "code": "unavailable",
                "message": "agent model is not configured",
                "retryable": False,
            }
        if isinstance(exc, IntegrationUnavailable):
            return {
                "type": "error",
                "code": "unavailable",
                "message": self._redact(str(exc), instance),
                "retryable": True,
            }
        public = _engine_error(exc)
        if public is not None:
            return {
                "type": "error",
                "code": public[0],
                "message": self._redact(public[1], instance),
                "retryable": public[2],
            }
        if exc.__class__.__name__ == "UsageLimitExceeded":
            return {
                "type": "error",
                "code": "budget_exhausted",
                "message": "the daily token budget was reached during this response",
                "retryable": False,
            }
        if isinstance(exc, _asyncio.TimeoutError):
            return {
                "type": "error",
                "code": "timeout",
                "message": "the engine did not finish within the configured limit",
                "retryable": True,
            }
        logger.warning("agent turn failed: %s", type(exc).__name__)
        return {
            "type": "error",
            "code": "agent_failed",
            "message": "the agent could not complete the response",
            "retryable": True,
        }

    async def _cancel_engine_quietly(self, turn: Turn) -> None:
        with turn.lock:
            engine = turn.engine
        if engine is None or not turn.session.capabilities.get("cancel", False):
            return
        identifier = turn.external_session_id or turn.session.external_session_id
        if not identifier:
            return
        try:
            await engine.cancel(identifier)
        except Exception:
            logger.warning("engine cancellation failed during cleanup")

    def _finish(
        self,
        turn: Turn,
        *,
        text: str,
        actions: list[dict[str, Any]],
        results: list[dict[str, Any]],
        approval: bool,
        measured: int,
        reported: int,
        cancelled: bool,
        failed: bool,
    ) -> None:
        now = utcnow()
        with self._active_lock:
            self._active.pop(turn.session.id, None)
        with self._session() as db:
            row = db.get(AgentSession, turn.session.id)
            if row is not None:
                messages = list(row.messages or [])
                if text:
                    messages.append({"role": "assistant", "content": text[-_MAX_MESSAGE:]})
                row.messages = messages
                row.status = "idle"
                row.cancel_requested = False
                row.updated_at = now
                if row.engine == PYDANTIC_ENGINE:
                    reply = getattr(turn, "_reply", None)
                    if reply is not None:
                        row.actions = [action.model_dump() for action in reply.actions]
                        row.results = list(reply.results)
                        row.approval_pending = bool(reply.approvalPending)
                else:
                    row.actions = []
                    row.results = []
                    row.approval_pending = False
                if turn.external_session_id:
                    row.external_session_id = turn.external_session_id
            run = db.execute(
                select(AgentRun)
                .where(AgentRun.session_id == turn.session.id, AgentRun.status == "running")
                .order_by(AgentRun.started_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if run is not None:
                if cancelled:
                    run.status = "cancelled"
                elif failed:
                    run.status = "failed"
                else:
                    run.status = "completed"
                run.finished_at = now
            record_usage(
                db, usage_day(now), turn.principal.actor_id, measured=measured, reported=reported
            )
            db.commit()

    # ----------------------------------------------------------------- install
    def _installer_instance(self) -> Any:
        if self._installer is not None:
            return self._installer
        try:
            from itsm.agent_integrations.installer import IntegrationInstaller

            self._installer = IntegrationInstaller(catalog=self._catalog_instance())
        except ImportError:
            raise IntegrationUnavailable("the integration installer is not available") from None
        return self._installer

    def _catalog_instance(self) -> Any:
        if self._catalog is not None:
            return self._catalog
        try:
            from itsm.agent_integrations.catalog import SkillCatalog

            self._catalog = SkillCatalog()
        except ImportError:
            raise IntegrationUnavailable("the skills catalog is not available") from None
        return self._catalog

    def _target(self, payload: Mapping[str, Any], *, engine: str | None = None) -> Any:
        if not isinstance(payload, Mapping):
            raise ValidationFailed("target is required")
        target_engine = _label(payload.get("engine"), limit=32)
        if target_engine not in INSTALLABLE_ENGINES:
            raise ValidationFailed("target engine must be one of: hermes, opencode")
        if engine is not None and target_engine != engine:
            raise ValidationFailed("target engine must match the instance engine")
        path = _absolute_path(payload.get("path"), "target.path")
        profile = _optional_text(payload.get("profile"), "target.profile", 200)
        version = _optional_text(payload.get("version"), "target.version", 64)
        self._target_remote(payload)
        from itsm.agent_integrations.installer import IntegrationTarget

        return IntegrationTarget(
            engine=target_engine,
            path=path,
            profile=profile,
            version=version,
        )

    def _target_remote(self, payload: Mapping[str, Any]) -> bool:
        remote = payload.get("remote", False)
        if not isinstance(remote, bool):
            raise ValidationFailed("target.remote must be a boolean")
        return remote

    def _mcp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValidationFailed("mcp is required")
        url = _http_url(payload.get("url"), "mcp.url")
        reference = _label(payload.get("secretRef"), limit=128)
        if reference is None:
            raise ValidationFailed("mcp.secretRef is required")
        if not SECRET_REF_PATTERN.fullmatch(reference):
            raise ValidationFailed("mcp.secretRef must be an environment variable name")
        identity_id = _uuid_text(payload.get("identityId"), "mcp.identityId")
        if identity_id is None:
            raise ValidationFailed("mcp.identityId is required")
        return {"url": url, "secretRef": reference, "identityId": identity_id}

    def _skills(self, payload: Any) -> list[str]:
        if payload is None:
            return []
        if not isinstance(payload, list) or any(not isinstance(item, str) for item in payload):
            raise ValidationFailed("skills must be a list of names")
        names = list(dict.fromkeys(item.strip() for item in payload if item.strip()))
        if len(names) > 50:
            raise ValidationFailed("too many skills selected")
        catalog = self._catalog_instance()
        available = {item["name"] for item in catalog.list_skills()}
        unknown = [name for name in names if name not in available]
        if unknown:
            raise ValidationFailed("unknown or disabled skills: " + ", ".join(sorted(unknown)))
        return names

    async def detect_target(
        self, principal: Principal, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "agent:integrations", human_only=True)
        remote = self._target_remote(payload)
        target = self._target(payload)
        installer = self._installer_instance()
        try:
            async with asyncio.timeout(self._settings.agent_install_timeout_seconds):
                detection = await installer.detect_target(target)
        except TimeoutError:
            raise IntegrationUnavailable("target detection timed out") from None
        except Exception as exc:
            public = _engine_error(exc)
            if public is not None:
                raise IntegrationUnavailable(public[1]) from None
            raise IntegrationUnavailable("target detection failed") from None
        return {
            "target": {
                "engine": target.engine,
                "path": target.path,
                "profile": target.profile,
                "version": target.version,
                "remote": remote,
            },
            "detection": _bounded_installer_payload(detection),
        }

    def _installation_row(
        self, db: Session, instance_id: str, target: Any
    ) -> AgentInstallation | None:
        return db.execute(
            select(AgentInstallation).where(
                AgentInstallation.instance_id == instance_id,
                AgentInstallation.engine == target.engine,
                AgentInstallation.path == target.path,
                AgentInstallation.profile.is_(None)
                if target.profile is None
                else AgentInstallation.profile == target.profile,
            )
        ).scalar_one_or_none()

    async def install(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        operation = _label(payload.get("operation"), limit=16) or "install"
        if operation not in OPERATIONS:
            raise ValidationFailed("operation is not supported")
        with self._session() as db:
            self._require_admin(db, principal, "agent:integrations", human_only=True)
            instance = self._instance(db, str(payload.get("instanceId") or ""))
            if instance.engine not in INSTALLABLE_ENGINES:
                raise ValidationFailed("the built-in instance has no external installation")
            if not instance.enabled:
                raise Conflict("the selected instance is disabled")
            target = self._target(payload.get("target"), engine=instance.engine)
            if instance.directory is not None and target.path != instance.directory:
                raise ValidationFailed("target.path must match the configured instance directory")
            if instance.profile != target.profile:
                raise ValidationFailed("target.profile must match the configured instance profile")
            existing = self._installation_row(db, instance.id, target)
            if operation != "install" and existing is None:
                raise ValidationFailed("the installation does not exist yet")
            stored = dict(existing.receipt or {}) if existing is not None else {}
            if payload.get("mcp") is not None:
                mcp = self._mcp(payload.get("mcp"))
            elif isinstance(stored.get("mcp"), Mapping):
                mcp = {
                    "url": stored["mcp"].get("url"),
                    "secretRef": stored["mcp"].get("secretRef"),
                    "identityId": stored["mcp"].get("identityId"),
                }
                mcp = self._mcp(mcp)
            else:
                raise ValidationFailed("mcp is required for the first installation")
            if (
                instance.integration_identity_id
                and mcp["identityId"] != instance.integration_identity_id
            ):
                raise ValidationFailed(
                    "the MCP identity must match the instance integration identity"
                )
            if not instance.integration_identity_id:
                raise ValidationFailed(
                    "the instance must be bound to an integration identity first"
                )
            if not os.environ.get(mcp["secretRef"]):
                raise ValidationFailed("mcp.secretRef does not resolve to a configured secret")
            if payload.get("skills") is not None:
                skills = self._skills(payload.get("skills"))
            elif existing is not None:
                skills = _string_list(
                    (stored.get("binding") or {}).get("skills") or stored.get("skills")
                )
            else:
                raise ValidationFailed("skills are required for the first installation")
            instance_snapshot = self._snapshot(instance)
        installer = self._installer_instance()
        remote_mode = self._remote_mode(payload)
        if remote_mode:
            sanitized = await self._export_request(target, mcp, skills, operation, existing=stored)
        else:

            async def inspect_profile(
                *,
                target: Any,
                mcp: Mapping[str, Any],
                skills: Sequence[str],
                config_digest: str,
            ) -> dict[str, Any] | None:
                return await self._opencode_profile_safety(
                    instance_snapshot,
                    target,
                    mcp,
                    list(skills),
                    {"configDigest": config_digest},
                )

            try:
                async with asyncio.timeout(self._settings.agent_install_timeout_seconds):
                    receipt = await installer.apply(
                        target,
                        mcp=dict(mcp),
                        skills=skills,
                        operation=operation,
                        profile_inspector=(
                            inspect_profile if target.engine == "opencode" else None
                        ),
                    )
            except TimeoutError:
                raise IntegrationUnavailable("the installer timed out") from None
            except Exception as exc:
                public = _engine_error(exc)
                if public is not None:
                    raise IntegrationUnavailable(public[1]) from None
                raise IntegrationUnavailable("the installer failed") from None
            if not isinstance(receipt, Mapping):
                raise IntegrationUnavailable("the installer returned no receipt")
            sanitized = _sanitize_receipt(dict(receipt), os.environ.get(mcp["secretRef"]))
        row = self._store_installation(
            principal, instance_snapshot, target, operation, sanitized, mcp
        )
        installed = self._installation_dto(row, include_request=True)
        if remote_mode:
            installed["status"] = "exported"
        return installed

    def _remote_mode(self, payload: Mapping[str, Any]) -> bool:
        mode = payload.get("mode", "local")
        if mode not in {"local", "remote"}:
            raise ValidationFailed("mode must be local or remote")
        return mode == "remote"

    async def _export_request(
        self,
        target: Any,
        mcp: Mapping[str, str],
        skills: list[str],
        operation: str,
        *,
        existing: Mapping[str, Any],
    ) -> dict[str, Any]:
        from itsm.agent_integrations.installer import build_request

        binding = existing.get("binding") if isinstance(existing, Mapping) else None
        expected = binding.get("manifestDigest") if isinstance(binding, Mapping) else None
        try:
            async with asyncio.timeout(self._settings.agent_install_timeout_seconds):
                request = build_request(
                    target,
                    mcp=dict(mcp),
                    skills=skills,
                    operation=operation,
                    expected_manifest_digest=expected,
                    catalog=self._catalog_instance(),
                )
        except TimeoutError:
            raise IntegrationUnavailable("building the remote request timed out") from None
        except Exception as exc:
            public = _engine_error(exc)
            if public is not None:
                raise IntegrationUnavailable(public[1]) from None
            raise IntegrationUnavailable(
                "the installer could not build the remote request"
            ) from None
        if not isinstance(request, Mapping):
            raise IntegrationUnavailable("the installer returned no remote request")
        request = dict(request)
        digest = request.get("requestDigest")
        if not isinstance(digest, str) or not digest:
            raise IntegrationUnavailable("the installer returned no request digest")
        return {
            "status": "configured",
            "verified": False,
            "mcpVerified": False,
            "profileSafetyVerified": False,
            "version": target.version,
            "managedFiles": [],
            "conflicts": [],
            "checks": [
                {
                    "name": "remote.request",
                    "status": "pending",
                    "detail": "run the helper on the target host and import its receipt",
                }
            ],
            "limitations": [
                "no target file access: the helper receipt must prove file and profile safety",
            ],
            "engine": target.engine,
            "profile": target.profile,
            "identityId": mcp["identityId"],
            "skills": list(skills),
            "mcp": dict(mcp),
            "request": request,
            "requestDigest": digest,
        }

    def _store_installation(
        self,
        principal: Principal,
        instance: Any,
        target: Any,
        operation: str,
        receipt: Mapping[str, Any],
        mcp: Mapping[str, str],
    ) -> AgentInstallation:
        sanitized = _sanitize_receipt(dict(receipt), os.environ.get(mcp["secretRef"]))
        status = sanitized.get("status")
        if status not in INSTALL_STATUSES:
            status = "failed"
        verified = (
            sanitized.get("verified") is True
            and status == "verified"
            and sanitized.get("profileSafetyVerified") is True
            and _check_passed(sanitized, "profile.safety")
        )
        managed = _string_list(sanitized.get("managedFiles"))
        conflicts = _string_list(sanitized.get("conflicts"))
        checks = sanitized.get("checks")
        binding = {
            key: sanitized[key]
            for key in (
                "engine",
                "profile",
                "format",
                "configFile",
                "skills",
                "identityId",
                "manifestVersion",
                "manifestDigest",
                "configDigest",
                "request",
            )
            if key in sanitized
        }
        with self._session() as db:
            identity = self._require_admin(db, principal, "agent:integrations", human_only=True)
            row = self._installation_row(db, instance.id, target)
            runtime_binding = self._instance_runtime_binding(instance, target)
            if row is None:
                row = AgentInstallation(
                    id=str(uuid4()),
                    instance_id=instance.id,
                    engine=target.engine,
                    path=target.path,
                    profile=target.profile,
                )
                db.add(row)
            row.version = _label(sanitized.get("version"), limit=64)
            row.operation = operation
            row.status = str(status)
            row.verified = verified
            row.receipt = {
                **sanitized,
                "managedFiles": managed,
                "conflicts": conflicts,
                "checks": checks if isinstance(checks, list) else [],
                "binding": binding,
                "instanceBinding": runtime_binding,
                "mcp": dict(mcp),
            }
            row.updated_at = utcnow()
            db.commit()
            identity.record_operation(
                principal,
                action=f"agent.integration.{operation}",
                resource=f"agent:{instance.id}",
            )
        return row

    async def import_receipt(
        self, principal: Principal, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        installation_id = _label(payload.get("installationId"), limit=64)
        instance_id = _label(payload.get("instanceId"), limit=36)
        receipt = payload.get("receipt")
        if not isinstance(receipt, Mapping):
            raise ValidationFailed("receipt must be an object")
        receipt = dict(receipt)
        try:
            encoded = json.dumps(receipt)
        except TypeError, ValueError:
            raise ValidationFailed("receipt must be JSON data") from None
        if len(encoded) > 512_000:
            raise ValidationFailed("receipt is too large")
        with self._session() as db:
            self._require_admin(db, principal, "agent:integrations", human_only=True)
            if installation_id is not None:
                row = db.get(AgentInstallation, installation_id)
                if row is None:
                    raise NotFound("installation not found")
            elif instance_id is not None:
                candidates = list(
                    db.execute(
                        select(AgentInstallation)
                        .where(AgentInstallation.instance_id == instance_id)
                        .order_by(AgentInstallation.updated_at.desc())
                    ).scalars()
                )
                row = next(
                    (
                        candidate
                        for candidate in candidates
                        if isinstance((candidate.receipt or {}).get("request"), Mapping)
                    ),
                    None,
                )
                if row is None:
                    raise NotFound("the instance has no exported installation request")
            else:
                raise ValidationFailed("installationId or instanceId is required")
            if instance_id is not None and row.instance_id != instance_id:
                raise ValidationFailed("the installation belongs to another instance")
            instance = self._instance(db, row.instance_id)
            stored = dict(row.receipt or {})
            request = stored.get("request")
            stored_mcp = stored.get("mcp")
            if not isinstance(request, Mapping) or not isinstance(stored_mcp, Mapping):
                raise ValidationFailed("the installation has no exported request")
            mcp = self._mcp(stored_mcp)
            if instance.integration_identity_id != mcp["identityId"]:
                raise Conflict("the installation identity is no longer bound")
            target = self._target(
                {
                    "engine": row.engine,
                    "path": row.path,
                    "profile": row.profile,
                    "version": row.version,
                },
                engine=row.engine,
            )
            skills = _string_list((stored.get("binding") or {}).get("skills"))
            expected_digest = stored.get("requestDigest")
            provided_digest = (
                _label(payload.get("requestDigest"), limit=200)
                or receipt.get("requestDigest")
                or (receipt.get("binding") or {}).get("requestDigest")
            )
            if expected_digest and provided_digest and provided_digest != expected_digest:
                raise ValidationFailed("the receipt belongs to a different request")
            for key, expected in (
                ("engine", row.engine),
                ("profile", row.profile),
                ("version", row.version),
                ("identityId", mcp["identityId"]),
            ):
                if receipt.get(key) not in (None, expected):
                    raise ValidationFailed(f"receipt {key} does not match the installation")
            from itsm.agent_integrations.installer import validate_receipt

            instance_snapshot = self._snapshot(instance)
            try:
                async with asyncio.timeout(self._settings.agent_install_timeout_seconds):
                    validation = validate_receipt(receipt, request=dict(request))
            except TimeoutError:
                raise IntegrationUnavailable("receipt validation timed out") from None
            if not _validated(validation):
                raise ValidationFailed("the receipt does not match the exported request")
            connection = await self._verify_connection(mcp)
            connection_ok = bool(connection.get("verified"))
            sanitized = _sanitize_receipt(receipt, os.environ.get(mcp["secretRef"]))
            safety = (
                await self._opencode_profile_safety(
                    instance_snapshot, target, mcp, skills, sanitized
                )
                if target.engine == "opencode"
                else None
            )
            independent_safe = bool(safety and safety.get("verified") is True)
            claimed = sanitized.get("verified") is True and sanitized.get("status") == "verified"
            status = "verified" if claimed and independent_safe and connection_ok else "configured"
            if sanitized.get("status") == "failed":
                status = "failed"
            sanitized["status"] = status
            sanitized["verified"] = status == "verified"
            sanitized["mcpVerified"] = connection_ok
            sanitized["profileSafetyVerified"] = independent_safe
            checks = [
                dict(check)
                for check in sanitized.get("checks") or []
                if isinstance(check, Mapping)
                and check.get("name") not in {"profile.safety", "control.profile", "control.mcp"}
            ]
            checks.append(
                {
                    "name": "control.profile",
                    "status": "pass" if independent_safe else "fail",
                    "detail": (
                        "independently inspected effective agent runtime profile"
                        if independent_safe
                        else "no authenticated engine runtime safety inspection was available"
                    ),
                }
            )
            checks.append(
                {
                    "name": "control.mcp",
                    "status": "pass" if connection_ok else "fail",
                    "detail": "independently verified MCP handshake and authorized query",
                }
            )
            sanitized["checks"] = checks
            sanitized["request"] = dict(request)
            sanitized["requestDigest"] = expected_digest or provided_digest
            sanitized["engine"] = row.engine
            sanitized["profile"] = row.profile
            sanitized["version"] = row.version
            sanitized["identityId"] = mcp["identityId"]
            sanitized["skills"] = skills
        row = self._store_installation(principal, instance, target, row.operation, sanitized, mcp)
        return self._installation_dto(row, include_request=True)

    async def _verify_connection(self, mcp: Mapping[str, str]) -> dict[str, Any]:
        from itsm.agent_integrations.installer import verify_connection

        try:
            async with asyncio.timeout(self._settings.agent_install_timeout_seconds):
                result = await verify_connection(dict(mcp))
        except TimeoutError:
            return {"verified": False, "checks": [{"name": "control.mcp", "status": "fail"}]}
        except Exception as exc:
            public = _engine_error(exc)
            logger.warning("MCP verification failed: %s", type(exc).__name__)
            return {
                "verified": False,
                "checks": [
                    {
                        "name": "control.mcp",
                        "status": "fail",
                        "detail": public[1] if public else "verification failed",
                    }
                ],
            }
        if not isinstance(result, Mapping):
            return {"verified": False, "checks": []}
        return {
            "verified": result.get("verified") is True,
            "checks": list(result.get("checks") or []),
        }

    async def _opencode_profile_safety(
        self,
        instance: Any,
        target: Any,
        mcp: Mapping[str, str],
        skills: list[str],
        receipt: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Inspect the authenticated OpenCode runtime; return evidence or None."""
        digest = receipt.get("configDigest")
        if not isinstance(digest, str) or not digest:
            return None
        base_url = getattr(instance, "base_url", None) or ""
        secret_ref = getattr(instance, "secret_ref", None)
        token = os.environ.get(secret_ref) if isinstance(secret_ref, str) else None
        if not token or not base_url:
            return None
        username = getattr(instance, "username", None) or "opencode"
        params = {"location[directory]": target.path}
        try:
            import httpx

            async with httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                auth=(username, token),
                timeout=min(self._settings.agent_engine_timeout_seconds, 30),
            ) as client:
                config_response = await client.get("/api/config", params=params)
                agent_response = await client.get("/api/agent/itsm", params=params)
                if agent_response.status_code == 404:
                    created_response = await client.post(
                        "/api/session",
                        json={
                            "title": "ITSM installation profile inspection",
                            "location": {"directory": target.path},
                        },
                    )
                    if created_response.status_code != 200:
                        return None
                    try:
                        created = created_response.json()
                        created_data = created.get("data") if isinstance(created, Mapping) else None
                        session_id = (
                            created_data.get("id") if isinstance(created_data, Mapping) else None
                        )
                        location = (
                            created_data.get("location")
                            if isinstance(created_data, Mapping)
                            else None
                        )
                        if (
                            not isinstance(session_id, str)
                            or not session_id
                            or not isinstance(location, Mapping)
                            or location.get("directory") != target.path
                        ):
                            if isinstance(session_id, str) and session_id:
                                await client.delete(f"/api/session/{quote(session_id, safe='')}")
                            return None
                    except ValueError:
                        return None
                    try:
                        agent_response = await client.get("/api/agent/itsm", params=params)
                    finally:
                        deleted = await client.delete(f"/api/session/{quote(session_id, safe='')}")
                        if deleted.status_code != 200:
                            logger.warning(
                                "OpenCode inspection session cleanup returned %s",
                                deleted.status_code,
                            )
                grants_response = await client.get("/api/permission/saved")
        except Exception as exc:
            logger.warning("OpenCode runtime inspection failed: %s", type(exc).__name__)
            return None
        if any(
            response.status_code != 200
            for response in (config_response, agent_response, grants_response)
        ):
            return None
        try:
            entries = config_response.json()
            agent_payload = agent_response.json()
            grants = grants_response.json()
        except ValueError:
            return None
        effective = _effective_config(entries)
        if effective is None:
            return None
        if not _config_selects_directory(entries, target.path):
            return None
        server = (effective.get("mcp") or {}).get("servers", {}).get("itsm")
        if not isinstance(server, Mapping) or server.get("type") != "remote":
            return None
        if str(server.get("url") or "").rstrip("/") != mcp["url"].rstrip("/"):
            return None
        if server.get("disabled") is True:
            return None
        headers = server.get("headers")
        authorization = (
            str(headers.get("Authorization") or "") if isinstance(headers, Mapping) else ""
        )
        mcp_secret = os.environ.get(mcp["secretRef"])
        expected_headers = {f"Bearer {{env:{mcp['secretRef']}}}"}
        if mcp_secret:
            expected_headers.add(f"Bearer {mcp_secret}")
        if authorization not in expected_headers:
            return None
        configured_skills = {
            str(item) for item in effective.get("skills") or [] if isinstance(item, str)
        }
        missing = [name for name in skills if name not in configured_skills]
        if missing:
            return None
        if effective.get("default_agent") != "itsm":
            return None
        agent_info = agent_payload.get("data") if isinstance(agent_payload, Mapping) else None
        if not isinstance(agent_info, Mapping) or agent_info.get("id") != "itsm":
            return None
        if agent_info.get("mode") not in {"primary", "all"}:
            return None
        permissions = agent_info.get("permissions")
        if not _restrictive_permissions(permissions, skills):
            return None
        grant_items = grants.get("data") if isinstance(grants, Mapping) else None
        if not isinstance(grant_items, list):
            return None
        if any(_broad_grant(item, skills) for item in grant_items):
            return None
        discovered = await self._discover(instance)
        observed_version = discovered.get("version")
        if target.version and observed_version and target.version != observed_version:
            return None
        checks = [
            {
                "name": "inspection.config",
                "status": "pass",
                "detail": "effective mcp/skills/default_agent",
            },
            {
                "name": "inspection.agent",
                "status": "pass",
                "detail": "itsm agent permissions inspected",
            },
            {
                "name": "inspection.grants",
                "status": "pass",
                "detail": "no broad saved permission grants",
            },
            {
                "name": "inspection.version",
                "status": "pass",
                "detail": observed_version or "unreported",
            },
        ]
        projected_config: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            if entry.get("type") == "directory" and isinstance(entry.get("path"), str):
                projected_config.append({"type": "directory", "path": entry["path"]})
            elif entry.get("type") == "document":
                info = entry.get("info")
                projected: dict[str, Any] = {"type": "document"}
                if isinstance(entry.get("path"), str):
                    projected["path"] = entry["path"]
                if isinstance(info, Mapping) and "default_agent" in info:
                    projected["info"] = {"default_agent": info["default_agent"]}
                projected_config.append(projected)
        projected_agent = {
            "id": agent_info.get("id"),
            "mode": agent_info.get("mode"),
            "permissions": [
                {
                    "action": rule.get("action"),
                    "resource": rule.get("resource"),
                    "effect": rule.get("effect"),
                }
                for rule in permissions
                if isinstance(rule, Mapping)
            ],
        }
        projected_grants = [
            {
                "action": item.get("action"),
                "resource": item.get("resource"),
                "effect": item.get("effect"),
            }
            for item in grant_items
            if isinstance(item, Mapping)
        ]
        return {
            "verified": True,
            "source": f"opencode:{base_url.rstrip('/')}",
            "configDigest": digest,
            "targetPath": target.path,
            "location": {"directory": target.path},
            "agent": projected_agent,
            "config": projected_config,
            "savedPermissions": projected_grants,
            "checks": checks,
        }

    def _installation_dto(
        self, row: AgentInstallation, *, include_request: bool = False
    ) -> dict[str, Any]:
        receipt = dict(row.receipt or {})
        binding = dict(receipt.get("binding") or {})
        request = receipt.get("request")
        remote = isinstance(request, Mapping)
        if remote:
            binding.setdefault("requestDigest", receipt.get("requestDigest"))
        stored_mcp = receipt.get("mcp") if isinstance(receipt.get("mcp"), Mapping) else {}
        skills = _string_list(binding.get("skills") or receipt.get("skills"))
        payload = {
            "id": row.id,
            "instanceId": row.instance_id,
            "target": {
                "engine": row.engine,
                "path": row.path,
                "profile": row.profile,
                "version": row.version,
                "remote": remote,
            },
            "skills": skills,
            "mcp": {
                "url": stored_mcp.get("url"),
                "secretRef": stored_mcp.get("secretRef"),
                "identityId": stored_mcp.get("identityId"),
            },
            "status": row.status,
            "verified": bool(row.verified),
            "mcpVerified": bool(receipt.get("mcpVerified", False)),
            "profileSafetyVerified": bool(receipt.get("profileSafetyVerified", False)),
            "checks": list(receipt.get("checks") or []),
            "conflicts": list(receipt.get("conflicts") or []),
            "binding": binding,
            "requestDigest": receipt.get("requestDigest"),
            "operation": row.operation,
            "managedFiles": list(receipt.get("managedFiles") or []),
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }
        if include_request and isinstance(request, Mapping):
            payload["request"] = dict(request)
        return payload

    def installation_request(self, principal: Principal, installation_id: str) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "agent:integrations", human_only=True)
            row = db.get(AgentInstallation, installation_id)
            if row is None:
                raise NotFound("installation not found")
            receipt = dict(row.receipt or {})
            request = receipt.get("request")
            if not isinstance(request, Mapping):
                raise Conflict("the installation has no exported remote request")
            return {
                "request": dict(request),
                "requestDigest": receipt.get("requestDigest"),
                "installation": self._installation_dto(row),
            }

    # ------------------------------------------------------------------ modules
    def catalog_snapshot(self, principal: Principal) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "agent:catalog", permission="system.modules")
        catalog = self._catalog_instance()
        return {
            "skills": list(catalog.list_skills()),
            "modules": list(catalog.list_modules()),
        }

    def list_modules(self, principal: Principal) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "agent:catalog", permission="system.modules")
        catalog = self._catalog_instance()
        return {"modules": list(catalog.list_modules())}

    def apply_module_states(self) -> None:
        if self._catalog is None:
            return
        with self._session() as db:
            rows = list(db.execute(select(AgentModuleState)).scalars())
        for row in rows:
            try:
                self._catalog.set_module_enabled(row.module_id, bool(row.enabled))
            except Exception:
                logger.warning("module state could not be applied: %s", row.module_id)
        if self._extension_sync is not None:
            self._extension_sync()

    def set_module(
        self, principal: Principal, module_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise ValidationFailed("enabled must be a boolean")
        with self._session() as db:
            self._require_admin(db, principal, "agent:catalog", permission="system.modules")
        catalog = self._catalog_instance()
        try:
            module = catalog.get_module(module_id)
        except Exception as exc:
            if exc.__class__.__name__ in {
                "UnknownModule",
                "CatalogModuleNotFound",
                "KeyError",
                "StopIteration",
                "LookupError",
            }:
                raise NotFound("module not found") from None
            raise
        if module.get("official") and not enabled:
            raise Conflict("the official ITSM module cannot be disabled")
        with self._session() as db:
            row = db.get(AgentModuleState, module_id)
            if row is None:
                row = AgentModuleState(module_id=module_id)
                db.add(row)
            row.enabled = enabled
            row.updated_at = utcnow()
            db.commit()
        catalog.set_module_enabled(module_id, enabled)
        if self._extension_sync is not None:
            self._extension_sync()
        return {"id": module_id, "enabled": enabled, "registered": True}


def _package_version(name: str) -> str:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return "unknown"


async def _quiet_close(engine: Any) -> None:
    close = getattr(engine, "close", None)
    if close is None:
        return
    try:
        await close()
    except Exception:
        logger.warning("engine close failed")


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:500] for item in value if isinstance(item, (str, int, float))][:200]


def _sanitize_receipt(value: dict[str, Any], secret: str | None) -> dict[str, Any]:
    if secret:
        encoded = json.dumps(value, ensure_ascii=False, default=str)
        if secret in encoded:
            encoded = encoded.replace(secret, _REDACTED)
            try:
                value = json.loads(encoded)
            except json.JSONDecodeError:
                return {
                    "status": "failed",
                    "verified": False,
                    "checks": ["receipt redaction failed"],
                }
    return value


def _bounded_installer_payload(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return _safe_value(value)
    return {str(key)[:80]: _safe_value(item) for key, item in list(value.items())[:50]}


__all__ = [
    "EXTERNAL_ENGINES",
    "INSTALL_STATUSES",
    "OPERATIONS",
    "PYDANTIC_ENGINE",
    "PYDANTIC_INSTANCE_ID",
    "AgentIntegrationService",
    "BudgetExhausted",
    "IntegrationUnavailable",
    "Turn",
    "record_usage",
    "usage_day",
]


def _validated(result: Any) -> bool:
    """Accept the installer receipt-validation result only when explicitly valid."""
    if isinstance(result, bool):
        return result
    if isinstance(result, Mapping):
        if "valid" in result:
            return result.get("valid") is True
        if "ok" in result:
            return result.get("ok") is True and not result.get("errors")
        return not result.get("errors")
    return False


def _check_passed(receipt: Mapping[str, Any], name: str) -> bool:
    checks = receipt.get("checks")
    if not isinstance(checks, list):
        return False
    for check in checks:
        if not isinstance(check, Mapping):
            continue
        if check.get("name") == name or check.get("id") == name:
            return check.get("status") == "pass"
    return False


def _effective_config(entries: Any) -> dict[str, Any] | None:
    """Fold OpenCode Config.Entry documents from lowest to highest priority."""
    if not isinstance(entries, list):
        return None
    effective: dict[str, Any] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or entry.get("type") != "document":
            continue
        info = entry.get("info")
        if not isinstance(info, Mapping):
            continue
        for key, value in info.items():
            if key == "mcp" and isinstance(value, Mapping):
                current = effective.setdefault("mcp", {})
                if not isinstance(current, dict):
                    current = {}
                    effective["mcp"] = current
                servers = value.get("servers")
                if isinstance(servers, Mapping):
                    existing = current.setdefault("servers", {})
                    if isinstance(existing, dict):
                        existing.update(servers)
                for option, option_value in value.items():
                    if option != "servers":
                        current[option] = option_value
            elif key == "agents" and isinstance(value, Mapping):
                current = effective.setdefault("agents", {})
                if isinstance(current, dict):
                    current.update(value)
            else:
                effective[key] = value
    return effective or None


def _config_selects_directory(entries: Any, directory: str) -> bool:
    """Require the inspected config to include the exact selected workspace root."""
    if not isinstance(entries, list) or not isinstance(directory, str) or not directory:
        return False
    expected = os.path.realpath(directory)
    for entry in entries:
        if (
            isinstance(entry, Mapping)
            and entry.get("type") == "directory"
            and isinstance(entry.get("path"), str)
            and os.path.realpath(entry["path"]) == expected
        ):
            return True
    return False


def _restrictive_permissions(permissions: Any, skills: list[str]) -> bool:
    """Require deny-all then only ITSM tools and exactly the selected skills."""
    if not isinstance(permissions, list) or not permissions:
        return False
    deny_all = False
    itsm_allow = False
    allowed_skills: set[str] = set()
    requested_skills = set(skills)
    for rule in permissions:
        if not isinstance(rule, Mapping):
            return False
        action = str(rule.get("action") or "")
        resource = str(rule.get("resource") or "*")
        effect = rule.get("effect")
        if not action:
            return False
        if effect == "deny":
            if action == "*" and resource == "*":
                deny_all = True
            continue
        if effect != "allow":
            return False
        if action == "skill":
            if resource in requested_skills and resource != "*":
                allowed_skills.add(resource)
                continue
            return False
        if action.startswith("itsm_") and len(action) > len("itsm_") and resource == "*":
            itsm_allow = True
            continue
        return False
    return deny_all and itsm_allow and allowed_skills == requested_skills


def _broad_grant(item: Any, skills: list[str]) -> bool:
    """A saved allow grant must stay inside ITSM tools/skills."""
    if not isinstance(item, Mapping) or item.get("effect") != "allow":
        return False
    action = str(item.get("action") or "")
    resource = str(item.get("resource") or "")
    if action == "skill":
        return resource not in set(skills) or resource == "*"
    return not (action.startswith("itsm_") and len(action) > len("itsm_") and resource == "*")
