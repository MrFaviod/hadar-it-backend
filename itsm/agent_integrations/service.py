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
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

from sqlalchemy import inspect, select, update
from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
from sqlalchemy.orm import Session

from itsm.agent_integrations.models import (
    AgentInstallation,
    AgentInstallationPreference,
    AgentInstance,
    AgentModuleState,
    AgentPreference,
    AgentProvider,
    AgentRun,
    AgentSession,
)
from itsm.agent_integrations.providers import (
    CredentialInvalid,
    CredentialUnavailable,
    ProviderEndpointError,
    ProviderModelSelection,
    ProviderNetworkPolicy,
    credential_key_state,
    credential_key_values,
    credential_storage_available,
    personal_endpoint_policy,
    probe_provider_models,
    seal_credential,
    unseal_credential,
    validate_provider_endpoint,
)
from itsm.agents.isolation import IsolatedRuntime, is_privileged_human
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
    PERSONAL_PROVIDER_PERMISSION,
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
PROVIDER_SCOPES = frozenset({"global", "personal"})
_MAX_PROVIDER_MODELS = 50
_KEYLESS_GLOBAL_CREDENTIAL = "local"
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
    scope: str | None = None
    quota_mode: str = "direct"
    direct_company_exception: bool = False
    managed_provider_id: str | None = None
    managed_context_tokens: int | None = None


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
    provider_selection: ProviderModelSelection | None = None
    run_id: str | None = None
    quota: Any = None
    cancel_sent: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def stream(self) -> AsyncIterator[dict[str, Any]]:
        return self.service._stream(self)


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


def _provider_values(
    payload: Mapping[str, Any],
    *,
    scope: str,
    policy: ProviderNetworkPolicy | None = None,
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if "name" in payload:
        name = _label(payload["name"], limit=120)
        if name is None:
            raise ValidationFailed("provider name is required")
        values["name"] = name
    if "baseUrl" in payload:
        try:
            values["base_url"] = validate_provider_endpoint(
                payload["baseUrl"], scope=scope, policy=policy
            )
        except ProviderEndpointError as exc:
            raise ValidationFailed(str(exc)) from None
    if "models" in payload:
        raw = payload["models"]
        if not isinstance(raw, list):
            raise ValidationFailed("models must be a list")
        models: list[str] = []
        for item in raw:
            model = _label(item, limit=200)
            if model is None:
                raise ValidationFailed("provider models must be non-empty identifiers")
            if model not in models:
                models.append(model)
        if len(models) > _MAX_PROVIDER_MODELS:
            raise ValidationFailed("provider models exceed the configured limit")
        values["models"] = models
    if "enabled" in payload:
        enabled = payload["enabled"]
        if not isinstance(enabled, bool):
            raise ValidationFailed("enabled must be a boolean")
        values["enabled"] = enabled
    return values


def _provider_api_key(payload: Mapping[str, Any]) -> str | None:
    api_key = payload.get("apiKey")
    if api_key is None:
        return None
    unwrap = getattr(api_key, "get_secret_value", None)
    if callable(unwrap):
        api_key = unwrap()
    if not isinstance(api_key, str):
        raise ValidationFailed("apiKey must be text")
    key = api_key.strip()
    if not key:
        raise ValidationFailed("apiKey must not be empty")
    if len(key) > 2048 or any(ord(char) < 32 for char in key):
        raise ValidationFailed("apiKey is not a valid credential")
    return key


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
        from itsm.ai_usage.service import AiUsageService

        self._usage = AiUsageService(settings, session_factory)

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

    def _privileged_human(self, db: Session, principal: Principal) -> bool:
        """Reload the persisted active role; request data never selects it."""
        return is_privileged_human(db, self._settings, principal)

    def _require_external_role(self, db: Session, principal: Principal) -> None:
        if not self._privileged_human(db, principal):
            raise PermissionDenied("external agent engines require administrator permissions")

    def _external_instance(self, db: Session, instance_id: str | None) -> bool:
        if instance_id is None:
            return False
        row = db.get(AgentInstance, instance_id)
        return row is not None and row.engine in EXTERNAL_ENGINES

    def _require_pydantic_available(self, db: Session, principal: Principal) -> None:
        """Ordinary Pydantic turns are unservable without the container broker."""
        if self._privileged_human(db, principal):
            return
        if not (self._settings.ai_broker_url and self._settings.ai_broker_token):
            raise IntegrationUnavailable("agent isolation is not configured for this account")

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
            quota_mode=row.quota_mode,
            direct_company_exception=row.direct_company_exception,
            managed_provider_id=row.managed_provider_id,
            managed_context_tokens=row.managed_context_tokens,
        )

    def _secret(self, row: AgentInstance) -> str | None:
        if not row.secret_ref:
            return None
        value = os.environ.get(row.secret_ref)
        if not value:
            raise IntegrationUnavailable("the engine credential is not configured")
        return value

    @staticmethod
    def _provider_snapshot(row: AgentProvider) -> InstanceSnapshot:
        return InstanceSnapshot(
            id=row.id,
            name=row.name,
            engine=PYDANTIC_ENGINE,
            base_url=row.base_url,
            secret_ref=None,
            username=None,
            profile=None,
            directory=None,
            enabled=bool(row.enabled),
            default_model=None,
            integration_identity_id=None,
            scope=row.scope,
        )

    @staticmethod
    def _provider_models(row: AgentProvider) -> list[str]:
        value = row.models if isinstance(row.models, list) else []
        return [item for item in value if isinstance(item, str) and item.strip()][
            :_MAX_PROVIDER_MODELS
        ]

    @staticmethod
    def _provider_visible(row: AgentProvider, principal: Principal) -> bool:
        if row.scope == "global":
            return True
        return row.scope == "personal" and row.owner_id == principal.actor_id

    def _resolve_instance(
        self, db: Session, principal: Principal, instance_id: str
    ) -> tuple[InstanceSnapshot, AgentProvider | None]:
        instance = db.get(AgentInstance, instance_id)
        if instance is not None:
            return self._snapshot(instance), None
        provider = db.get(AgentProvider, instance_id)
        if provider is None or not self._provider_visible(provider, principal):
            raise NotFound("agent instance not found")
        return self._provider_snapshot(provider), provider

    def _provider_dto(self, row: AgentProvider) -> dict[str, Any]:
        # The owner sees whether a stored credential is still readable by this
        # process; the credential itself is never returned in any form.
        credential_status = (
            credential_key_state(self._settings, row.api_key_ciphertext)
            if row.api_key_ciphertext
            else "missing"
        )
        return {
            "id": row.id,
            "name": row.name,
            "scope": row.scope,
            "baseUrl": row.base_url,
            "models": list(row.models or []),
            "credentialConfigured": bool(row.api_key_ciphertext),
            "credentialStatus": credential_status,
            "enabled": bool(row.enabled),
        }

    def _provider_row(self, db: Session, provider_id: str) -> AgentProvider:
        row = db.get(AgentProvider, provider_id)
        if row is None:
            raise NotFound("provider not found")
        return row

    def _require_personal_provider(self, db: Session, principal: Principal) -> IdentityService:
        if principal.kind != HUMAN_ACTOR_KIND:
            raise PermissionDenied("personal providers require a signed-in person")
        identity = IdentityService(db, self._settings)
        identity.authorize(principal, PERSONAL_PROVIDER_PERMISSION, resource="agent:providers")
        return identity

    def _provider_policy(self, scope: str) -> ProviderNetworkPolicy | None:
        """Deployment policy for personal records; ``None`` for global records."""
        return personal_endpoint_policy(self._settings) if scope == "personal" else None

    def _can_manage_global(self, db: Session, principal: Principal) -> bool:
        if principal.kind != HUMAN_ACTOR_KIND:
            return False
        identity = IdentityService(db, self._settings)
        return "system.providers" in identity._persisted_permissions(principal)

    def _seal_credential(self, value: str) -> str:
        try:
            return seal_credential(self._settings, value)
        except CredentialUnavailable:
            raise IntegrationUnavailable("credential storage is not configured") from None

    def _provider_credential(self, row: AgentProvider) -> str:
        if row.api_key_ciphertext:
            try:
                return unseal_credential(self._settings, row.api_key_ciphertext)
            except CredentialUnavailable:
                raise IntegrationUnavailable("credential storage is not configured") from None
            except CredentialInvalid:
                raise IntegrationUnavailable(
                    "the stored provider credential cannot be read"
                ) from None
        if row.scope == "personal":
            raise IntegrationUnavailable("the provider credential is not configured")
        return _KEYLESS_GLOBAL_CREDENTIAL

    def _validate_provider_model(self, row: AgentProvider, model: str) -> str:
        value = _label(model, limit=200)
        if value is None or value not in self._provider_models(row):
            raise ValidationFailed("the selected model is not configured on this provider")
        return value

    def _provider_selection(
        self,
        db: Session,
        principal: Principal,
        row: AgentProvider,
        model: str,
    ) -> ProviderModelSelection:
        value = self._validate_provider_model(row, model)
        allow_private: bool | ProviderNetworkPolicy = True
        if row.scope == "personal":
            self._require_personal_provider(db, principal)
            allow_private = personal_endpoint_policy(self._settings)
        credential = self._provider_credential(row)
        return ProviderModelSelection(
            base_url=row.base_url,
            model=value,
            api_key=credential,
            allow_private=allow_private,
        )

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
            "quotaMode": row.quota_mode,
            "directCompanyException": row.direct_company_exception,
            "managedProviderId": row.managed_provider_id,
            "managedContextTokens": row.managed_context_tokens,
            "quota": self._quota_capability(row),
            "createdAt": row.created_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
        }

    def _public_instance(
        self,
        row: AgentInstance | InstanceSnapshot,
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
            "quota": self._quota_capability(row),
        }

    def _quota_capability(self, row: AgentInstance | InstanceSnapshot) -> dict[str, Any]:
        if row.engine == PYDANTIC_ENGINE:
            return {
                "mode": "builtin",
                "enforcement": "admission_only",
                "reason": (
                    "Cada solicitud reserva saldo; sin contador previo o límite de contexto "
                    "verificado no hay garantía estricta."
                ),
                "directException": False,
            }
        managed = row.quota_mode == "managed"
        return {
            "mode": "managed" if managed else "direct",
            "enforcement": "admission_only" if managed else "observed",
            "reason": "Proxy con reservas por llamada; aislamiento de salida de red no verificado."
            if managed
            else "Motor directo: consumo informado, sin control previo de cada llamada.",
            "directException": bool(row.direct_company_exception),
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

    def _redact(self, value: str, row: InstanceSnapshot, *, secret: str | None = None) -> str:
        text = value
        if row.base_url:
            text = text.replace(row.base_url, _REDACTED)
        engine_secret = os.environ.get(row.secret_ref) if row.secret_ref else None
        if engine_secret:
            text = text.replace(engine_secret, _REDACTED)
        if secret:
            text = text.replace(secret, _REDACTED)
        for credential_key in credential_key_values(self._settings):
            text = text.replace(credential_key, _REDACTED)
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
        if row.quota_mode == "managed":
            with self._session() as db:
                provider = self._provider_row(db, row.managed_provider_id or "")
                if not provider.enabled or provider.scope != "global":
                    raise IntegrationUnavailable("the managed provider is unavailable")
                models = [
                    {"id": item, "name": item, "provider": provider.name, "free": None}
                    for item in provider.models
                ]
            return {
                "version": "managed",
                "models": models,
                "capabilities": {
                    "streaming": True,
                    "sessions": True,
                    "history": True,
                    "model_switch": True,
                    "cancel": True,
                    "tools": True,
                    "usage": True,
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
                provider = db.get(AgentProvider, candidate.instance_id)
                if (
                    provider is not None
                    and provider.enabled
                    and self._provider_visible(provider, principal)
                ):
                    return candidate.instance_id, candidate.model
        return None, None

    def _budget(self, db: Session, principal: Principal) -> dict[str, Any]:
        return self._usage.me(principal.actor_id)

    # ------------------------------------------------------------- public engine API
    async def engines(self, principal: Principal) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            self._ensure_builtin(db)
            privileged = self._privileged_human(db, principal)
            rows = db.execute(select(AgentInstance).order_by(AgentInstance.created_at)).scalars()
            snapshots = [
                self._snapshot(row)
                for row in rows
                if privileged or row.engine not in EXTERNAL_ENGINES
            ]
            provider_rows = [
                row
                for row in db.execute(
                    select(AgentProvider).order_by(AgentProvider.created_at)
                ).scalars()
                if self._provider_visible(row, principal)
            ]
            provider_snapshots = [
                (self._provider_snapshot(row), self._provider_models(row)) for row in provider_rows
            ]
            preference = self._effective_preference(db, principal)
            if not privileged and self._external_instance(db, preference[0]):
                preference = (None, None)
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
        for snapshot, models in provider_snapshots:
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
            instances.append(
                self._public_instance(
                    snapshot,
                    models=[
                        {
                            "id": model,
                            "name": model,
                            "provider": "openai-compatible",
                            "free": None,
                        }
                        for model in models
                    ],
                    version=_package_version("pydantic-ai-slim"),
                    capabilities=self._session_capabilities(PYDANTIC_ENGINE, None),
                    error=None,
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
            provider = None
            if row is None:
                provider = db.get(AgentProvider, instance_id)
                if provider is None or not self._provider_visible(provider, principal):
                    raise ValidationFailed("unknown instance")
                if not provider.enabled:
                    raise ValidationFailed("the selected instance is disabled")
                snapshot = self._provider_snapshot(provider)
            else:
                if not row.enabled:
                    raise ValidationFailed("the selected instance is disabled")
                if row.engine in EXTERNAL_ENGINES:
                    self._require_external_role(db, principal)
                snapshot = self._snapshot(row)
        value: str | None = None
        if model is not None:
            if snapshot.engine == PYDANTIC_ENGINE:
                if provider is not None:
                    value = self._validate_provider_model(provider, model)
                elif model != self._settings.agent_model:
                    raise ValidationFailed("the built-in instance uses the server-configured model")
                else:
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

    # --------------------------------------------------------------- providers
    def providers(self, principal: Principal) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            rows = list(
                db.execute(select(AgentProvider).order_by(AgentProvider.created_at)).scalars()
            )
            visible = [row for row in rows if self._provider_visible(row, principal)]
            can_manage_global = self._can_manage_global(db, principal)
            identity = IdentityService(db, self._settings)
            can_manage_personal = (
                principal.kind == HUMAN_ACTOR_KIND
                and PERSONAL_PROVIDER_PERMISSION in identity._persisted_permissions(principal)
            )
        visible.sort(key=lambda row: (row.scope != "global", row.created_at))
        return {
            "items": [self._provider_dto(row) for row in visible],
            "canManageGlobal": can_manage_global,
            "canManagePersonal": can_manage_personal,
            "credentialStorageAvailable": credential_storage_available(self._settings),
        }

    def create_provider(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_human(principal)
        scope = payload.get("scope")
        if scope not in PROVIDER_SCOPES:
            raise ValidationFailed("scope must be global or personal")
        api_key = _provider_api_key(payload)
        with self._session() as db:
            self._ensure_builtin(db)
            if scope == "global":
                self._require_admin(db, principal, "agent:providers", human_only=True)
            else:
                self._require_personal_provider(db, principal)
            values = _provider_values(payload, scope=scope, policy=self._provider_policy(scope))
            if "name" not in values:
                raise ValidationFailed("provider name is required")
            if "base_url" not in values:
                raise ValidationFailed("provider base URL is required")
            values.setdefault("models", [])
            values.setdefault("enabled", True)
            row = AgentProvider(
                id=str(uuid4()),
                scope=scope,
                owner_id=principal.actor_id if scope == "personal" else None,
                api_key_ciphertext=self._seal_credential(api_key) if api_key else None,
                **values,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            return self._provider_dto(row)

    def update_provider(
        self, principal: Principal, provider_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require_human(principal)
        api_key = _provider_api_key(payload)
        with self._session() as db:
            row = self._provider_row(db, provider_id)
            if row.scope == "personal":
                if row.owner_id != principal.actor_id:
                    raise NotFound("provider not found")
                self._require_personal_provider(db, principal)
            else:
                self._require_admin(db, principal, "agent:providers", human_only=True)
            requested_scope = payload.get("scope")
            if requested_scope is not None and requested_scope != row.scope:
                raise ValidationFailed("provider scope cannot be changed")
            values = _provider_values(
                payload, scope=row.scope, policy=self._provider_policy(row.scope)
            )
            for name, value in values.items():
                setattr(row, name, value)
            if api_key:
                row.api_key_ciphertext = self._seal_credential(api_key)
            row.updated_at = utcnow()
            db.commit()
            db.refresh(row)
            return self._provider_dto(row)

    def delete_provider(self, principal: Principal, provider_id: str) -> dict[str, Any]:
        self._require_human(principal)
        with self._session() as db:
            row = self._provider_row(db, provider_id)
            if row.scope == "personal":
                if row.owner_id != principal.actor_id:
                    raise NotFound("provider not found")
                self._require_personal_provider(db, principal)
            else:
                self._require_admin(db, principal, "agent:providers", human_only=True)
            db.delete(row)
            db.commit()
        return {"id": provider_id, "deleted": True}

    async def check_provider(self, principal: Principal, provider_id: str) -> dict[str, Any]:
        """Owner-authorized, bounded models probe for one stored provider.

        It uses the same guarded transport as a turn, records no usage and never
        returns the credential, an upstream body or a resolved address.
        """
        self._require_human(principal)
        with self._session() as db:
            row = self._provider_row(db, provider_id)
            if not self._provider_visible(row, principal):
                raise NotFound("provider not found")
            if row.scope == "personal":
                self._require_personal_provider(db, principal)
            else:
                self._require_admin(db, principal, "agent:providers", human_only=True)
            base_url = row.base_url
            scope = row.scope
            try:
                credential = self._provider_credential(row)
            except IntegrationUnavailable:
                return {
                    "ok": False,
                    "code": "credential_unavailable",
                    "checkedAt": utcnow().isoformat(),
                }
        allow_private: bool | ProviderNetworkPolicy = (
            personal_endpoint_policy(self._settings) if scope == "personal" else True
        )
        code, model_count = await probe_provider_models(
            base_url, credential, allow_private=allow_private
        )
        checked: dict[str, Any] = {
            "ok": code == "ok",
            "code": code,
            "checkedAt": utcnow().isoformat(),
        }
        if model_count is not None:
            checked["modelCount"] = model_count
        return checked

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

        mapping = {
            "quotaMode": "quota_mode",
            "directCompanyException": "direct_company_exception",
            "managedProviderId": "managed_provider_id",
            "managedContextTokens": "managed_context_tokens",
        }
        for public, stored in mapping.items():
            if public in payload:
                values[stored] = payload[public]
        mode = values.get("quota_mode", getattr(existing, "quota_mode", "direct"))
        if mode not in {"direct", "managed"}:
            raise ValidationFailed("quotaMode must be managed or direct")
        if mode == "managed":
            provider_id = values.get(
                "managed_provider_id", getattr(existing, "managed_provider_id", None)
            )
            provider = db.get(AgentProvider, provider_id) if provider_id else None
            if provider is None or provider.scope != "global" or not provider.enabled:
                raise ValidationFailed("managedProviderId must select an enabled global provider")
            model = values.get("default_model", getattr(existing, "default_model", None))
            self._validate_provider_model(provider, model)
            bound = values.get(
                "managed_context_tokens", getattr(existing, "managed_context_tokens", None)
            )
            if (
                isinstance(bound, bool)
                or not isinstance(bound, int)
                or not 1 <= bound <= 100_000_000
            ):
                raise ValidationFailed("managedContextTokens must be a positive input bound")
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
            snapshot, provider = self._resolve_instance(db, principal, instance_id)
            if not snapshot.enabled:
                raise ValidationFailed("the selected instance is disabled")
            if snapshot.engine != PYDANTIC_ENGINE:
                self._require_external_role(db, principal)
                instance = self._instance(db, instance_id)
                identity = IdentityService(db, self._settings)
                self._assert_binding_ceiling(db, identity, principal, instance)
                self._require_verified_profile(db, instance)
            else:
                self._require_pydantic_available(db, principal)
                if provider is not None:
                    self._validate_provider_model(provider, model)
                    if provider.scope == "personal":
                        self._require_personal_provider(db, principal)
                else:
                    if not self._runtime_configured():
                        raise IntegrationUnavailable("agent model is not configured")
                    if model != self._settings.agent_model:
                        raise ValidationFailed(
                            "the built-in instance uses the server-configured model"
                        )
        capabilities: dict[str, bool] = self._session_capabilities(snapshot.engine, None)
        external_session_id: str | None = None
        if snapshot.engine != PYDANTIC_ENGINE and snapshot.quota_mode != "managed":
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
            current, current_provider = self._resolve_instance(db, principal, instance_id)
            if not current.enabled:
                raise Conflict("the selected instance changed while starting the session")
            if current.engine != PYDANTIC_ENGINE:
                self._require_external_role(db, principal)
            if provider is not None and current_provider is None:
                raise Conflict("the selected provider changed while starting the session")
            if provider is not None and provider.scope == "personal":
                self._require_personal_provider(db, principal)
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

    async def update_session(
        self, principal: Principal, session_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require_human(principal)
        requested_model = _label(payload.get("model"), limit=200)
        instance_id = _label(payload.get("instanceId"), limit=36)
        with self._session() as db:
            row = self._owned(db, principal, session_id)
            if row.status == "running":
                raise Conflict("a response is already running in this session")
            original_updated_at = row.updated_at
            current_model = row.model
            target_id = instance_id or row.instance_id
            snapshot, provider = self._resolve_instance(db, principal, target_id)
            if not snapshot.enabled:
                raise ValidationFailed("the selected instance is disabled")
            if snapshot.engine != PYDANTIC_ENGINE:
                self._require_external_role(db, principal)
                instance = self._instance(db, target_id)
                identity = IdentityService(db, self._settings)
                self._assert_binding_ceiling(db, identity, principal, instance)
                self._require_verified_profile(db, instance)
                value = requested_model
            else:
                self._require_pydantic_available(db, principal)
                if provider is not None:
                    configured = self._provider_models(provider)
                    if requested_model is not None:
                        value = self._validate_provider_model(provider, requested_model)
                    elif not configured:
                        raise ValidationFailed("the selected provider has no configured models")
                    else:
                        value = current_model if current_model in configured else configured[0]
                    if provider.scope == "personal":
                        self._require_personal_provider(db, principal)
                else:
                    if (
                        requested_model is not None
                        and requested_model != self._settings.agent_model
                    ):
                        raise ValidationFailed(
                            "the built-in instance uses the server-configured model"
                        )
                    value = self._settings.agent_model
                    if value is None:
                        raise IntegrationUnavailable("agent model is not configured")
        capabilities = self._session_capabilities(snapshot.engine, None)
        if snapshot.engine != PYDANTIC_ENGINE:
            if not capabilities.get("model_switch", True):
                raise Conflict("the selected engine does not support changing models")
            info = await self._discover(snapshot)
            model_ids = [item["id"] for item in info["models"]]
            available = set(model_ids)
            if requested_model is not None:
                value = requested_model
            elif snapshot.default_model in available:
                value = snapshot.default_model
            elif current_model in available:
                value = current_model
            elif model_ids:
                value = model_ids[0]
            else:
                raise ValidationFailed("the selected instance exposes no models")
            if value not in available:
                raise ValidationFailed("the selected model is not available on this instance")
            capabilities = self._session_capabilities(snapshot.engine, info)
        with self._session() as db:
            row = self._owned(db, principal, session_id)
            if row.status == "running":
                raise Conflict("a response is already running in this session")
            target, provider = self._resolve_instance(db, principal, target_id)
            if not target.enabled:
                raise Conflict("the selected instance changed while switching engines")
            if target.engine != PYDANTIC_ENGINE:
                self._require_external_role(db, principal)
                instance = self._instance(db, target_id)
                identity = IdentityService(db, self._settings)
                self._assert_binding_ceiling(db, identity, principal, instance)
                self._require_verified_profile(db, instance)
            else:
                self._require_pydantic_available(db, principal)
                if provider is not None:
                    self._validate_provider_model(provider, value)
                    if provider.scope == "personal":
                        self._require_personal_provider(db, principal)
                elif value != self._settings.agent_model:
                    raise Conflict("the built-in instance uses the server-configured model")
            values: dict[str, Any] = {"model": value, "updated_at": utcnow()}
            if target_id != row.instance_id:
                values.update(
                    instance_id=target_id,
                    engine=target.engine,
                    external_session_id=None,
                    capabilities=capabilities,
                )
            claimed = db.execute(
                update(AgentSession)
                .where(
                    AgentSession.id == session_id,
                    AgentSession.owner_id == principal.actor_id,
                    AgentSession.status == "idle",
                    AgentSession.instance_id == row.instance_id,
                    AgentSession.model == row.model,
                    AgentSession.updated_at == original_updated_at,
                )
                .values(**values)
                .execution_options(synchronize_session=False)
            )
            db.commit()
            if claimed.rowcount != 1:
                raise Conflict("the session changed while switching engines")
            row = self._owned(db, principal, session_id)
            db.refresh(row)
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
            instance, provider = self._resolve_instance(db, principal, row.instance_id)
            if not instance.enabled:
                raise Conflict("the selected instance is disabled")
            provider_selection: ProviderModelSelection | None = None
            if instance.engine != PYDANTIC_ENGINE:
                self._require_external_role(db, principal)
                identity = IdentityService(db, self._settings)
                instance_row = self._instance(db, row.instance_id)
                self._assert_binding_ceiling(db, identity, principal, instance_row)
                self._require_verified_profile(db, instance_row)
                if instance.quota_mode == "direct" and not instance.direct_company_exception:
                    raise PermissionDenied(
                        "company-funded direct engines require an explicit quota exception"
                    )
                if instance.quota_mode == "managed":
                    provider = self._provider_row(db, instance.managed_provider_id or "")
                    if provider.scope != "global" or not provider.enabled:
                        raise IntegrationUnavailable("the managed global provider is unavailable")
                    provider_selection = self._provider_selection(
                        db, principal, provider, row.model
                    )
            else:
                self._require_pydantic_available(db, principal)
                if provider is not None:
                    provider_selection = self._provider_selection(
                        db, principal, provider, row.model
                    )
                elif not self._runtime_configured():
                    raise IntegrationUnavailable("agent model is not configured")
            run_id = str(uuid4())
            self._recover_stale(db, now)
            if row.status == "running":
                raise Conflict("a response is already running in this session")
            from itsm.agents.quota import reserve_run

            attribution = {
                "provider_id": provider.id if provider is not None else None,
                "provider_scope": provider.scope if provider is not None else None,
                "provider_name": provider.name if provider is not None else None,
                "model": row.model,
            }
            quota = reserve_run(
                self._settings,
                self._session_factory,
                principal,
                run_id=run_id,
                engine=instance.engine,
                provider=attribution,
            )
            original_updated_at = row.updated_at
            messages = list(row.messages or [])
            messages.append({"role": "user", "content": message})
            claimed = db.execute(
                update(AgentSession)
                .where(
                    AgentSession.id == session_id,
                    AgentSession.owner_id == principal.actor_id,
                    AgentSession.status == "idle",
                    AgentSession.instance_id == row.instance_id,
                    AgentSession.model == row.model,
                    AgentSession.updated_at == original_updated_at,
                )
                .values(
                    messages=messages,
                    status="running",
                    cancel_requested=False,
                    asset_id=asset_id,
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                db.rollback()
                quota.finish_without_dispatch()
                raise Conflict("the session changed while starting the turn")
            db.add(
                AgentRun(
                    id=run_id,
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
            instance_snapshot = instance
        turn = Turn(
            service=self,
            principal=principal,
            session=snapshot,
            instance=instance_snapshot,
            message=message,
            asset_id=asset_id,
            external_session_id=snapshot.external_session_id,
            provider_selection=provider_selection,
            run_id=run_id,
            quota=quota,
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
            if (
                turn.session.engine != PYDANTIC_ENGINE
                and turn.engine is None
                and turn.instance.quota_mode != "managed"
            ):
                with turn.lock:
                    if turn.engine is None:
                        turn.engine = self._build_engine(turn.instance)
            yield {"type": "session", "sessionId": turn.session.id}
            async for event in self._events(turn):
                kind = event["type"]
                if kind == "delta":
                    text = (text + event["text"])[-_MAX_MESSAGE:]
                elif kind == "usage":
                    turn._usage_events = [*getattr(turn, "_usage_events", []), event]
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
            error_seen = self._exception_event(exc, turn)
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
            try:
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
            finally:
                owned_runtime = getattr(turn, "_owned_runtime", None)
                if owned_runtime is not None:
                    try:
                        await owned_runtime.aclose()
                    except Exception:
                        logger.warning("agent provider client could not be closed")
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
        with self._session() as db:
            privileged = self._privileged_human(db, turn.principal)
        if privileged:
            runtime = self._runtime
            if runtime is None:
                from itsm.agents.runtime import AgentRuntime

                runtime = AgentRuntime(self._settings, self._session_factory)
                turn._owned_runtime = runtime  # type: ignore[attr-defined]
        else:
            runtime = IsolatedRuntime(self._settings, self._session_factory)
            turn._owned_runtime = runtime  # type: ignore[attr-defined]
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
        usage = AgentUsage()
        options: dict[str, Any] = {
            "credential_digest": None,
            "usage": usage,
            "quota": turn.quota,
        }
        if turn.provider_selection is not None:
            options["provider_selection"] = turn.provider_selection
        try:
            reply, usage = await asyncio.to_thread(
                runtime.chat_with_usage,
                turn.principal,
                request,
                **options,
            )
        except BaseException:
            turn._usage = usage  # type: ignore[attr-defined]
            raise
        turn._usage = usage  # type: ignore[attr-defined]
        turn._reply = reply  # type: ignore[attr-defined]
        for event in turn.quota.evidence if turn.quota is not None else []:
            yield event
        for action in reply.actions:
            yield {
                "type": "tool",
                "tool": action.tool,
                "status": action.status,
            }
        if reply.message:
            yield {"type": "delta", "text": reply.message}
        yield {"type": "done", "cancelled": False}

    async def _managed_events(self, turn: Turn) -> AsyncIterator[dict[str, Any]]:
        from itsm.agents.managed import (
            ManagedEngineRunner,
            ManagedEngineSettings,
            ManagedProfileInputs,
        )
        from itsm.ai_gateway import AiGatewayService

        settings = self._settings
        gateway_url = settings.ai_managed_gateway_url
        if not gateway_url or turn.provider_selection is None or turn.quota is None:
            raise IntegrationUnavailable("the managed engine gateway is not configured")
        with self._session() as db:
            row = db.get(AgentInstance, turn.instance.id)
            installation = self._verified_installation(db, row) if row else None
            if installation is None:
                raise IntegrationUnavailable("the managed profile is not verified")
            receipt = installation.receipt or {}
            mcp = receipt.get("mcp") or {}
            token = os.environ.get(mcp.get("secretRef", ""))
            if not token:
                raise IntegrationUnavailable("the integration credential is unavailable")
            packages = {
                name: self._catalog_instance().get_skill(name)["files"]
                for name in _skill_names(receipt.get("skills"))
            }
            provider_name = self._provider_row(db, turn.instance.managed_provider_id).name
        profile = ManagedProfileInputs(
            mcp_url=mcp.get("url"), mcp_token=token, skill_packages=packages
        )
        gateway = AiGatewayService(settings, self._session_factory, self._usage)
        grant = turn.quota.reservation
        lease = gateway.issue_lease(
            actor_id=turn.principal.actor_id,
            funding=grant.funding,
            parent_reservation_id=grant.reservation_id,
            selection=turn.provider_selection,
            provider_id=turn.instance.managed_provider_id,
            provider_scope="global",
            provider_name=provider_name,
            model=turn.session.model,
            engine=turn.session.engine,
            run_id=turn.run_id,
            context_tokens=turn.instance.managed_context_tokens,
            output_tokens=settings.agent_max_output_tokens,
        )
        runner = None
        try:
            # Replace admission sentinel before starting anything capable of inference.
            turn.quota.finish_without_dispatch()
            runner = ManagedEngineRunner(
                ManagedEngineSettings(
                    hermes_binary=settings.ai_managed_hermes_binary,
                    opencode_binary=settings.ai_managed_opencode_binary,
                    profile_root=settings.ai_managed_profile_root,
                    startup_timeout_seconds=settings.ai_managed_startup_timeout_seconds,
                    shutdown_timeout_seconds=settings.ai_managed_shutdown_timeout_seconds,
                ),
                turn.instance,
                lease,
                gateway_url,
                profile=profile,
            )
            async with asyncio.timeout(settings.agent_run_timeout_seconds):
                await runner.start()
                with turn.lock:
                    turn.engine = runner
                session_id = await runner.create_session()
                turn.external_session_id = session_id
                if self._cancel_requested(turn.session.id):
                    await runner.cancel(session_id)
                    return
                history = [
                    {"role": item["role"], "content": item["content"][:8000]}
                    for item in turn.session.messages[:-1]
                    if item.get("role") in {"user", "assistant"}
                ]
                count = settings.agent_max_history_messages
                history = history[-count:] if count else []
                async for raw in runner.stream(
                    turn.message, session_id=session_id, model=runner.native_model, history=history
                ):
                    event = self._normalize_event(raw, turn)
                    if event is not None:
                        yield event
        finally:
            try:
                if runner is not None:
                    await runner.aclose()
            finally:
                gateway.revoke(lease.lease_id)

    async def _external_events(self, turn: Turn) -> AsyncIterator[dict[str, Any]]:
        if turn.instance.quota_mode == "managed":
            async for event in self._managed_events(turn):
                yield event
            return
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
            from itsm.agents.usage import UsageEvidence

            names = {
                "inputTokens": "input_tokens",
                "outputTokens": "output_tokens",
                "cacheReadTokens": "cache_read_tokens",
                "cacheWriteTokens": "cache_write_tokens",
                "reasoningTokens": "reasoning_tokens",
                "totalTokens": "total_tokens",
                "estimationMethod": "estimation_method",
                "inputIncludesCache": "input_includes_cache",
                "outputIncludesReasoning": "output_includes_reasoning",
                "totalSource": "total_source",
            }
            try:
                payload = {
                    names.get(key, key): value for key, value in raw.items() if key != "type"
                }
                return UsageEvidence.model_validate(payload).event()
            except ValueError:
                return None
        if kind == "error":
            code = _label(raw.get("code"), limit=64) or "engine_error"
            message = _clean(raw.get("message"), 1000)
            if message is None:
                message = "the engine reported an error"
            message = self._redact(message, turn.instance, secret=self._turn_secret(turn))
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

    @staticmethod
    def _turn_secret(turn: Turn) -> str | None:
        selection = turn.provider_selection
        return selection.api_key if selection is not None else None

    def _exception_event(self, exc: BaseException, turn: Turn) -> dict[str, Any]:
        import asyncio as _asyncio

        instance = turn.instance
        secret = self._turn_secret(turn)
        from itsm.ai_usage import QuotaExceeded

        if isinstance(exc, QuotaExceeded):
            return {"type": "error", "code": exc.code, "message": str(exc), "retryable": False}
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
                "message": self._redact(str(exc), instance, secret=secret),
                "retryable": True,
            }
        public = _engine_error(exc)
        if public is not None:
            return {
                "type": "error",
                "code": public[0],
                "message": self._redact(public[1], instance, secret=secret),
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
            run = db.get(AgentRun, turn.run_id) if turn.run_id else None
            if run is not None:
                if cancelled:
                    run.status = "cancelled"
                elif failed:
                    run.status = "failed"
                else:
                    run.status = "completed"
                run.finished_at = now
            db.commit()
        # The ledger owns a separate transaction: never nest its writes inside
        # the session transaction (SQLite would deadlock against our own lock).
        if (
            turn.quota is not None
            and turn.session.engine != PYDANTIC_ENGINE
            and turn.instance.quota_mode != "managed"
        ):
            events = getattr(turn, "_usage_events", [])
            if len(events) == 1:
                evidence = {
                    key: value for key, value in events[0].items() if key not in {"type", "cost"}
                }
                self._usage.settle(turn.quota.reservation.reservation_id, evidence)
            else:
                self._usage.settle(
                    turn.quota.reservation.reservation_id,
                    {"precision": "unavailable", "source": "engine"},
                )

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
                skills = _skill_names(
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
                inspector = (
                    self._hermes_profile_safety
                    if target.engine == "hermes"
                    else self._opencode_profile_safety
                )
                return await inspector(
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
                        profile_inspector=inspect_profile,
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
        if "skills" in binding:
            binding["skills"] = _skill_names(binding["skills"])
        with self._session() as db:
            identity = self._require_admin(db, principal, "agent:integrations", human_only=True)
            row = self._installation_row(db, instance.id, target)
            previous = dict((row.receipt or {}).get("binding") or {}) if row is not None else {}
            if previous and status in {"failed", "conflict"}:
                # A failed lifecycle operation reports why it failed; it must not
                # drop the last known binding a retry needs.
                binding = {
                    **previous,
                    **{
                        key: value
                        for key, value in binding.items()
                        if value not in (None, "", [], {})
                    },
                }
                if "skills" in previous:
                    binding["skills"] = _skill_names(previous["skills"])
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
            skills = _skill_names((stored.get("binding") or {}).get("skills"))
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
            inspector = (
                self._hermes_profile_safety
                if target.engine == "hermes"
                else self._opencode_profile_safety
            )
            safety = await inspector(instance_snapshot, target, mcp, skills, sanitized)
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

    async def _hermes_profile_safety(
        self,
        instance: Any,
        target: Any,
        mcp: Mapping[str, str],
        skills: list[str],
        receipt: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Bind a live native inspection to an independently owned host launch."""
        import httpx

        from itsm.agent_integrations.installer import _hermes_runtime_safety

        digest = receipt.get("configDigest")
        inspector_url = self._settings.hermes_inspector_url
        inspector_token = self._settings.hermes_inspector_token
        endpoint = (getattr(instance, "base_url", None) or "").rstrip("/")
        home = os.path.realpath(target.path)
        if not isinstance(digest, str) or not digest or not inspector_url or not inspector_token:
            return None
        try:
            async with httpx.AsyncClient(
                timeout=30,
                follow_redirects=False,
                headers={"Authorization": "Bearer " + inspector_token.get_secret_value()},
            ) as client:
                response = await client.post(
                    inspector_url + "/profile-proof",
                    json={"profileHome": home, "endpoint": endpoint, "configDigest": digest},
                )
            if response.status_code != 200 or len(response.content) > 8192:
                return None
            launch = response.json()
            if not isinstance(launch, Mapping):
                return None
            pid = launch.get("processId")
            if (
                launch.get("protocol") != "itsm-hermes-launch-v1"
                or launch.get("profileHome") != home
                or launch.get("endpoint") != endpoint
                or launch.get("configDigest") != digest
                or not isinstance(launch.get("launchId"), str)
                or not launch["launchId"]
                or not isinstance(pid, int)
                or isinstance(pid, bool)
                or pid <= 0
            ):
                return None
            engine = self._build_engine(instance)
            try:
                runtime = await engine.inspect_profile_runtime()
            finally:
                await engine.close()
            evidence = {
                "source": "hermes:" + endpoint,
                "verified": True,
                "configDigest": digest,
                "targetPath": home,
                "launch": dict(launch),
                "runtime": runtime,
                "checks": [
                    {
                        "name": "runtime.profile",
                        "status": "pass",
                        "detail": "host-owned launch and live native surface inspected",
                    }
                ],
            }
            # Reuse the installer's exact restrictions, including remote receipt import.
            state = SimpleNamespace(
                root=home,
                config_data={"mcp_servers": {"itsm": {"url": mcp["url"]}}},
            )
            safe, _detail = _hermes_runtime_safety(evidence, state, skills)
            return evidence if safe else None
        except Exception as exc:
            logger.warning("Hermes runtime inspection failed: %s", type(exc).__name__)
            return None

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
                skills_response = await client.get("/api/skill", params=params)
        except Exception as exc:
            logger.warning("OpenCode runtime inspection failed: %s", type(exc).__name__)
            return None
        if any(
            response.status_code != 200
            for response in (config_response, agent_response, grants_response, skills_response)
        ):
            return None
        try:
            entries = config_response.json()
            agent_payload = agent_response.json()
            grants = grants_response.json()
            skill_payload = skills_response.json()
        except ValueError:
            return None
        binding = _config_profile_entries(entries, target.path)
        if binding is None:
            return None
        directory_entry, document_entries = binding
        effective = _effective_config(document_entries)
        if effective is None:
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
        if effective.get("default_agent") != "itsm":
            return None
        agent_info = agent_payload.get("data") if isinstance(agent_payload, Mapping) else None
        if not isinstance(agent_info, Mapping) or agent_info.get("id") != "itsm":
            return None
        if agent_info.get("mode") not in {"primary", "all"}:
            return None
        if agent_info.get("hidden") is not False:
            return None
        permissions = agent_info.get("permissions")
        if not _restrictive_permissions(permissions, skills):
            return None
        grant_items = grants.get("data") if isinstance(grants, Mapping) else None
        if not isinstance(grant_items, list):
            return None
        if any(_broad_grant(item, skills) for item in grant_items):
            return None
        if not isinstance(skill_payload, Mapping):
            return None
        if set(skill_payload) != {"location", "data"}:
            return None
        skill_location = skill_payload.get("location")
        if not isinstance(skill_location, Mapping) or os.path.realpath(
            str(skill_location.get("directory") or "")
        ) != os.path.realpath(target.path):
            return None
        skill_items = skill_payload.get("data")
        if not isinstance(skill_items, list):
            return None
        projected_skills: list[dict[str, str]] = []
        seen_skills: set[str] = set()
        for item in skill_items:
            if not isinstance(item, Mapping):
                return None
            skill_id = item.get("id")
            skill_name = item.get("name")
            skill_path = item.get("path")
            if (
                not isinstance(skill_id, str)
                or not skill_id
                or not isinstance(skill_name, str)
                or not skill_name
                or not isinstance(skill_path, str)
                or not os.path.isabs(skill_path)
            ):
                return None
            if skill_id in seen_skills:
                return None
            seen_skills.add(skill_id)
            if skill_id in skills and os.path.realpath(skill_path) != os.path.realpath(
                os.path.join(target.path, ".opencode", "skills", skill_id, "SKILL.md")
            ):
                return None
            projected_skills.append({"id": skill_id, "name": skill_name, "path": skill_path})
        if not set(skills).issubset(seen_skills):
            return None
        discovered = await self._discover(instance)
        observed_version = discovered.get("version")
        if target.version and observed_version and target.version != observed_version:
            return None
        checks = [
            {
                "name": "inspection.config",
                "status": "pass",
                "detail": "selected Config.Entry sources and effective mcp/default_agent",
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
                "name": "inspection.skills",
                "status": "pass",
                "detail": "selected profile skill inventory inspected",
            },
            {
                "name": "inspection.version",
                "status": "pass",
                "detail": observed_version or "unreported",
            },
        ]
        projected_config: list[dict[str, Any]] = [
            {"type": "directory", "path": directory_entry["path"]},
            {
                "type": "document",
                "path": document_entries[0]["path"],
                "info": {"default_agent": effective.get("default_agent")},
            },
        ]
        projected_agent = {
            "id": agent_info.get("id"),
            "mode": agent_info.get("mode"),
            "hidden": agent_info.get("hidden"),
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
            "skills": {"location": {"directory": target.path}, "data": projected_skills},
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
        skills = _skill_names(binding.get("skills") or receipt.get("skills"))
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
            "error": dict(receipt["error"]) if isinstance(receipt.get("error"), Mapping) else None,
            "limitations": _string_list(receipt.get("limitations")),
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


def _skill_names(value: Any) -> list[str]:
    """Canonical skill names from a binding list or installer receipt objects.

    Installer receipts list selected skills as ``{name, version, digest}``
    objects while requests use plain names; both shapes reduce to the same
    canonical selection so verification keeps comparing exact names.
    """
    if not isinstance(value, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = item.get("name") if isinstance(item, Mapping) else item
        if not isinstance(name, str):
            continue
        name = name.strip()[:200]
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names[:50]


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
    "IntegrationUnavailable",
    "Turn",
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


def _config_profile_entries(
    entries: Any, directory: str
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]] | None:
    """Require actual Config.Entry sources bound to one selected profile.

    OpenCode 2.1.2 reports the selected ``<workspace>/.opencode`` directory and
    one ``<workspace>/opencode.json(c)`` document.  System, global, ancestor,
    Claude, or content sources would broaden the inspected authority.
    """
    if not isinstance(entries, list) or not entries or not isinstance(directory, str):
        return None
    expected_directory = os.path.realpath(os.path.join(directory, ".opencode"))
    expected_documents = {
        os.path.realpath(os.path.join(directory, "opencode.json")),
        os.path.realpath(os.path.join(directory, "opencode.jsonc")),
    }
    directory_entries: list[Mapping[str, Any]] = []
    document_entries: list[Mapping[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) - {"type", "path", "info"}:
            return None
        path = entry.get("path")
        if not isinstance(path, str) or not os.path.isabs(path):
            return None
        if entry.get("type") == "directory":
            directory_entries.append(entry)
        elif entry.get("type") == "document":
            if not isinstance(entry.get("info"), Mapping):
                return None
            document_entries.append(entry)
        else:
            return None
    if len(directory_entries) != 1:
        return None
    if os.path.realpath(str(directory_entries[0]["path"])) != expected_directory:
        return None
    if len(document_entries) != 1:
        return None
    if os.path.realpath(str(document_entries[0]["path"])) not in expected_documents:
        return None
    return directory_entries[0], document_entries


def _restrictive_permissions(permissions: Any, skills: list[str]) -> bool:
    """Require a final deny-all and only approved overrides after it.

    OpenCode evaluates an ordered rule list with last-match-wins semantics and
    appends agent rules after lower-priority builtins. Rules before the last
    exact ``*``/``*`` deny are therefore fully shadowed for every request, so
    they cannot widen the effective policy. Only the suffix beginning at that
    deny is policy-relevant and must satisfy the strict whitelist below.
    """
    if not isinstance(permissions, list) or not permissions:
        return False
    boundary: int | None = None
    for index, rule in enumerate(permissions):
        if not isinstance(rule, Mapping):
            return False
        action = rule.get("action")
        resource = rule.get("resource")
        if not isinstance(action, str) or not action:
            return False
        if not isinstance(resource, str) or not resource:
            return False
        if rule.get("effect") not in {"allow", "ask", "deny"}:
            return False
        if action == "*" and resource == "*" and rule.get("effect") == "deny":
            boundary = index
    if boundary is None:
        return False
    return _strict_permission_suffix(permissions[boundary:], skills)


def _strict_permission_suffix(permissions: list[Any], skills: list[str]) -> bool:
    """Validate only the rules that can still win after the final deny-all."""
    deny_all = False
    itsm_allow = False
    allowed_skills: set[str] = set()
    requested_skills = set(skills)
    for rule in permissions:
        if not isinstance(rule, Mapping):
            return False
        action = rule.get("action")
        resource = rule.get("resource")
        effect = rule.get("effect")
        if not isinstance(action, str) or not action:
            return False
        if not isinstance(resource, str) or not resource:
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
