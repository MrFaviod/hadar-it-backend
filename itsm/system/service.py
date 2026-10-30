"""Canonical installation service shared by HTTP, MCP and the integrated agent."""

from __future__ import annotations

import json
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from itsm import __version__
from itsm.agent_integrations.service import AgentIntegrationService
from itsm.config import Settings
from itsm.database import DatabaseUnavailable, migration_state, probe_database
from itsm.identity.clock import utcnow
from itsm.identity.service import IdentityService, Principal, ValidationFailed
from itsm.system.authorization import require_system_authority
from itsm.system.executor import ACTION_NAMES, ExecutorOutcome, SystemExecutor
from itsm.system.models import SystemPreference, SystemProviderSettings
from itsm.system.providers import (
    CLASSIFICATIONS,
    MAINTENANCE_WINDOWS,
    ProviderSelectionError,
    effective_selection,
    persisted_selection,
    provider_descriptors,
    selection_payload,
    validate_selection,
)

OPERATION_PERMISSIONS: dict[str, str] = {
    "deployment.status": "system.view",
    "update.prepare": "system.update",
    "backup.create": "system.backup",
}


# ----------------------------------------------------- backup status boundary
# The maintenance service publishes a small JSON document next to its backup
# artifacts. The API only reads that document: it never runs a dump or restore
# tool, never opens an engine socket, never scans artifacts and never recomputes
# a hash. Everything below is therefore a bounded read plus a strict allow-list
# of summary fields; locators, filesystem paths, dump names, digests, tool
# versions and restore commands stay out of the browser surface.
BACKUP_STATUS_MAX_BYTES = 64 * 1024
BACKUP_STATUS_MAX_FAILURES = 10
BACKUP_STATUS_TEXT_MAX = 200
BACKUP_STATUS_REASON_MAX = 500

_URL_LIKE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S*")
_PATH_LIKE = re.compile(r"(?:[A-Za-z]:[\\/]|(?<![\w.])/)[^\s,;\"']*")
_CREDENTIAL_PAIR = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|authorization|dsn|database_url|url)"
    r"(\s*[=:]\s*)(\S+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")


def _redacted(value: str) -> str:
    """Mask locators, filesystem paths and credential-shaped tokens.

    Bare prose is left readable: the publisher already sanitizes configured
    secrets at the source, and this API cannot recognize an arbitrary opaque
    word as a secret. Recognizable carriers -- DSNs, URL userinfo, ``key=value``
    credentials and bearer headers -- are masked entirely.
    """
    masked = _URL_LIKE.sub("[redacted]", value)
    masked = _CREDENTIAL_PAIR.sub(r"\1\2[redacted]", masked)
    masked = _BEARER.sub("Bearer [redacted]", masked)
    return _PATH_LIKE.sub("[redacted]", masked)


def _text(value: Any, limit: int = BACKUP_STATUS_TEXT_MAX) -> str | None:
    """Return a bounded redacted string, or ``None`` for any other type."""
    if not isinstance(value, str) or not value.strip():
        return None
    return _redacted(value.strip())[:limit]


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _last_backup_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    summary: dict[str, Any] = {
        "id": _text(value.get("id")),
        "createdAt": _text(value.get("createdAt")),
        "size": _count(value.get("size")),
        "engine": _text(value.get("engine")),
        "verified": _flag(value.get("verified")),
        "checksum": _flag(value.get("checksum")),
        "alembicRevision": _text(value.get("alembicRevision")),
    }
    return None if all(item is None for item in summary.values()) else summary


def _failure_summaries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    entries: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        reason = _text(item.get("reason"), BACKUP_STATUS_REASON_MAX)
        operation = _text(item.get("operation"))
        if reason is None and operation is None:
            continue
        entries.append({"at": _text(item.get("at")), "operation": operation, "reason": reason})
        if len(entries) == BACKUP_STATUS_MAX_FAILURES:
            break
    return entries


def _last_upgrade_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    summary: dict[str, Any] = {
        "status": _text(value.get("status")),
        "currentRevision": _text(value.get("currentRevision")),
        "headRevision": _text(value.get("headRevision")),
        "backupId": _text(value.get("backupId")),
    }
    return None if all(item is None for item in summary.values()) else summary


def _empty_backup_summary() -> dict[str, Any]:
    return {
        "status": None,
        "engine": None,
        "backupCount": None,
        "lastBackup": None,
        "failures": [],
        "lastUpgrade": None,
        "updatedAt": None,
    }


def _backup_summary(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": _text(document.get("status")),
        "engine": _text(document.get("engine")),
        "backupCount": _count(document.get("backupCount")),
        "lastBackup": _last_backup_summary(document.get("lastBackup")),
        "failures": _failure_summaries(document.get("failures")),
        "lastUpgrade": _last_upgrade_summary(document.get("lastUpgrade")),
        "updatedAt": _text(document.get("updatedAt")),
    }


def _read_published_status(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read one bounded JSON object; the reason never echoes the path."""
    try:
        info = path.stat()
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"
    if not stat.S_ISREG(info.st_mode):
        return None, "not_a_file"
    if info.st_size > BACKUP_STATUS_MAX_BYTES:
        return None, "too_large"
    try:
        with path.open("rb") as handle:
            raw = handle.read(BACKUP_STATUS_MAX_BYTES + 1)
    except OSError:
        return None, "unreadable"
    if len(raw) > BACKUP_STATUS_MAX_BYTES:
        return None, "too_large"
    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError, ValueError:
        return None, "malformed"
    if not isinstance(document, dict):
        return None, "malformed"
    return document, None


class SystemService:
    """Authorization, persistence and bounded execution for installation operations."""

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session],
        *,
        integrations: AgentIntegrationService | None = None,
        executor: SystemExecutor | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._integrations = integrations
        self._executor = executor
        self._database = make_url(settings.database_url).get_backend_name()

    # ----------------------------------------------------------------- helpers
    def _executor_client(self) -> SystemExecutor:
        if self._executor is None:
            self._executor = SystemExecutor(self._settings)
        return self._executor

    def _integration_service(self) -> AgentIntegrationService:
        if self._integrations is None:
            self._integrations = AgentIntegrationService(self._settings, self._session_factory)
            self._integrations.initialize()
        return self._integrations

    def _authorize(
        self,
        session: Session,
        principal: Principal,
        permission: str,
        resource: str,
    ) -> None:
        require_system_authority(session, self._settings, principal, permission, resource)

    def _audit(
        self,
        session: Session,
        principal: Principal,
        action: str,
        resource: str,
        outcome: str = "success",
    ) -> None:
        IdentityService(session, self._settings).record_operation(
            principal, action=action, resource=resource, outcome=outcome
        )

    @staticmethod
    def _preference_row(session: Session) -> SystemPreference | None:
        try:
            return session.get(SystemPreference, 1)
        except SQLAlchemyError:
            session.rollback()
            return None

    def _default_classification(self) -> str:
        value = getattr(self._settings, "environment", "development")
        return value if value in CLASSIFICATIONS else "development"

    def _configuration_payload(self, row: SystemPreference | None) -> dict[str, Any]:
        classification = row.classification if row is not None else self._default_classification()
        window = row.maintenance_window if row is not None else "anytime"
        return {
            "deployment": {
                "classification": classification
                if classification in CLASSIFICATIONS
                else self._default_classification(),
                "maintenanceWindow": window if window in MAINTENANCE_WINDOWS else "anytime",
                "database": self._database,
            },
            "executor": {"configured": self._executor_client().configured},
        }

    # ------------------------------------------------------------------ status
    def status(self, principal: Principal) -> dict[str, Any]:
        with self._session_factory() as session:
            self._authorize(session, principal, "system.view", "system:status")
            engine = session.get_bind()
        try:
            probe_database(engine)
            database = "ok"
        except DatabaseUnavailable:
            database = "unavailable"
        migrations = migration_state(engine, self._settings)
        available = self._executor_client().availability()
        return {
            "ready": database == "ok" and migrations.status == "ok",
            "checkedAt": utcnow().isoformat(),
            "app": {
                "name": self._settings.app_name,
                "version": __version__,
                "mode": self._settings.environment,
                "database": self._database,
            },
            "readiness": {
                "database": database,
                "migrations": migrations.status,
                "current": migrations.current,
                "head": migrations.head,
            },
            "executor": available,
        }

    def backup_status(self, principal: Principal) -> dict[str, Any]:
        """Summarize the maintenance-published backup state; never execute backups."""
        with self._session_factory() as session:
            self._authorize(session, principal, "system.view", "system:backups")
        path = self._settings.backup_status_path
        document: Mapping[str, Any] | None = None
        reason: str | None = "unconfigured"
        if path is not None:
            document, reason = _read_published_status(path)
        summary = _empty_backup_summary() if document is None else _backup_summary(document)
        return {
            "available": document is not None,
            "reason": reason,
            "checkedAt": utcnow().isoformat(),
            **summary,
        }

    # ----------------------------------------------------------- configuration
    def configuration(self, principal: Principal) -> dict[str, Any]:
        with self._session_factory() as session:
            self._authorize(session, principal, "system.view", "system:configuration")
            row = self._preference_row(session)
            return self._configuration_payload(row)

    def update_configuration(
        self, principal: Principal, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        deployment = payload.get("deployment")
        if not isinstance(deployment, Mapping):
            raise ValidationFailed("deployment preferences are required")
        unknown = set(deployment) - {"classification", "maintenanceWindow"}
        if unknown:
            raise ValidationFailed("unsupported deployment preference")
        classification = deployment.get("classification")
        if classification is not None and classification not in CLASSIFICATIONS:
            raise ValidationFailed("deployment classification is not supported")
        window = deployment.get("maintenanceWindow")
        if window is not None and window not in MAINTENANCE_WINDOWS:
            raise ValidationFailed("maintenance window is not supported")
        with self._session_factory() as session:
            self._authorize(session, principal, "system.configure", "system:configuration")
            row = session.get(SystemPreference, 1)
            if row is None:
                row = SystemPreference(id=1, classification=self._default_classification())
                session.add(row)
            if classification is not None:
                row.classification = str(classification)
            if window is not None:
                row.maintenance_window = str(window)
            row.updated_at = utcnow()
            row.updated_by = principal.actor_id
            session.commit()
            self._audit(
                session,
                principal,
                "system.configuration.updated",
                "system:configuration",
            )
            return self._configuration_payload(row)

    # --------------------------------------------------------------- providers
    def _providers_payload(self, session: Session) -> dict[str, Any]:
        selection = effective_selection(session, self._settings)
        return {
            "selected": (
                None
                if selection is None
                else {"provider": selection.provider, "model": selection.model}
            ),
            "selection": selection_payload(selection),
            "providers": provider_descriptors(),
        }

    def providers(self, principal: Principal) -> dict[str, Any]:
        with self._session_factory() as session:
            self._authorize(session, principal, "system.view", "system:providers")
            return self._providers_payload(session)

    def set_provider(self, principal: Principal, payload: Mapping[str, Any]) -> dict[str, Any]:
        if set(payload) - {"provider", "model"}:
            raise ValidationFailed("unsupported provider field")
        try:
            provider, model = validate_selection(payload.get("provider"), payload.get("model"))
        except ProviderSelectionError as exc:
            raise ValidationFailed(str(exc)) from None
        with self._session_factory() as session:
            self._authorize(session, principal, "system.providers", "system:providers")
            row = session.get(SystemProviderSettings, 1)
            if row is None:
                row = SystemProviderSettings(id=1, provider=provider, model=model)
                session.add(row)
            else:
                row.provider = provider
                row.model = model
            row.updated_at = utcnow()
            row.updated_by = principal.actor_id
            session.commit()
            self._audit(session, principal, "system.provider.updated", "system:providers")
            return self._providers_payload(session)

    def selected_provider(self) -> dict[str, Any] | None:
        """Current effective provider for diagnostics without authorization."""
        with self._session_factory() as session:
            payload = selection_payload(persisted_selection(session))
        return payload

    # ----------------------------------------------------------------- modules
    def modules(self, principal: Principal) -> dict[str, Any]:
        with self._session_factory() as session:
            self._authorize(session, principal, "system.modules", "system:modules")
        return self._integration_service().list_modules(principal)

    def set_module(
        self, principal: Principal, module_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(module_id, str) or not module_id or len(module_id) > 120:
            raise ValidationFailed("module id is invalid")
        if set(payload) != {"enabled"} or not isinstance(payload.get("enabled"), bool):
            raise ValidationFailed("module payload must contain only a boolean enabled")
        with self._session_factory() as session:
            self._authorize(session, principal, "system.modules", "system:modules")
        result = self._integration_service().set_module(
            principal, module_id, {"enabled": payload["enabled"]}
        )
        with self._session_factory() as session:
            self._audit(
                session,
                principal,
                "system.module.updated",
                f"system:module:{module_id}"[:200],
            )
        return result

    # -------------------------------------------------------------- operations
    def operation(self, principal: Principal, action: str) -> dict[str, Any]:
        permission = OPERATION_PERMISSIONS.get(action)
        if action not in ACTION_NAMES or permission is None:
            raise ValidationFailed("unknown system operation")
        with self._session_factory() as session:
            self._authorize(session, principal, permission, f"system:operation:{action}")
        outcome: ExecutorOutcome = self._executor_client().execute(action)
        with self._session_factory() as session:
            self._audit(
                session,
                principal,
                f"system.operation.{action}",
                "system:operation",
                outcome=outcome.state,
            )
        return outcome.as_dict()


__all__ = ["OPERATION_PERMISSIONS", "SystemService"]
