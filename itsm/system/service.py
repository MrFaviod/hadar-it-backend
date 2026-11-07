"""Canonical installation service shared by HTTP, MCP and the integrated agent."""

from __future__ import annotations

from collections.abc import Callable, Mapping
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
