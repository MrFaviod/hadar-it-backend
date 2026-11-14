"""Assisted configuration for the setup wizard.

Every change is a three-step conversation with the operator: read the current
effective value through the owning domain service, preview the diff, and apply
only after an explicit confirmation. The apply call runs in process and builds
the principal of the owner created moments earlier, so the domain service still
re-checks its own permission and audit trail; the setup process never writes
domain settings directly.

Nothing here trusts intent. An applied section is recorded with a sanitized
receipt built from what was read back, and a capability is only green when it
was observed: a provider row, a configured credential and a model that really
called a tool.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from itsm.setup import checklist as checklist_module
from itsm.setup.store import SetupError, SetupStore, StateRefused

PROBE_CATEGORY = "default"
#: Operational settings that setup owns in the private installation file. The
#: environment still wins over the file, by design; the read-back says so.
OPERATIONAL_SETTING_KEYS: tuple[str, ...] = (
    "auth_origin",
    "auth_cookie_secure",
    "auth_cookie_name",
    "auth_session_minutes_default",
)
_OPERATIONAL_ENV: dict[str, str] = {
    "auth_origin": "ITSM_AUTH_ORIGIN",
    "auth_cookie_secure": "ITSM_AUTH_COOKIE_SECURE",
    "auth_cookie_name": "ITSM_AUTH_COOKIE_NAME",
    "auth_session_minutes_default": "ITSM_AUTH_SESSION_MINUTES_DEFAULT",
}
RESTART_SCOPE: tuple[str, ...] = ("backend", "worker")
RESTART_NOTE = (
    "the installation file now carries these values; the backend and worker "
    "apply them after a restart"
)
_OPERATIONAL_STATUS_RANK = {"applied": 0, "risk": 1, "declared": 2}
#: The probe owns its client for one bounded turn; the address policy and the
#: assistant timeout bound the run, this only stops a socket hanging forever.
_PROBE_CLIENT_TIMEOUT = 30.0
_SAFE_REASON = re.compile(r"[^a-z0-9_]+")
_MAX_REASON = 80


class ConfigurationUnavailable(SetupError):
    """The installation database or a domain service could not answer."""

    code = "configuration_unavailable"


class ConfigurationInvalid(SetupError):
    """The proposed values cannot be applied by the owning service."""

    code = "configuration_invalid"


class PermissionRefused(SetupError):
    """The owner principal is not allowed to change this section."""

    code = "permission_denied"


class ConfirmationRequired(SetupError):
    """A write was proposed without the human confirmation flag."""

    code = "confirmation_required"


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def _now() -> datetime:
    return datetime.now(UTC)


def _clean_reason(value: Any) -> str:
    text = str(value or "").strip().lower().replace(" ", "_")
    text = _SAFE_REASON.sub("", text)[:_MAX_REASON].strip("_")
    return text or "unspecified"


def _runtime_settings(environ: Mapping[str, str] | None = None) -> Any:
    """Resolve the installation settings; secrets stay inside the runtime."""

    from itsm.config import (
        InstallationConfigError,
        resolve_settings_sources,
    )

    source = dict(os.environ) if environ is None else dict(environ)
    try:
        return resolve_settings_sources(source)
    except InstallationConfigError as exc:
        raise ConfigurationUnavailable("the installation settings could not be read") from exc


def _database(environ: Mapping[str, str] | None = None):
    from itsm.database import create_engine_from_settings, create_session_factory

    settings = _runtime_settings(environ)
    try:
        engine = create_engine_from_settings(settings)
    except Exception as exc:  # pragma: no cover - defensive translation
        raise ConfigurationUnavailable("the installation database is not usable") from exc
    return settings, engine, create_session_factory(engine)


@contextmanager
def _domain(environ: Mapping[str, str] | None = None) -> Iterator[tuple[Any, Any, Any]]:
    settings, engine, factory = _database(environ)
    try:
        yield settings, engine, factory
    finally:
        engine.dispose()


def _owner_principal(settings: Any, factory: Any):
    """Rebuild the owner principal from the database, once per service call."""

    from sqlalchemy import select

    from itsm.identity.models import Identity, IdentityRole
    from itsm.identity.service import HUMAN_ACTOR_KIND, IdentityService

    with factory() as session:
        identity = session.scalars(
            select(Identity)
            .join(IdentityRole, IdentityRole.id == Identity.role_id)
            .where(Identity.actor_kind == HUMAN_ACTOR_KIND, Identity.active.is_(True))
            .where(IdentityRole.id == "superadmin")
        ).first()
        if identity is None:
            raise ConfigurationUnavailable("the first owner is missing")
        identity_service = IdentityService(session, settings)
        return identity_service._principal(identity)


def _translate(function: Callable[[], Any]) -> Any:
    """Run a domain call and translate its refusals into setup errors."""

    from itsm.identity.service import Conflict, NotFound, PermissionDenied, ValidationFailed

    try:
        return function()
    except PermissionDenied as exc:
        raise PermissionRefused("the installation owner may not change this section") from exc
    except (ValidationFailed, Conflict, NotFound) as exc:
        raise ConfigurationInvalid("the proposed values were refused") from exc


@dataclass(frozen=True)
class SectionPlan:
    """A section's shape: what it is called and whether it may be postponed."""

    id: str
    required: bool
    postponable: bool
    actions: tuple[str, ...]


def section_plan(mode: str, section: str) -> SectionPlan:
    if section not in checklist_module.SECTIONS:
        raise ConfigurationInvalid("unknown configuration section")
    return SectionPlan(
        id=section,
        required=checklist_module.section_required(mode, section),
        postponable=checklist_module.section_postponable(section),
        actions=("apply", "postpone")
        if checklist_module.section_postponable(section)
        else ("apply",),
    )


# --------------------------------------------------------------------- read
def _appearance_current(settings: Any, factory: Any, principal: Any) -> dict[str, Any]:
    from itsm.appearance.service import AppearanceService

    service = AppearanceService(factory, settings=settings)
    active = service.active()
    return {
        "preset": active.get("activeId"),
        "previous": active.get("previousId"),
        "builtinIds": list(active.get("builtinIds") or []),
    }


def _appearance_apply(
    settings: Any, factory: Any, principal: Any, values: dict[str, Any]
) -> dict[str, Any]:
    from itsm.appearance.service import AppearanceService

    service = AppearanceService(factory, settings=settings)
    preset = str(values.get("preset") or "").strip()
    if not preset:
        raise ConfigurationInvalid("a preset is required")
    catalog = _translate(lambda: service.presets(principal))
    known = {str(item.get("id")) for item in catalog.get("presets") or []}
    if preset not in known:
        raise ConfigurationInvalid("unknown appearance preset")
    _translate(lambda: service.apply_preset(principal, preset))
    current = _appearance_current(settings, factory, principal)
    if current["preset"] != preset:
        raise ConfigurationUnavailable("the appearance change did not persist")
    return {
        "status": checklist_module.GREEN,
        "receipt": {
            "source": "apply_preset",
            "active_id": current["preset"],
            "previous_id": current["previous"],
        },
    }


def _agent_current(settings: Any, factory: Any) -> dict[str, Any]:
    from itsm.system.providers import (
        credential_configured,
        effective_selection,
        persisted_selection,
    )

    with factory() as session:
        persisted = persisted_selection(session)
        effective = persisted or effective_selection(session, settings)
    return {
        "provider": effective.provider if effective else None,
        "model": effective.model if effective else None,
        "source": effective.source if effective else None,
        "persisted": persisted is not None,
        "credential_configured": bool(effective and credential_configured(effective.provider)),
    }


def _agent_apply(
    store: SetupStore,
    mode: str,
    settings: Any,
    factory: Any,
    principal: Any,
    values: dict[str, Any],
) -> dict[str, Any]:
    from itsm.system.providers import (
        ProviderSelectionError,
        credential_configured,
        persisted_selection,
        validate_selection,
    )
    from itsm.system.service import SystemService

    provider = str(values.get("provider") or "").strip()
    model = str(values.get("model") or "").strip()
    try:
        validate_selection(provider, model)
    except ProviderSelectionError as exc:
        raise ConfigurationInvalid("the provider selection is not valid") from exc

    _translate(
        lambda: SystemService(settings, factory).set_provider(
            principal, {"provider": provider, "model": model}
        )
    )
    with factory() as session:
        persisted = persisted_selection(session)
    if persisted is None or persisted.provider != provider or persisted.model != model:
        raise ConfigurationUnavailable("the provider selection did not persist")

    credential = credential_configured(provider)
    ai = store.public_state().get("ai") or {}
    probe = {
        "capability": "unverified",
        "tool": None,
        "latency_ms": None,
        "reason": "credential_missing",
    }
    if credential:
        probe = _probe_agent(settings, factory, principal, provider, model, mode)
    reason = probe.get("reason")
    ai_deferred = bool(ai.get("pending"))
    if ai_deferred:
        status = "pending"
        reason = "ai_deferred"
    elif probe.get("capability") == "verified":
        status = checklist_module.GREEN
    else:
        status = "pending"

    receipt = {
        "status": status,
        "provider": provider,
        "model": model,
        "credential_configured": credential,
        "capability": probe.get("capability"),
        "tool": probe.get("tool"),
        "latency_ms": probe.get("latency_ms"),
        "reason": _clean_reason(reason) if reason else None,
    }
    return {"status": status, "receipt": receipt}


def _unverified(reason: str) -> dict[str, Any]:
    return {"capability": "unverified", "tool": None, "latency_ms": None, "reason": reason}


class _OperatorDestinationMissing(Exception):
    """No destination the operator entered exists for this probe."""


def _provider_credential(provider: str) -> str:
    """Read the allowlisted credential of one provider from the process env."""

    from itsm.system.providers import PROVIDER_CATALOG

    entry = PROVIDER_CATALOG.get(provider) or {}
    for name in entry.get("credentialEnv") or ():  # type: ignore[union-attr]
        value = os.environ.get(str(name), "").strip()
        if value:
            return value
    return ""


def _verified_setup_provider(settings: Any, factory: Any, principal: Any) -> tuple[str, str] | None:
    """Read the provider this setup verified and handed to the owner, if it stayed."""

    from sqlalchemy import select

    from itsm.agent_integrations.models import AgentProvider
    from itsm.agent_integrations.providers import unseal_credential
    from itsm.setup.owner import PROVIDER_NAME

    owner_id = str(getattr(principal, "actor_id", "") or "")
    if not owner_id:
        return None
    try:
        with factory() as session:
            rows = [
                row
                for row in session.scalars(
                    select(AgentProvider).where(
                        AgentProvider.scope == "personal",
                        AgentProvider.owner_id == owner_id,
                        AgentProvider.enabled.is_(True),
                    )
                ).all()
                if (row.name or "") == PROVIDER_NAME
            ]
            if len(rows) != 1:
                return None
            row = rows[0]
            token = row.api_key_ciphertext or ""
            base_url = row.base_url or ""
            if not token or not base_url:
                return None
            return base_url, unseal_credential(settings, token)
    except Exception:  # observation only: a missing row leaves the section unverified
        return None


def _probe_model(
    settings: Any, factory: Any, principal: Any, provider: str, model_name: str
) -> tuple[Any, Any]:
    """Build the probe model over a client this probe owns and closes.

    The probe only talks to a destination the operator entered: the explicit
    installation base URL, or the provider the setup step verified and handed
    to this owner. Both are reached through
    :mod:`itsm.agent_integrations.providers`, which owns the address policy.
    The provider SDK would otherwise fall back to an ambient
    ``OPENAI_BASE_URL``, a destination nobody entered in this setup.
    """

    from itsm.agent_integrations.providers import (
        ProviderModelSelection,
        build_provider_model,
        personal_endpoint_policy,
        provider_http_client,
        validate_provider_endpoint,
    )

    if provider != "openai":
        from types import SimpleNamespace

        from itsm.agents.runtime import resolve_model

        client = provider_http_client(allow_private=True, timeout=_PROBE_CLIENT_TIMEOUT)
        model = resolve_model(
            settings, SimpleNamespace(provider=provider, model=model_name), http_client=client
        )
        return model, client
    explicit = getattr(settings, "agent_openai_base_url", None)
    api_key = _provider_credential(provider)
    if explicit and api_key:
        endpoint = validate_provider_endpoint(explicit, scope="global")
        client = provider_http_client(allow_private=True, timeout=_PROBE_CLIENT_TIMEOUT)
        selection = ProviderModelSelection(
            base_url=endpoint,
            model=model_name,
            api_key=api_key,
            allow_private=True,
        )
        return build_provider_model(selection, http_client=client), client
    verified = _verified_setup_provider(settings, factory, principal)
    if verified is None:
        raise _OperatorDestinationMissing()
    base_url, api_key = verified
    policy = personal_endpoint_policy(settings)
    endpoint = validate_provider_endpoint(base_url, scope="personal", policy=policy)
    client = provider_http_client(policy=policy, timeout=_PROBE_CLIENT_TIMEOUT)
    selection = ProviderModelSelection(
        base_url=endpoint,
        model=model_name,
        api_key=api_key,
        allow_private=policy,
    )
    return build_provider_model(selection, http_client=client), client


async def _probe_turn(model: Any, client: Any, reader: Callable[[], Mapping[str, Any]]) -> Any:
    """Run one probe turn and always close the client the probe opened."""

    from itsm.setup import assistant as bootstrap

    try:
        instance = bootstrap.BootstrapAssistant(
            model,
            status_reader=reader,
            timeout=bootstrap.PROBE_TIMEOUT_SECONDS,
            request_limit=bootstrap.PROBE_REQUEST_LIMIT,
            tool_calls_limit=bootstrap.PROBE_TOOL_CALLS_LIMIT,
            output_tokens=bootstrap.PROBE_OUTPUT_TOKENS,
            system_prompt=bootstrap._PROBE_SYSTEM_PROMPT,
        )
        return await asyncio.wait_for(
            instance.run(bootstrap.PROBE_QUESTION),
            timeout=bootstrap.PROBE_TIMEOUT_SECONDS + 5.0,
        )
    finally:
        await client.aclose()


def _probe_agent(
    settings: Any, factory: Any, principal: Any, provider: str, model_name: str, mode: str
) -> dict[str, Any]:
    """Ask the configured model to call a read-only tool; observation only.

    The probe only talks to a destination the operator entered: the provider
    verified in the setup step when there is one, otherwise the explicit
    installation base URL. An ambient ``OPENAI_BASE_URL`` is not a destination
    of its own, so a probe without either fails closed before any request.
    """

    from itsm.agent_integrations.providers import (
        CredentialInvalid,
        CredentialUnavailable,
        ProviderEndpointError,
    )
    from itsm.setup import assistant as bootstrap

    started = time.monotonic()
    try:
        model, client = _probe_model(settings, factory, principal, provider, model_name)
    except _OperatorDestinationMissing:
        return _unverified("credential_missing")
    except CredentialUnavailable, CredentialInvalid:
        return _unverified("credential_missing")
    except ProviderEndpointError:
        return _unverified("endpoint_forbidden")
    except Exception:
        return _unverified("model_unavailable")

    reader = lambda: {"state": "configuring", "mode": mode}  # noqa: E731 - tiny closure
    try:
        answer = asyncio.run(_probe_turn(model, client, reader))
    except Exception as exc:  # transport, provider and timeout failures
        return {
            "capability": "unverified",
            "tool": None,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "reason": bootstrap.diagnostic_for(exc) or "probe_failed",
        }
    latency = int((time.monotonic() - started) * 1000)
    called = bootstrap.TOOL_GET_SETUP_STATUS in answer.tools
    return {
        "capability": "verified" if called else "unverified",
        "tool": bootstrap.TOOL_GET_SETUP_STATUS if called else None,
        "latency_ms": latency,
        "reason": None if called else "tool_not_called",
    }


def _notification_current(settings: Any, factory: Any, principal: Any) -> dict[str, Any]:
    from itsm.notifications.service import NotificationService

    with factory() as session:
        service = NotificationService(session, settings)
        config = _translate(lambda: service.get_config(principal))
    channels = list(config.get("channels") or [])
    return {"channels": channels, "count": len(channels)}


def _notification_apply(
    settings: Any, factory: Any, principal: Any, values: dict[str, Any]
) -> dict[str, Any]:
    from itsm.notifications.service import NotificationService

    payload = {
        "kind": str(values.get("kind") or "").strip(),
        "name": str(values.get("name") or "").strip(),
        "enabled": bool(values.get("enabled", True)),
        "config": dict(values.get("config") or {}),
    }
    if values.get("secretRef"):
        payload["secretRef"] = str(values["secretRef"])
    with factory() as session:
        service = NotificationService(session, settings)
        saved = _translate(lambda: service.save_channel(principal, payload))
    return {
        "status": checklist_module.GREEN,
        "receipt": {
            "source": "save_channel",
            "kind": saved.get("kind"),
            "name": saved.get("name"),
            "enabled": bool(saved.get("enabled")),
        },
    }


def _monitoring_current(settings: Any, factory: Any, principal: Any) -> dict[str, Any]:
    from itsm.monitoring.service import MonitoringService

    with factory() as session:
        service = MonitoringService(session, settings)
        config = _translate(lambda: service.get_config(principal))
    profiles = list(config.get("profiles") or [])
    profile = next(
        (item for item in profiles if item.get("category") == PROBE_CATEGORY),
        profiles[0] if profiles else None,
    )
    return {"category": PROBE_CATEGORY, "profile": profile}


def _monitoring_apply(
    settings: Any, factory: Any, principal: Any, values: dict[str, Any]
) -> dict[str, Any]:
    from itsm.monitoring.service import MonitoringService

    category = str(values.get("category") or PROBE_CATEGORY)
    updates = {key: value for key, value in values.items() if key != "category"}
    with factory() as session:
        service = MonitoringService(session, settings)
        saved = _translate(lambda: service.update_profile(principal, category, updates))
    return {
        "status": checklist_module.GREEN,
        "receipt": {
            "source": "update_profile",
            "category": saved.get("category"),
            "enabled": bool(saved.get("enabled")),
            "checkType": saved.get("checkType"),
        },
    }


# ---------------------------------------------------------------- sections
_APPLIERS: dict[str, Callable[..., dict[str, Any]]] = {
    "appearance": _appearance_apply,
    "agent": _agent_apply,
    "notifications": _notification_apply,
    "monitoring": _monitoring_apply,
}


def _stored_sections(store: SetupStore) -> dict[str, Any]:
    record = store.configuration_record()
    sections = record.get("sections")
    return dict(sections) if isinstance(sections, dict) else {}


def _section_status(store: SetupStore, section: str) -> str:
    entry = _stored_sections(store).get(section)
    return str(entry.get("status")) if isinstance(entry, dict) else "pending"


def _apply_values(
    store: SetupStore,
    mode: str,
    section: str,
    values: dict[str, Any],
    environ: Mapping[str, str] | None,
) -> dict[str, Any]:
    if section == "operational":
        raise ConfigurationInvalid("operational items are observed, not configured")
    applier = _APPLIERS.get(section)
    if applier is None:
        raise ConfigurationInvalid("unknown configuration section")
    with _domain(environ) as (settings, _engine, factory):
        principal = _owner_principal(settings, factory)
        if section == "agent":
            result = applier(store, mode, settings, factory, principal, values)
        else:
            result = applier(settings, factory, principal, values)
    entry = store.record_configuration_section(
        section, status=str(result["status"]), receipt=dict(result["receipt"])
    )
    plan = section_plan(mode, section)
    return {
        "section": section,
        "required": plan.required,
        "postponable": plan.postponable,
        "status": entry["status"],
        "receipt": entry["receipt"],
    }


def read_section(
    store: SetupStore,
    mode: str,
    section: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return the section's stored decision and, where possible, its live value."""

    plan = section_plan(mode, section)
    stored = _stored_sections(store).get(section)
    entry = stored if isinstance(stored, dict) else {}
    body: dict[str, Any] = {
        "section": section,
        "required": plan.required,
        "postponable": plan.postponable,
        "status": entry.get("status", "pending"),
        "receipt": entry.get("receipt"),
        "current": None,
        "proposed": None,
        "actions": list(plan.actions),
    }
    try:
        if section == "operational":
            with _domain(environ) as (settings, _engine, factory):
                body["current"] = _operational_current(settings, factory, environ)
        elif section == "agent":
            with _domain(environ) as (settings, _engine, factory):
                body["current"] = _agent_current(settings, factory)
        elif section in _APPLIERS:
            with _domain(environ) as (settings, _engine, factory):
                principal = _owner_principal(settings, factory)
                if section == "appearance":
                    body["current"] = _appearance_current(settings, factory, principal)
                elif section == "notifications":
                    body["current"] = _notification_current(settings, factory, principal)
                elif section == "monitoring":
                    body["current"] = _monitoring_current(settings, factory, principal)
    except ConfigurationUnavailable, SetupError:
        body["current"] = None
        body["currentUnavailable"] = True
    return body


def _installation_file_values(environ: Mapping[str, str] | None) -> dict[str, Any]:
    """Read the installation file's values for provenance; never raise to readers."""

    from itsm.config import (
        InstallationConfigError,
        _load_installation_values,
        installation_config_path,
    )

    try:
        path = installation_config_path(environ)
    except InstallationConfigError:
        return {}
    if path is None:
        return {}
    try:
        return dict(_load_installation_values(path))
    except InstallationConfigError:
        return {}


def _same_setting(left: Any, right: Any) -> bool:
    return str(left).strip().lower() == str(right).strip().lower()


def _operational_provenance(
    environ: Mapping[str, str] | None, settings: Any
) -> dict[str, dict[str, Any]]:
    """Say, per setting, whether the environment or the file produced the value."""

    file_values = _installation_file_values(environ)
    source_environment = dict(os.environ if environ is None else environ)
    detail: dict[str, dict[str, Any]] = {}
    for key in OPERATIONAL_SETTING_KEYS:
        env_name = _OPERATIONAL_ENV[key]
        effective = getattr(settings, key)
        source = "default"
        overridden_by = None
        if env_name in source_environment:
            source = "env"
            if key in file_values and not _same_setting(file_values[key], effective):
                overridden_by = env_name
        elif key in file_values:
            source = "installation"
        detail[key] = {
            "value": effective,
            "source": source,
            "overridden_by": overridden_by,
        }
    return detail


def _declared_policy(factory: Any) -> dict[str, Any] | None:
    """Read the declaration back from the installation database."""

    from itsm.setup import backup_policy

    try:
        with factory() as session:
            row = backup_policy.read_policy(session)
            return backup_policy.as_body(row) if row is not None else None
    except Exception:  # a missing table or a dead database is simply "not declared"
        return None


def _operational_current(
    settings: Any, factory: Any, environ: Mapping[str, str] | None
) -> dict[str, Any]:
    provenance = _operational_provenance(environ, settings)
    file_values = _installation_file_values(environ)
    restart_required = any(key in file_values for key in OPERATIONAL_SETTING_KEYS)
    return {
        "origin": settings.auth_origin,
        "cookie_secure": bool(settings.auth_cookie_secure),
        "worker": "unknown",
        "settings": provenance,
        "backup_policy": _declared_policy(factory),
        "restart_required": restart_required,
        "restart_scope": list(RESTART_SCOPE),
        "note": RESTART_NOTE if restart_required else "operational items are observed by verify",
    }


def _policy_source(values: dict[str, Any]) -> dict[str, Any]:
    from itsm.setup import backup_policy

    source = values.get("policy")
    if not isinstance(source, dict):
        source = values
    return {key: source.get(key) for key in backup_policy.FIELDS}


def _operational_values(values: dict[str, Any]) -> dict[str, Any]:
    """Validate the origin/session values the operator proposed, before any write."""

    from pydantic import ValidationError

    from itsm.config import Settings

    if not isinstance(values, dict):
        raise ConfigurationInvalid("operational settings must be proposed as an object")
    if set(values) - set(OPERATIONAL_SETTING_KEYS):
        raise ConfigurationInvalid("only the public origin and session settings can be applied")
    picked = {
        key: values[key]
        for key in OPERATIONAL_SETTING_KEYS
        if key in values and values[key] is not None
    }
    if not picked:
        raise ConfigurationInvalid("no operational setting was proposed")
    try:
        validated = Settings(_env_file=None, **picked)
    except ValidationError as exc:
        raise ConfigurationInvalid("the proposed operational values are not valid") from exc
    return {key: getattr(validated, key) for key in picked}


def _record_operational(store: SetupStore, status: str, receipt: dict[str, Any]) -> dict[str, Any]:
    """Keep one operational receipt: an origin apply and a declaration coexist."""

    entry = _stored_sections(store).get("operational")
    existing = entry if isinstance(entry, dict) else {}
    merged = dict(existing.get("receipt") or {})
    merged.update(receipt)
    previous = str(existing.get("status") or "pending")
    chosen = (
        status
        if _OPERATIONAL_STATUS_RANK.get(status, -1) >= _OPERATIONAL_STATUS_RANK.get(previous, -1)
        else previous
    )
    return store.record_configuration_section("operational", status=chosen, receipt=merged)


def _section_result(mode: str, entry: dict[str, Any]) -> dict[str, Any]:
    plan = section_plan(mode, "operational")
    return {
        "section": "operational",
        "required": plan.required,
        "postponable": plan.postponable,
        "status": entry["status"],
        "receipt": entry["receipt"],
    }


def _operational_preview(
    plan: SectionPlan,
    environ: Mapping[str, str] | None,
    values: dict[str, Any],
) -> dict[str, Any]:
    """Preview a policy declaration or an origin/session change; write nothing."""

    from itsm.setup import backup_policy

    if values.get("item") == "backup_policy_declared":
        try:
            proposed = backup_policy.normalize(_policy_source(values))
        except backup_policy.BackupPolicyInvalid as exc:
            raise ConfigurationInvalid(str(exc)) from exc
        with _domain(environ) as (_settings, _engine, factory):
            current = _declared_policy(factory) or {}
        changes = [
            {"field": key, "from": current.get(key), "to": proposed[key]}
            for key in backup_policy.FIELDS
            if current.get(key) != proposed[key]
        ]
        return {
            "section": "operational",
            "status": "preview",
            "required": plan.required,
            "postponable": plan.postponable,
            "current": current,
            "proposed": proposed,
            "changes": changes,
            "preview_only": True,
        }

    picked = _operational_values(values)
    settings = _runtime_settings(environ)
    provenance = _operational_provenance(environ, settings)
    source_environment = dict(os.environ if environ is None else environ)
    changes = [
        {"field": key, "from": getattr(settings, key), "to": value}
        for key, value in picked.items()
        if not _same_setting(getattr(settings, key), value)
    ]
    env_override = sorted(
        {_OPERATIONAL_ENV[key] for key in picked if _OPERATIONAL_ENV[key] in source_environment}
    )
    return {
        "section": "operational",
        "status": "preview",
        "required": plan.required,
        "postponable": plan.postponable,
        "current": {key: provenance[key]["value"] for key in OPERATIONAL_SETTING_KEYS},
        "proposed": picked,
        "changes": changes,
        "env_override": env_override,
        "preview_only": True,
    }


def _declare_backup_policy(
    store: SetupStore,
    mode: str,
    environ: Mapping[str, str] | None,
    values: dict[str, Any],
) -> dict[str, Any]:
    """Store the operator's declaration, then read it back from the database.

    This writes installation metadata, never a domain setting: the effective
    backup state still belongs to ``SystemService.backup_status``.
    """

    from sqlalchemy.exc import SQLAlchemyError

    from itsm.setup import backup_policy

    if values.get("item") != "backup_policy_declared":
        raise ConfigurationInvalid(
            "only the backup policy can be declared in the operational section"
        )
    try:
        policy = backup_policy.normalize(_policy_source(values))
    except backup_policy.BackupPolicyInvalid as exc:
        raise ConfigurationInvalid(str(exc)) from exc
    owner = store.owner_record() or {}
    with _domain(environ) as (_settings, _engine, factory):
        try:
            with factory() as session:
                row = backup_policy.declare(session, policy, declared_by=owner.get("username"))
                body = backup_policy.as_body(row)
        except SQLAlchemyError as exc:
            raise ConfigurationUnavailable(
                "the installation database refused the backup policy declaration"
            ) from exc
    entry = _record_operational(
        store,
        "declared",
        {
            "item": "backup_policy_declared",
            "status": "declared",
            "source": backup_policy.TABLE_NAME,
            "backup_policy": body,
        },
    )
    return _section_result(mode, entry)


def _apply_operational(
    store: SetupStore,
    mode: str,
    environ: Mapping[str, str] | None,
    values: dict[str, Any],
) -> dict[str, Any]:
    """Publish validated settings into the private file and report what is effective."""

    from itsm.config import InstallationConfigError, installation_config_path
    from itsm.setup.storage import write_installation_values

    picked = _operational_values(values)
    try:
        path = installation_config_path(environ)
    except InstallationConfigError as exc:
        raise ConfigurationUnavailable(
            "ITSM_INSTALLATION_CONFIG must be an absolute private file path"
        ) from exc
    if path is None:
        raise ConfigurationInvalid(
            "ITSM_INSTALLATION_CONFIG is not set, so the operational values cannot be published"
        )
    write_installation_values(path, picked)
    effective = _runtime_settings(environ)
    provenance = _operational_provenance(environ, effective)
    overridden = sorted(
        {detail["overridden_by"] for detail in provenance.values() if detail["overridden_by"]}
    )
    entry = _record_operational(
        store,
        "applied",
        {
            "source": "installation_file",
            "written": sorted(picked),
            "effective": provenance,
            "overridden_by": overridden,
            "restart_required": True,
            "restart_scope": list(RESTART_SCOPE),
            "note": RESTART_NOTE,
        },
    )
    return _section_result(mode, entry)


def preview(
    store: SetupStore,
    mode: str,
    section: str,
    values: dict[str, Any],
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a diff preview; never calls an applying service."""

    plan = section_plan(mode, section)
    if section == "operational":
        return _operational_preview(plan, environ, values)
    if section not in _APPLIERS:
        raise ConfigurationInvalid("unknown configuration section")

    current_now = read_section(store, mode, section, environ=environ)
    current = current_now.get("current") or {}
    if section == "appearance":
        current_value = {"preset": current.get("preset", "generic")}
        proposed = {"preset": str(values.get("preset") or "").strip()}
    elif section == "agent":
        current_value = {
            "provider": current.get("provider"),
            "model": current.get("model"),
        }
        proposed = {
            "provider": str(values.get("provider") or "").strip(),
            "model": str(values.get("model") or "").strip(),
        }
        from itsm.system.providers import ProviderSelectionError, validate_selection

        try:
            validate_selection(proposed["provider"], proposed["model"])
        except ProviderSelectionError as exc:
            raise ConfigurationInvalid("the provider selection is not valid") from exc
    elif section == "notifications":
        channels = list(current.get("channels") or [])
        chosen = channels[0] if channels else {}
        current_value = {
            "kind": chosen.get("kind"),
            "name": chosen.get("name"),
            "enabled": chosen.get("enabled"),
        }
        proposed = {
            "kind": str(values.get("kind") or "").strip(),
            "name": str(values.get("name") or "").strip(),
            "enabled": bool(values.get("enabled", True)),
        }
    else:
        profile = current.get("profile") or {}
        current_value = {key: profile.get(key) for key in ("category", "enabled", "checkType")}
        proposed = {
            "category": str(values.get("category") or PROBE_CATEGORY),
            "enabled": bool(values.get("enabled", True)),
            "checkType": values.get("checkType"),
        }

    changes = [
        {"field": key, "from": current_value.get(key), "to": proposed[key]}
        for key in sorted(proposed)
        if current_value.get(key) != proposed.get(key)
    ]
    return {
        "section": section,
        "status": "preview",
        "required": plan.required,
        "postponable": plan.postponable,
        "current": current_value,
        "proposed": proposed,
        "changes": changes,
        "preview_only": True,
    }


def apply_section(
    store: SetupStore,
    mode: str,
    section: str,
    values: dict[str, Any],
    *,
    action: str = "apply",
    confirm: bool = False,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Apply one section after the human confirmation; never a silent write."""

    plan = section_plan(mode, section)
    if action not in {"apply", "postpone", "accept_risk", "declare"}:
        raise ConfigurationInvalid("unknown configuration action")
    if action == "postpone":
        if not plan.postponable:
            raise ConfigurationInvalid("this section cannot be postponed")
        if not confirm:
            raise ConfirmationRequired("postponing a section needs the operator's confirmation")
        receipt = {
            "status": "postponed",
            "reason": _clean_reason(values.get("reason")),
            "postponed_at": _iso(_now()),
        }
        entry = store.record_configuration_section(section, status="postponed", receipt=receipt)
        return {
            "section": section,
            "required": plan.required,
            "postponable": plan.postponable,
            "status": "postponed",
            "receipt": entry["receipt"],
        }
    if action == "accept_risk":
        if section != "operational" or str(values.get("item")) != "backup_policy_declared":
            raise ConfigurationInvalid("only the production backup can be accepted as a risk")
        if (
            store.public_state().get("mode") != "prod"
            and _runtime_settings(environ).release_mode != "prod"
        ):
            raise ConfigurationInvalid("a backup risk only exists in production")
        if not confirm:
            raise ConfirmationRequired("accepting a risk needs the operator's confirmation")
        receipt = {
            "status": "risk",
            "item": "backup_policy_declared",
            "reason": _clean_reason(values.get("reason")),
            "accepted_at": _iso(_now()),
        }
        entry = _record_operational(store, "risk", receipt)
        return {
            "section": section,
            "required": plan.required,
            "postponable": plan.postponable,
            "status": "risk",
            "receipt": entry["receipt"],
        }

    if not confirm:
        raise ConfirmationRequired("applying a configuration needs explicit confirmation")
    if section == "operational":
        if action == "declare":
            return _declare_backup_policy(store, mode, environ, values)
        if action == "apply":
            return _apply_operational(store, mode, environ, values)
        raise ConfigurationInvalid("unknown configuration action for the operational section")
    if action == "declare":
        raise ConfigurationInvalid("only the operational backup policy can be declared")
    return _apply_values(store, mode, section, values, environ)


# -------------------------------------------------------------- verification
WORKER_PROBE_TIMEOUT_SECONDS = 20.0
WORKER_PROBE_POLL_SECONDS = 0.25


def _worker_observation(settings: Any, *, queue_ok: bool) -> dict[str, Any]:
    """Observe a real worker completing one harmless job.

    A pid marker only proves a process once existed; on redis or postgres there
    is no marker at all. Setup therefore enqueues ``setup_ping`` and waits a
    bounded time for a worker to report it complete. A timeout stays ``unknown``
    and blocks completion instead of assuming a worker is alive.
    """

    from itsm.tasks.adapter import HueyTaskQueue, TaskState, TaskStorageUnavailable

    if not queue_ok:
        return {"status": "pending", "evidence": f"{settings.task_storage} queue did not answer"}

    queue = HueyTaskQueue(settings)
    try:
        submitted = queue.submit_setup_ping()
    except TaskStorageUnavailable:
        return {"status": "pending", "evidence": "the queue refused the setup ping"}

    deadline = time.monotonic() + WORKER_PROBE_TIMEOUT_SECONDS
    last = "the setup ping stayed pending"
    while time.monotonic() < deadline:
        try:
            status = queue.get_status(submitted.task_id)
        except TaskStorageUnavailable:
            return {"status": "unknown", "evidence": "queue storage stopped answering"}
        if status is not None:
            if status.state is TaskState.COMPLETE:
                return {"status": "passed", "evidence": "a worker completed the setup ping"}
            if status.state is TaskState.ERROR:
                return {"status": "pending", "evidence": "the worker failed the setup ping"}
            if status.state is TaskState.RUNNING:
                last = "a worker started the setup ping but did not finish it"
        time.sleep(WORKER_PROBE_POLL_SECONDS)
    return {
        "status": "unknown",
        "evidence": (
            f"{last} within {int(WORKER_PROBE_TIMEOUT_SECONDS)} s; "
            "check the worker and verify again"
        ),
    }


def _observe(
    store: SetupStore,
    mode: str,
    settings: Any,
    engine: Any,
    factory: Any,
    principal: Any,
) -> dict[str, dict[str, Any]]:
    """Collect the operational evidence without claiming what is not observed."""

    from itsm.database import check_readiness
    from itsm.tasks.adapter import HueyTaskQueue

    observations: dict[str, dict[str, Any]] = {}
    snapshot = store.status_snapshot()
    observations["setup_enabled"] = {
        "status": "passed" if snapshot.get("setup_enabled") else "pending",
        "evidence": "setup answers while enabled"
        if snapshot.get("setup_enabled")
        else "setup disabled by the operator",
    }
    public = store.public_state()
    observations["claim_completed"] = {
        "status": "passed" if store.configuration_record() else "pending",
        "evidence": "claim completed before configuration"
        if store.configuration_record()
        else "no claim recorded",
    }
    owner = store.owner_record() or {}
    observations["owner_present"] = {
        "status": "passed" if owner.get("username") else "pending",
        "evidence": f"owner {owner.get('username')} recorded"
        if owner.get("username")
        else "no owner recorded",
    }

    task_ok = False
    try:
        HueyTaskQueue(settings).probe()
        task_ok = True
    except Exception:
        pass

    try:
        readiness = check_readiness(engine, settings, task_storage_ok=task_ok)
    except Exception:
        readiness = None
    if readiness is None or readiness.database != "ok":
        observations["database_ready"] = {"status": "pending", "evidence": "database unavailable"}
        observations["migrated"] = {"status": "pending", "evidence": "database unavailable"}
    else:
        observations["database_ready"] = {"status": "passed", "evidence": "database answered"}
        migrations = readiness.migrations
        if migrations is not None and getattr(migrations, "is_current", False):
            observations["migrated"] = {
                "status": "passed",
                "evidence": f"migration head {migrations.head} installed",
            }
        else:
            current = getattr(migrations, "current", None)
            head = getattr(migrations, "head", None)
            observations["migrated"] = {
                "status": "pending",
                "evidence": f"revision {current or 'none'} is not the head {head or 'unknown'}",
            }

    observations["worker_ready"] = _worker_observation(settings, queue_ok=task_ok)
    observations["storage_ready"] = _storage_observation(settings)
    observations["origin_valid"] = _origin_observation(settings.auth_origin)
    observations["session_valid"] = _session_observation(settings, mode)

    from itsm.system.service import SystemService

    try:
        status = _translate(lambda: SystemService(settings, factory).backup_status(principal))
    except SetupError:
        status = {"available": False, "reason": "unreadable"}
    declared = _declared_policy(factory)
    if status.get("available"):
        observations["backup_policy_declared"] = {
            "status": "passed",
            "evidence": str(status.get("summary") or "published backup status")[:120],
        }
    elif declared:
        observations["backup_policy_declared"] = {
            "status": "declared",
            "evidence": (
                "declared: "
                f"{declared['location_kind']} target {declared['target']}; "
                f"{declared['schedule']}; retention {declared['retention']}; "
                f"responsible {declared['responsible']}"
            )[:240],
        }
    else:
        observations["backup_policy_declared"] = {
            "status": "pending",
            "evidence": str(status.get("reason") or "no backup policy declared"),
        }

    observations["ai"] = {
        "pending": bool((public.get("ai") or {}).get("pending")),
    }
    return observations


def _storage_observation(settings: Any) -> dict[str, Any]:
    path: Path = settings.attachment_storage_path
    probe = path / f".setup-probe-{os.getpid()}"
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"probe")
        probe.unlink()
    except OSError:
        return {"status": "pending", "evidence": f"{path} is not writable"}
    return {"status": "passed", "evidence": f"{path} is writable"}


def _origin_observation(origin: str) -> dict[str, Any]:
    parsed = urlsplit(str(origin or ""))
    bare = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    bare = bare and not parsed.path.strip("/") and not parsed.query and not parsed.fragment
    bare = bare and "@" not in parsed.netloc
    return {
        "status": "passed" if bare else "pending",
        "evidence": f"origin {parsed.scheme}://{parsed.netloc}"
        if bare
        else "origin is not a bare http(s) origin",
    }


def _session_observation(settings: Any, mode: str) -> dict[str, Any]:
    if mode != "prod":
        return {"status": "not_required", "evidence": "not required in dev"}
    host = urlsplit(str(settings.auth_origin)).hostname or ""
    loopback = host == "localhost"
    with suppress(ValueError):
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    secure = bool(settings.auth_cookie_secure) and host not in {"localhost", "127.0.0.1", "::1"}
    return {
        "status": "passed" if secure and not loopback else "pending",
        "evidence": (
            "secure cookies and a public origin"
            if secure and not loopback
            else "production needs Secure session cookies on a public origin"
        ),
    }


def verify(
    store: SetupStore, mode: str, *, environ: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Evaluate the contract checklist and open ``verifying`` only when green."""

    state = store.public_state().get("state")
    record = store.configuration_record()
    if state == "verifying":
        stored = record.get("verification") or {}
        return {
            "state": "verifying",
            "ready": True,
            "mode": mode,
            "checklist": list(stored.get("items") or []),
            "blocking": list(stored.get("blocking") or []),
            "acceptedRisk": list(stored.get("acceptedRisk") or []),
        }
    if state != "configuring":
        raise StateRefused("verification requires the configuring state")

    with _domain(environ) as (settings, engine, factory):
        principal = _owner_principal(settings, factory)
        observations = _observe(store, mode, settings, engine, factory, principal)

    result = checklist_module.build_checklist(mode, configuration=record, observations=observations)
    if not result["ready"]:
        return {"state": "configuring", **result}
    summary = {
        "blocking": result["blocking"],
        "acceptedRisk": result["acceptedRisk"],
        "items": [
            {
                "id": item["id"],
                "status": item["status"],
                "evidence": item["evidence"],
                "required": item["required"],
                "postponable": item["postponable"],
                "acceptedRisk": item["acceptedRisk"],
            }
            for item in result["checklist"]
        ],
    }
    store.record_verification(summary=summary)
    return {"state": "verifying", **result}


def recheck(
    store: SetupStore, mode: str, *, environ: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Re-run the observations from scratch, trusting no stored receipt.

    ``/complete`` uses this so a stale green checklist cannot finish setup after
    the worker, database or backup policy changed since ``/verify``.
    """

    with _domain(environ) as (settings, engine, factory):
        principal = _owner_principal(settings, factory)
        observations = _observe(store, mode, settings, engine, factory, principal)
    return checklist_module.build_checklist(
        mode, configuration=store.configuration_record(), observations=observations
    )


def overview(store: SetupStore, mode: str) -> dict[str, Any]:
    """Read the section overview plus the checklist built from stored receipts."""

    record = store.configuration_record()
    sections = []
    for section in checklist_module.SECTIONS:
        plan = section_plan(mode, section)
        sections.append(
            {
                "section": section,
                "required": plan.required,
                "postponable": plan.postponable,
                "status": _section_status(store, section),
                "actions": list(plan.actions),
            }
        )
    built = checklist_module.build_checklist(mode, configuration=record)
    return {
        "state": store.public_state().get("state"),
        "mode": mode,
        "sections": sections,
        "checklist": built["checklist"],
        "blocking": built["blocking"],
        "acceptedRisk": built["acceptedRisk"],
    }


__all__ = [
    "ConfigurationInvalid",
    "ConfigurationUnavailable",
    "ConfirmationRequired",
    "PermissionRefused",
    "apply_section",
    "overview",
    "preview",
    "read_section",
    "section_plan",
    "verify",
]
