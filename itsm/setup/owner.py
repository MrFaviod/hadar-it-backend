"""Create the first installation owner through the existing identity bootstrap.

The setup service never writes an identity row itself: it opens the prepared
database, counts human identities, and delegates to
``IdentityService.bootstrap_superadmin`` so password hashing, role locking and
the first-owner refusal stay in one authority. A sealed early AI provider is
then handed to ``AgentIntegrationService`` and deleted only after the canonical
row is read back and its credential unsealed.

All database and provider imports happen inside functions: importing the setup
app must not create an engine or require a driver.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Mapping
from typing import Any

from itsm.setup.store import (
    OwnerExists,
    OwnerInputInvalid,
    ProviderTransferFailed,
    SetupConfigurationError,
    SetupSettings,
    SetupStore,
    StateRefused,
)

# Tests replace this hook to stop between durable steps and simulate a crash.
_checkpoint: Callable[[str], None] | None = None
PROVIDER_NAME = "Onboarding provider"


def _mark(stage: str) -> None:
    if _checkpoint is not None:
        _checkpoint(stage)


def _runtime_settings(environ: Mapping[str, str]) -> Any:
    from itsm.config import (
        InstallationConfigError,
        installation_config_path,
        resolve_settings_sources,
    )

    try:
        path = installation_config_path(environ)
    except InstallationConfigError as exc:
        raise SetupConfigurationError(
            "ITSM_INSTALLATION_CONFIG must be an absolute private file path"
        ) from exc
    return resolve_settings_sources(dict(environ), installation_path=path)


def _normalized(username: str) -> str:
    return username.strip().lower()


def _human_identities(session: Any) -> list[Any]:
    from sqlalchemy import select

    from itsm.identity.models import Identity
    from itsm.identity.permissions import HUMAN_ACTOR_KIND

    return list(
        session.scalars(select(Identity).where(Identity.actor_kind == HUMAN_ACTOR_KIND)).all()
    )


def _owner_status(store: SetupStore) -> str:
    record = store.owner_record()
    receipt = record.get("receipt") if isinstance(record, dict) else None
    if isinstance(receipt, dict):
        status = receipt.get("ai")
        if status in {"transferred", "pending"}:
            return str(status)
    return "pending"


def _transfer_provider(
    store: SetupStore,
    setup_settings: SetupSettings,
    runtime: Any,
    session_factory: Any,
    identity: Any,
) -> str:
    """Move the sealed early provider into the canonical table, then delete it."""

    from sqlalchemy import select

    from itsm.agent_integrations.models import AgentProvider
    from itsm.agent_integrations.providers import credential_key_state, unseal_credential
    from itsm.agent_integrations.service import AgentIntegrationService
    from itsm.identity.service import IdentityService

    record = store.ai_private_record()
    if not record or not record.get("ciphertext"):
        return "pending"
    ciphertext = str(record["ciphertext"])
    base_url = str(record["base_url"])
    model = str(record["model"])
    try:
        api_key = unseal_credential(runtime, ciphertext)
    except Exception as exc:  # a broken key ring must not delete the only copy
        raise ProviderTransferFailed(
            "the early provider credential cannot be unsealed with this key ring"
        ) from exc

    def canonical(session: Any) -> list[Any]:
        return [
            row
            for row in session.scalars(
                select(AgentProvider).where(
                    AgentProvider.scope == "personal",
                    AgentProvider.owner_id == identity.id,
                )
            ).all()
            if (row.base_url or "").rstrip("/") == base_url.rstrip("/")
        ]

    with session_factory() as check_session:
        principal = IdentityService(check_session, runtime)._principal(identity)
        existing = canonical(check_session)
    if not existing:
        service = AgentIntegrationService(runtime, session_factory)
        try:
            asyncio.run(
                service.create_provider(
                    principal,
                    {
                        "name": PROVIDER_NAME,
                        "baseUrl": base_url,
                        "scope": "personal",
                        "apiKey": api_key,
                        "models": [model],
                    },
                )
            )
        except Exception as exc:
            raise ProviderTransferFailed(
                "the canonical provider service refused the early provider"
            ) from exc
    with session_factory() as read_session:
        existing = canonical(read_session)
        if len(existing) != 1:
            raise ProviderTransferFailed("the canonical provider could not be read back")
        row = existing[0]
        try:
            stored_key = unseal_credential(runtime, row.api_key_ciphertext or "")
        except Exception as exc:
            raise ProviderTransferFailed(
                "the canonical provider credential cannot be read back"
            ) from exc
        state = credential_key_state(runtime, row.api_key_ciphertext)
    if stored_key != api_key or state != "primary":
        raise ProviderTransferFailed("the canonical provider credential does not match")
    _mark("provider_verified")
    public = dict(record.get("receipt") or {})
    public["provider"] = public.get("provider") or base_url.split("//", 1)[-1].split("/", 1)[0]
    public["model"] = public.get("model") or model
    store.mark_ai_transferred(receipt=public)
    return "transferred"


def create_first_owner(
    store: SetupStore,
    setup_settings: SetupSettings,
    *,
    username: str,
    display_name: str,
    email: str | None,
    password: str,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Bootstrap the only human superadmin and finish the provider handoff."""

    state = store.public_state()["state"]
    if state == "owner_ready":
        record = store.owner_record() or {}
        receipt = dict(record.get("receipt") or {})
        receipt.setdefault(
            "owner", {"username": record.get("username", username), "display_name": display_name}
        )
        receipt["ai"] = _owner_status(store)
        return receipt
    if state != "storage_ready":
        raise StateRefused("owner creation requires a prepared database")

    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    from itsm.database import create_engine_from_settings, create_session_factory
    from itsm.identity.service import (
        BootstrapRefused,
        Conflict,
        IdentityService,
        ValidationFailed,
    )

    source = dict(os.environ if environ is None else environ)
    runtime = _runtime_settings(source)
    token = store.begin_owner_attempt(_normalized(username))
    engine = None
    try:
        engine = create_engine_from_settings(runtime)
        session_factory = create_session_factory(engine)
        with Session(engine) as session:
            humans = _human_identities(session)
            if humans:
                matching = [row for row in humans if row.username == _normalized(username)]
                if len(humans) != 1 or not matching:
                    raise OwnerExists("the installation already has a human owner")
                identity = matching[0]
                view_username = identity.username
                view_name = identity.name
            else:
                try:
                    view = IdentityService(session, runtime).bootstrap_superadmin(
                        username,
                        display_name,
                        password,
                        email=email,
                    )
                except BootstrapRefused as exc:
                    raise OwnerExists("the installation already has a human owner") from exc
                except (ValidationFailed, Conflict) as exc:
                    raise OwnerInputInvalid(
                        "the owner details do not satisfy the identity policy"
                    ) from exc
                view_username = view.username
                view_name = view.name
                session.expire_all()
                identity = next(
                    (row for row in _human_identities(session) if row.username == view_username),
                    None,
                )
                if identity is None:
                    raise OwnerExists("the installation already has a human owner")
            _mark("owner")
            ai_status = _transfer_provider(
                store, setup_settings, runtime, session_factory, identity
            )
            session.commit()
        receipt = {
            "owner": {"username": view_username, "display_name": view_name},
            "ai": ai_status,
        }
        stored = store.record_owner_ready(
            username=view_username,
            receipt=receipt,
            attempt_token=token,
        )
        if isinstance(stored, dict) and isinstance(stored.get("receipt"), dict):
            return dict(stored["receipt"])
        return receipt
    except SQLAlchemyError as exc:
        store.abort_owner_attempt(token)
        raise ProviderTransferFailed("the prepared database stopped answering") from exc
    except BaseException:
        store.abort_owner_attempt(token)
        raise
    finally:
        if engine is not None:
            engine.dispose()
