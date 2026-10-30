"""Read-only status and re-encryption for stored provider credentials.

Every stored provider key and every unexpired managed-gateway lease keeps its
upstream credential inside a Fernet token. This module reports how the current
key ring reads those tokens and rotates them onto the primary key. It never
prints, returns or persists a key, a plaintext credential or a ciphertext.

Rotation is transactional and idempotent: a token already readable by the
primary key is left byte-identical, an older token is re-encrypted with
``MultiFernet.rotate`` (preserving its original timestamp) and an unreadable
token is reported and left untouched, never deleted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.agent_integrations.models import AgentProvider
from itsm.agent_integrations.providers import (
    KEY_STATE_OLDER,
    KEY_STATE_PRIMARY,
    CredentialUnavailable,
    credential_key_fingerprints,
    credential_key_state,
    credential_storage_available,
    primary_fingerprint,
    rotate_credential,
)
from itsm.ai_gateway.models import AiGatewayLease
from itsm.config import Settings
from itsm.identity.clock import as_utc

PROVIDER_TABLE = "agent_providers"
LEASE_TABLE = "ai_gateway_leases"
PROVIDER_SCOPES = ("global", "personal")


def _counts() -> dict[str, int]:
    return {"total": 0, "primary": 0, "older": 0, "unreadable": 0}


def _tally(counts: dict[str, int], state: str) -> None:
    counts["total"] += 1
    bucket = state if state in (KEY_STATE_PRIMARY, KEY_STATE_OLDER) else "unreadable"
    counts[bucket] += 1


def _provider_rows(session: Session) -> list[tuple[str, str, str]]:
    statement = (
        select(AgentProvider.id, AgentProvider.scope, AgentProvider.api_key_ciphertext)
        .where(AgentProvider.api_key_ciphertext.is_not(None))
        .order_by(AgentProvider.id)
    )
    return [(row[0], row[1], row[2]) for row in session.execute(statement).all() if row[2]]


def _lease_rows(session: Session, now: datetime) -> list[tuple[str, str]]:
    statement = select(
        AiGatewayLease.id,
        AiGatewayLease.selection_ciphertext,
        AiGatewayLease.expires_at,
    ).order_by(AiGatewayLease.id)
    return [
        (row[0], row[1])
        for row in session.execute(statement).all()
        if row[2] is not None and as_utc(row[2]) > now
    ]


def status(session: Session, settings: Settings, *, now: datetime | None = None) -> dict[str, Any]:
    """Count stored ciphertext by table and scope against the configured ring."""
    moment = now or datetime.now(UTC)
    providers = {scope: _counts() for scope in PROVIDER_SCOPES}
    unreadable_rows: list[dict[str, str]] = []
    for provider_id, scope, ciphertext in _provider_rows(session):
        state = credential_key_state(settings, ciphertext)
        _tally(providers.setdefault(scope, _counts()), state)
        if state not in (KEY_STATE_PRIMARY, KEY_STATE_OLDER):
            unreadable_rows.append({"table": PROVIDER_TABLE, "id": provider_id, "scope": scope})
    leases = _counts()
    for lease_id, ciphertext in _lease_rows(session, moment):
        state = credential_key_state(settings, ciphertext)
        _tally(leases, state)
        if state not in (KEY_STATE_PRIMARY, KEY_STATE_OLDER):
            unreadable_rows.append({"table": LEASE_TABLE, "id": lease_id})
    return {
        "status": "ok" if not unreadable_rows else "unreadable_credentials",
        "action": "status",
        "credentialStorageAvailable": credential_storage_available(settings),
        "primaryFingerprint": primary_fingerprint(settings),
        "activeFingerprints": credential_key_fingerprints(settings),
        "providers": providers,
        "gatewayLeases": {"unexpired": leases},
        "unreadableRows": unreadable_rows,
    }


def rotate(
    session: Session,
    settings: Settings,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-encrypt every stored ciphertext onto the primary key in one transaction."""
    if not credential_storage_available(settings):
        raise CredentialUnavailable("credential storage is not configured")
    moment = now or datetime.now(UTC)
    rotated = {"providers": 0, "gatewayLeases": 0}
    pending = {"providers": 0, "gatewayLeases": 0}
    unchanged = {"providers": 0, "gatewayLeases": 0}
    unreadable: list[dict[str, str]] = []

    try:
        statement = (
            select(AgentProvider)
            .where(AgentProvider.api_key_ciphertext.is_not(None))
            .order_by(AgentProvider.id)
        )
        for row in session.scalars(statement).all():
            state = credential_key_state(settings, row.api_key_ciphertext or "")
            if state == KEY_STATE_PRIMARY:
                unchanged["providers"] += 1
            elif state == KEY_STATE_OLDER:
                pending["providers"] += 1
                if not dry_run:
                    row.api_key_ciphertext = rotate_credential(
                        settings, row.api_key_ciphertext or ""
                    )
                    rotated["providers"] += 1
            else:
                unreadable.append({"table": PROVIDER_TABLE, "id": row.id, "scope": row.scope})

        for lease in session.scalars(select(AiGatewayLease).order_by(AiGatewayLease.id)).all():
            if lease.expires_at is None or as_utc(lease.expires_at) <= moment:
                continue
            state = credential_key_state(settings, lease.selection_ciphertext)
            if state == KEY_STATE_PRIMARY:
                unchanged["gatewayLeases"] += 1
            elif state == KEY_STATE_OLDER:
                pending["gatewayLeases"] += 1
                if not dry_run:
                    lease.selection_ciphertext = rotate_credential(
                        settings, lease.selection_ciphertext
                    )
                    rotated["gatewayLeases"] += 1
            else:
                unreadable.append({"table": LEASE_TABLE, "id": lease.id})

        if not dry_run:
            session.commit()
    except BaseException:
        session.rollback()
        raise

    payload = status(session, settings, now=moment)
    payload.update(
        {
            "action": "rotate",
            "dryRun": dry_run,
            "rotated": rotated,
            "pendingRotation": pending,
            "unchanged": unchanged,
        }
    )
    return payload
