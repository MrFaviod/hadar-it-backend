"""Finalize the installation: re-verify, write the marker, close the surface.

The database row is committed *before* the private store is advanced, and a
crash between the two still means complete: on restart the marker is read from
the database and the wizard never reopens. The exported report contains only
identifiers, observed receipts and checklist evidence; no credential, URL or
password ever enters it.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from itsm.installation import (
    SETUP_CONTRACT_VERSION,
    report_digest,
    write_completion,
)
from itsm.setup import configuration
from itsm.setup.store import SetupError, SetupStore, StateRefused

REPORT_CONTRACT = "onboarding/v1"
STORE_KEYS = (
    "version",
    "engine",
    "status",
    "identity",
    "config_source",
    "migrated",
    "identity_claimed",
)


class CompletionBlocked(SetupError):
    """The server-side re-verification is not green; nothing was written."""

    code = "completion_blocked"


class CompletionUnavailable(SetupError):
    """The installation database could not be reached to record completion."""

    code = "completion_unavailable"


def _checkpoint(stage: str) -> None:
    """Crash-test seam: production is a no-op between the two writes."""


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def build_report(store: SetupStore, mode: str) -> dict[str, Any]:
    """A sanitized, exportable report of what the setup process observed."""

    public = store.public_state()
    owner = store.owner_record() or {}
    storage = store.storage_receipt() or {}
    ai = public.get("ai") or {}
    configuration_record = store.configuration_record()
    verification = configuration_record.get("verification") or {}
    completion = store.completion_record()
    items = [
        {
            "id": item.get("id"),
            "section": item.get("section"),
            "required": item.get("required"),
            "postponable": item.get("postponable"),
            "status": item.get("status"),
            "evidence": item.get("evidence"),
            "blocking": item.get("blocking"),
            "acceptedRisk": item.get("acceptedRisk"),
        }
        for item in verification.get("items") or []
        if isinstance(item, dict)
    ]
    report: dict[str, Any] = {
        "contract": REPORT_CONTRACT,
        "setup_contract_version": SETUP_CONTRACT_VERSION,
        "mode": mode,
        "release_mode": mode,
        "state": public.get("state"),
        "instance_id": public.get("instance_id"),
        "owner": {"username": owner.get("username")},
        "ai": {
            "status": ai.get("status"),
            "provider": ai.get("provider"),
            "model": ai.get("model"),
            "pending": ai.get("pending"),
        },
        "storage": {key: storage.get(key) for key in STORE_KEYS},
        "checklist": items,
        "blocking": list(verification.get("blocking") or []),
        "acceptedRisk": list(verification.get("acceptedRisk") or []),
        "verified_at": verification.get("checked_at"),
        "completed_at": completion.get("completed_at"),
        "completed_by": completion.get("completed_by"),
        "report_digest": completion.get("report_digest"),
    }
    return report


def complete(
    store: SetupStore,
    mode: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Re-verify, write the completion row, then close the private store.

    Repeating the call after completion returns the stored report without
    touching the row or ``completed_at``.
    """

    stored = store.completion_record()
    if stored and isinstance(stored.get("report"), dict):
        return dict(stored["report"])
    if store.public_state().get("state") != "verifying":
        raise StateRefused("completion requires a green verification")

    try:
        result = configuration.recheck(store, mode, environ=environ)
    except SetupError:
        raise
    except Exception as exc:  # the database never answered; keep setup open
        raise CompletionUnavailable("the installation database is not usable") from exc
    if not result.get("ready"):
        blocking = ", ".join(str(item) for item in result.get("blocking") or [])
        raise CompletionBlocked(f"verification is not green: {blocking or 'unknown item'}")

    source = dict(os.environ) if environ is None else dict(environ)
    stack = contextlib.ExitStack()
    try:
        domain = stack.enter_context(configuration._domain(source))
    except SetupError:
        raise
    except Exception as exc:  # the database never answered; keep setup open
        raise CompletionUnavailable("the installation database is not usable") from exc
    with stack:
        settings, _engine, factory = domain
        try:
            principal = configuration._owner_principal(settings, factory)
        except SetupError:
            raise
        except Exception as exc:
            raise CompletionUnavailable("the installation database is not usable") from exc
        completed_by = getattr(principal, "actor_id", None)
        base = build_report(store, mode)
        stamp = datetime.now(UTC)
        candidate = {**base, "completed_at": _iso(stamp), "completed_by": completed_by}
        digest = report_digest(candidate)
        try:
            with factory() as session:
                row = write_completion(
                    session,
                    completed_by=completed_by,
                    instance_id=base.get("instance_id"),
                    setup_contract_version=SETUP_CONTRACT_VERSION,
                    digest=digest,
                    completed_at=stamp,
                )
        except SetupError:
            raise
        except Exception as exc:
            raise CompletionUnavailable("the installation database is not usable") from exc
        _checkpoint("committed")
        report = {
            **base,
            "state": "complete",
            "completed_at": _iso(row.completed_at),
            "completed_by": row.completed_by,
            "report_digest": row.report_digest,
        }
        store.mark_complete(
            completed_at=str(report["completed_at"]),
            completed_by=row.completed_by,
            instance_id=row.instance_id,
            setup_contract_version=row.setup_contract_version,
            report_digest=row.report_digest,
            report=report,
        )
    return report


def exported_report(store: SetupStore, mode: str) -> dict[str, Any]:
    """Read the stored report after completion, or a live preview before it."""

    stored = store.completion_record()
    report = stored.get("report") if isinstance(stored, dict) else None
    if isinstance(report, dict):
        return dict(report)
    return build_report(store, mode)


__all__ = [
    "CompletionBlocked",
    "CompletionUnavailable",
    "build_report",
    "complete",
    "exported_report",
]
