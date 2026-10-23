"""Durable job dispatch: no raw credential, arbitrary callable or actor from input.

Dispatch is a database claim, not an in-process decision: only a conditional
state transition may queue work, so concurrent or repeated requests reuse the
same job locator instead of dispatching a second task. Execution revalidates the
stored executor session/credential and the human approval authority, and a
failure never regresses an operation that already completed.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from sqlalchemy import select, update

from itsm.identity.clock import as_utc, utcnow
from itsm.identity.models import IdentityCredential, IdentitySession
from itsm.identity.service import Conflict, IdentityService, PermissionDenied
from itsm.inventory.codes import serialized
from itsm.workflows.models import Operation
from itsm.workflows.service import WorkflowService

DISPATCHABLE_STATES = frozenset({"approved", "queue_error", "error"})
ACTIVE_STATES = frozenset({"queued", "running"})
TRUSTED_SOURCES = frozenset({"rest", "agent", "mcp", "internal"})


def _executor_payload(principal: Any, credential_digest: str | None) -> dict[str, Any]:
    """The trusted authority snapshot; never built from request input."""
    return {
        "actorId": principal.actor_id,
        "scopes": sorted(principal.scopes),
        "executionId": principal.execution_id,
        "authorizationRef": principal.authorization_ref,
        "sessionId": principal.session_id,
        "credentialDigest": credential_digest,
    }


def _trusted_source(service: WorkflowService) -> str:
    """Keep the trusted boundary value; never accept a caller-supplied source."""
    source = getattr(service, "source", None)
    return source if isinstance(source, str) and source in TRUSTED_SOURCES else "internal"


def _claim(
    service: WorkflowService,
    operation_id: str,
    observed_state: str,
    job_id: str,
    payload: dict[str, Any],
) -> bool:
    """Claim the observed state for one dispatch, or report a lost race.

    The observed state is part of the UPDATE: a caller working from a stale read
    can never queue a second task for the same operation.
    """
    result = service._session.execute(
        update(Operation)
        .where(Operation.id == operation_id, Operation.state == observed_state)
        .values(state="queued", job_id=job_id, payload=payload)
    )
    return result.rowcount == 1


def _store_state(
    service: WorkflowService, operation_id: str, job_id: str, state: str, *, from_state: str
) -> bool:
    """Move one operation between states without overwriting a later transition."""
    result = service._session.execute(
        update(Operation)
        .where(
            Operation.id == operation_id,
            Operation.state == from_state,
            Operation.job_id == job_id,
        )
        .values(state=state)
    )
    service._session.commit()
    return result.rowcount == 1


@serialized
def enqueue(
    service: WorkflowService,
    principal: Any,
    operation_id: str,
    queue: Any,
    *,
    credential_digest: str | None = None,
) -> dict[str, Any]:
    """Queue one approved operation; repeats reuse the locator instead of tasks."""
    operation = service._operation(principal, operation_id, "assets.edit")
    service._approval(operation, principal)
    state = operation.state
    stored_job = operation.job_id if isinstance(operation.job_id, str) else None
    job_id = stored_job or ""
    if state == "complete":
        return service.get(principal, operation_id)
    if state in ACTIVE_STATES:
        if not (state == "queued" and job_id and queue.get_status(job_id) is None):
            return service.get(principal, operation_id)
        # The dispatch died between the state commit and queue storage: recover
        # it with the same locator instead of leaving the operation stuck.
    elif state in DISPATCHABLE_STATES:
        job_id = ""
    else:
        raise Conflict("operation is not ready to enqueue")
    job_id = job_id or str(uuid4())
    payload = {
        **operation.payload,
        "source": _trusted_source(service),
        "executor": _executor_payload(principal, credential_digest),
    }
    if not _claim(service, operation_id, state, job_id, payload):
        service._session.rollback()
        raise Conflict("operation state changed; retry the request")
    service._session.commit()
    try:
        queue.submit_operation(operation_id, job_id)
    except Exception:
        _store_state(service, operation_id, job_id, "queue_error", from_state="queued")
        raise
    return service.get(principal, operation_id)


def _stored_executor(operation: Operation) -> dict[str, Any]:
    executor = operation.payload.get("executor")
    if not isinstance(executor, dict) or not isinstance(executor.get("actorId"), str):
        raise PermissionDenied("operation has no stored executor authority")
    return executor


def _assert_executor_authority(session: Any, principal: Any, executor: dict[str, Any]) -> None:
    """The persisted session or machine credential must still be usable."""
    if executor.get("sessionId"):
        grant = session.get(IdentitySession, executor["sessionId"])
        if (
            grant is None
            or grant.identity_id != principal.actor_id
            or grant.revoked_at is not None
            or as_utc(grant.expires_at) <= utcnow()
        ):
            raise PermissionDenied("job session is no longer active")
    elif principal.kind != "human":
        credential = session.scalar(
            select(IdentityCredential).where(
                IdentityCredential.identity_id == principal.actor_id,
                IdentityCredential.token_digest == executor.get("credentialDigest"),
                IdentityCredential.revoked_at.is_(None),
            )
        )
        if credential is None:
            raise PermissionDenied("job credential is no longer active")


def _mark_failed(session: Any, operation_id: str) -> None:
    """Record a failed attempt without regressing an already completed operation."""
    session.execute(
        update(Operation)
        .where(Operation.id == operation_id, Operation.state != "complete")
        .values(state="error")
    )
    session.commit()


def execute_job(session: Any, settings: Any, operation_id: str) -> dict[str, Any]:
    """Run one queued operation with the authority captured at enqueue time."""
    operation = session.get(Operation, operation_id)
    if operation is None:
        raise PermissionDenied("operation is not available")
    executor = _stored_executor(operation)
    try:
        identity = IdentityService(session, settings)
        principal = identity.resolve_actor(
            executor["actorId"],
            scopes=executor.get("scopes") or (),
            execution_id=executor.get("executionId"),
            authorization_ref=executor.get("authorizationRef"),
        )
        _assert_executor_authority(session, principal, executor)
        source = operation.payload.get("source")
        service = WorkflowService(
            session,
            settings,
            identity=identity,
            source=source if source in TRUSTED_SOURCES else "internal",
        )
        return service.execute(principal, operation_id)
    except Exception:
        session.rollback()
        _mark_failed(session, operation_id)
        raise
