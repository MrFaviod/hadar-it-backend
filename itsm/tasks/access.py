"""Authorize public task results from durable, server-owned task locators."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.identity.models import IdentityAuditEvent
from itsm.identity.permissions import ROLE_ADMIN, ROLE_SUPERADMIN
from itsm.identity.service import IdentityService, NotFound, Principal
from itsm.reports.models import ReportJob
from itsm.workflows.models import Operation


def authorize_task_read(
    session: Session, identity: IdentityService, principal: Principal, task_id: str
) -> None:
    """Never consult queue results until a known task's owner is authorized."""
    identity.authorize(principal, "assets.view", resource=f"task:{task_id}")
    owner = session.execute(
        select(IdentityAuditEvent.actor_id)
        .where(
            IdentityAuditEvent.action == "tasks.demo.submit",
            IdentityAuditEvent.resource == f"task:{task_id}",
            IdentityAuditEvent.outcome == "success",
        )
        .limit(1)
    ).scalar_one_or_none()
    if owner is None:
        owner = session.execute(
            select(Operation.owner_id).where(Operation.job_id == task_id).limit(1)
        ).scalar_one_or_none()
    if owner is None:
        owner = session.execute(
            select(ReportJob.owner_id).where(ReportJob.id == task_id)
        ).scalar_one_or_none()
    if owner == principal.actor_id:
        return
    if (
        owner is not None
        and principal.kind == "human"
        and not principal.api_key_id
        and not principal.scopes
    ):
        actor = identity.resolve_actor(principal.actor_id)
        if actor.role_id in {ROLE_ADMIN, ROLE_SUPERADMIN}:
            return
    raise NotFound("task not found")
