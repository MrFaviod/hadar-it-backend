"""Reserved installation authority, revalidated on every system operation.

Casbin policy rows remain the grant source. On top of that, a reserved
permission is effective only for a persisted human ``superadmin`` or for an
explicitly delegated machine whose active human delegator is a superadmin.
The identity is always reread here, so revoking either side takes effect on the
next call.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.models import Identity
from itsm.identity.permissions import (
    HUMAN_ACTOR_KIND,
    MACHINE_ACTOR_KINDS,
)
from itsm.identity.policy import PolicyEngine
from itsm.identity.service import IdentityService, PermissionDenied, Principal

SYSTEM_PERMISSIONS: Final[tuple[str, ...]] = (
    "system.view",
    "system.providers",
    "system.modules",
    "system.configure",
    "system.backup",
    "system.update",
)
ROLE_SUPERADMIN_ID: Final[str] = "superadmin"
ROLE_ADMIN_ID: Final[str] = "admin"


def require_system_authority(
    session: Session,
    settings: Settings,
    principal: Principal,
    permission: str,
    resource: str,
) -> None:
    """Authorize one reserved permission or audit the denial and raise."""
    if permission not in SYSTEM_PERMISSIONS:
        raise ValueError("not a reserved system permission")
    row = session.get(Identity, principal.actor_id)
    allowed = False
    if row is not None and row.active:
        engine = PolicyEngine.load(session)
        grants = engine.permissions(row.role_id)
        if row.actor_kind == HUMAN_ACTOR_KIND:
            allowed = row.role_id == ROLE_SUPERADMIN_ID and permission in grants
        elif row.actor_kind in MACHINE_ACTOR_KINDS:
            allowed = (
                row.role_id not in {ROLE_ADMIN_ID, ROLE_SUPERADMIN_ID}
                and getattr(row, "role_owner", None) == ROLE_SUPERADMIN_ID
                and permission in grants
                and row.delegated_by_id is not None
            )
            if allowed and row.delegated_by_id is not None:
                delegator = session.get(Identity, row.delegated_by_id)
                allowed = bool(
                    delegator is not None
                    and delegator.active
                    and delegator.actor_kind == HUMAN_ACTOR_KIND
                    and delegator.role_id == ROLE_SUPERADMIN_ID
                    and permission in engine.permissions(delegator.role_id)
                )
                if allowed and principal.scopes:
                    allowed = permission in principal.scopes
    if allowed:
        return
    IdentityService(session, settings).record_operation(
        principal,
        action=permission,
        resource=resource[:200],
        outcome="denied",
    )
    raise PermissionDenied("system operations are reserved to the installation owner")
