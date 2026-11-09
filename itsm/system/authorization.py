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
    # IdentityService owns both installation-owner rules and live bearer ceilings.
    # Duplicating its policy here let a scoped human key inherit all owner grants.
    try:
        IdentityService(session, settings).authorize(principal, permission, resource=resource[:200])
    except PermissionDenied as exc:
        raise PermissionDenied(
            "system operations are reserved to the installation owner",
            key="api.system.system_operations_reserved_installation_owner",
        ) from exc
