"""The permission catalog, actor kinds and the built-in profile templates.

This module is the single authority for permission codes. Roles are stored as
resource/operation policy rows and evaluated by Casbin; nothing here grants a
permission implicitly, with the deliberate exception of the built-in profile
templates that the 0021 migration seeds.

Three persisted profiles own the product: ``superadmin`` owns the installation,
``admin`` administers ITSM business functions and ``user`` is read-only until a
custom business grant is assigned. ``operator`` is preserved as an ordinary
(not built-in) business role from earlier installations.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, Literal

ActorKind = Literal["human", "internal_agent", "external_agent", "external_client"]

ACTOR_KINDS: Final[tuple[ActorKind, ...]] = (
    "human",
    "internal_agent",
    "external_agent",
    "external_client",
)

HUMAN_ACTOR_KIND: Final[ActorKind] = "human"

MACHINE_ACTOR_KINDS: Final[frozenset[str]] = frozenset(
    {"internal_agent", "external_agent", "external_client"}
)

# Reserved installation authority. These codes exist in the Casbin catalog so
# every transport can be denied by the same policy engine, but the identity
# service additionally requires a persisted human superadmin (or an explicitly
# delegated machine whose delegator is an active human superadmin).
SYSTEM_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        "system.view",
        "system.providers",
        "system.modules",
        "system.configure",
        "system.backup",
        "system.update",
    }
)

# Stable UI/API codes: ``resource.operation``.
PERMISSION_CATALOG: Final[tuple[str, ...]] = (
    "agents.providers.personal",
    "assets.view",
    "assets.edit",
    "assets.assign",
    "assets.purge",
    "assets.remote",
    "reports.share",
    "people.view",
    "people.create",
    "people.edit",
    "config.general",
    "config.categories",
    "config.sites",
    "config.departments",
    "config.integrations",
    "users.view",
    "users.create",
    "users.edit",
    "roles.manage",
    "sessions.manage",
    "system.view",
    "system.providers",
    "system.modules",
    "system.configure",
    "system.backup",
    "system.update",
)

PERMISSION_CODES: Final[frozenset[str]] = frozenset(PERMISSION_CATALOG)

ROLE_SUPERADMIN: Final[str] = "superadmin"
ROLE_ADMIN: Final[str] = "admin"
ROLE_OPERATOR: Final[str] = "operator"
ROLE_USER: Final[str] = "user"

BUILT_IN_ROLE_IDS: Final[tuple[str, ...]] = (ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_USER)

BUILT_IN_ROLE_NAMES: Final[dict[str, str]] = {
    ROLE_SUPERADMIN: "Superadministrador",
    ROLE_ADMIN: "Administrador",
    ROLE_USER: "Usuario",
}

_OPERATOR_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        "assets.view",
        "assets.edit",
        "assets.assign",
        "assets.remote",
        "people.view",
        "people.create",
        "people.edit",
    }
)

_USER_PERMISSIONS: Final[frozenset[str]] = frozenset({"assets.view", "people.view"})

# Adding personal OpenAI-compatible providers is an explicit grant: no built-in
# business profile receives it implicitly. The 0023 migration grants it to the
# installation owner so it can be handed to a custom role.
PERSONAL_PROVIDER_PERMISSION: Final[str] = "agents.providers.personal"

BUILT_IN_ROLE_PERMISSIONS: Final[dict[str, frozenset[str]]] = {
    ROLE_SUPERADMIN: PERMISSION_CODES,
    ROLE_ADMIN: PERMISSION_CODES - SYSTEM_PERMISSIONS - {PERSONAL_PROVIDER_PERMISSION},
    ROLE_USER: _USER_PERMISSIONS,
}

# Machines never receive identity/policy administration, even when a role that
# contains those codes is assigned to them, and never inherit the superadmin or
# admin role. Permanent asset purge is human-only: the service refuses it for
# any machine actor and the permission itself is never effective there.
MACHINE_FORBIDDEN_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        "users.view",
        "users.create",
        "users.edit",
        "roles.manage",
        "sessions.manage",
        "assets.purge",
    }
)

# Sensitive machine operations additionally require an explicit approval
# reference recorded in the audit trail (no approval workflow exists yet).
SENSITIVE_MACHINE_PERMISSIONS: Final[frozenset[str]] = frozenset({"assets.remote"})


def split_permission(code: str) -> tuple[str, str]:
    """Split ``resource.operation`` without accepting partial codes."""
    resource, separator, operation = code.partition(".")
    if not separator or not resource or not operation or "." in operation:
        raise ValueError("permission code must be resource.operation")
    return resource, operation


def is_known_permission(code: str) -> bool:
    return code in PERMISSION_CODES


def is_full_administrator(grants: Iterable[tuple[str, str]]) -> bool:
    """True only when the persisted policy grants every known permission.

    The catalog now includes installation-only codes, so only the superadmin
    profile qualifies as a full administrator. Business administration must use
    the concrete business grants instead of this helper.
    """
    return {f"{resource}.{operation}" for resource, operation in grants} >= PERMISSION_CODES
