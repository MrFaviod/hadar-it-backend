"""The permission catalog, actor kinds and the built-in role templates.

This module is the single authority for permission codes. Roles are stored as
resource/operation policy rows and evaluated by Casbin; nothing here grants a
permission implicitly, with the deliberate exception of the built-in role
templates that the migration seeds.
"""

from __future__ import annotations

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

# Stable UI/API codes: ``resource.operation``.
PERMISSION_CATALOG: Final[tuple[str, ...]] = (
    "assets.view",
    "assets.edit",
    "assets.assign",
    "assets.remote",
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
)

PERMISSION_CODES: Final[frozenset[str]] = frozenset(PERMISSION_CATALOG)

ROLE_ADMIN: Final[str] = "admin"
ROLE_OPERATOR: Final[str] = "operator"
ROLE_READER: Final[str] = "reader"

BUILT_IN_ROLE_IDS: Final[tuple[str, ...]] = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)

BUILT_IN_ROLE_NAMES: Final[dict[str, str]] = {
    ROLE_ADMIN: "Administrador",
    ROLE_OPERATOR: "Operador",
    ROLE_READER: "Lector",
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

_READER_PERMISSIONS: Final[frozenset[str]] = frozenset({"assets.view", "people.view"})

BUILT_IN_ROLE_PERMISSIONS: Final[dict[str, frozenset[str]]] = {
    ROLE_ADMIN: PERMISSION_CODES,
    ROLE_OPERATOR: _OPERATOR_PERMISSIONS,
    ROLE_READER: _READER_PERMISSIONS,
}

# Machines never receive identity/policy administration, even when a role that
# contains those codes is assigned to them, and never inherit the admin role.
MACHINE_FORBIDDEN_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {"users.view", "users.create", "users.edit", "roles.manage", "sessions.manage"}
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
