"""System profiles: installation owner, business administrator and user.

Revision ID: 0021_system_profiles
Revises: 0020_agent_integrations

The migration is deliberately data-preserving and never promotes an existing
administrator:

* ``superadmin`` and ``user`` profiles are seeded; ``reader`` assignments move
  to ``user`` and the ``reader`` role is removed.
* ``operator`` keeps every policy row and assignment but becomes an ordinary
  (non built-in) custom business role, so its authority is not altered.
* ``admin`` keeps its identity and receives every business permission. It never
  receives the new reserved ``system.*`` codes.
* ``identity_identities.role_owner`` persists the delegator's role for machine
  reserved grants, so a later delegator change cannot silently broaden them.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision = "0021_system_profiles"
down_revision = "0020_agent_integrations"
branch_labels = None
depends_on = None

BUSINESS_PERMISSIONS: tuple[str, ...] = (
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
)
SYSTEM_PERMISSIONS: tuple[str, ...] = (
    "system.view",
    "system.providers",
    "system.modules",
    "system.configure",
    "system.backup",
    "system.update",
)
USER_PERMISSIONS: tuple[str, ...] = ("assets.view", "people.view")


def _roles_table() -> sa.TableClause:
    return sa.table(
        "identity_roles",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("built_in", sa.Boolean),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )


def _policies_table() -> sa.TableClause:
    return sa.table(
        "identity_role_policies",
        sa.column("role_id", sa.String),
        sa.column("resource", sa.String),
        sa.column("operation", sa.String),
    )


def _available_name(connection: sa.Connection, desired: str, role_id: str) -> str:
    """Return a display name that does not collide with another role."""
    query = text("SELECT id FROM identity_roles WHERE name = :name")
    row = connection.execute(query, {"name": desired}).first()
    if row is None or str(row[0]) == role_id:
        return desired
    fallback = f"{desired} (sistema)"
    if connection.execute(query, {"name": fallback}).first() is None:
        return fallback
    return f"{desired} ({role_id})"


def _upsert_role(connection: sa.Connection, role_id: str, desired: str, *, built_in: bool) -> None:
    name = _available_name(connection, desired, role_id)
    exists = connection.execute(
        text("SELECT id FROM identity_roles WHERE id = :id"), {"id": role_id}
    ).first()
    if exists is None:
        op.bulk_insert(
            _roles_table(),
            [
                {
                    "id": role_id,
                    "name": name,
                    "built_in": built_in,
                    "created_at": datetime.now(UTC),
                }
            ],
        )
        return
    connection.execute(
        text("UPDATE identity_roles SET name = :name, built_in = :built_in WHERE id = :id"),
        {"name": name, "built_in": built_in, "id": role_id},
    )


def _grant(connection: sa.Connection, role_id: str, codes: tuple[str, ...]) -> None:
    existing = {
        (str(resource), str(operation))
        for resource, operation in connection.execute(
            text("SELECT resource, operation FROM identity_role_policies WHERE role_id = :role_id"),
            {"role_id": role_id},
        )
    }
    missing = []
    for code in codes:
        resource, _, operation = code.partition(".")
        if (resource, operation) not in existing:
            missing.append({"role_id": role_id, "resource": resource, "operation": operation})
    if missing:
        op.bulk_insert(_policies_table(), missing)


def upgrade() -> None:
    op.add_column(
        "identity_identities",
        sa.Column("role_owner", sa.String(length=32), nullable=True),
    )

    connection = op.get_bind()
    _upsert_role(connection, "superadmin", "Superadministrador", built_in=True)
    _upsert_role(connection, "user", "Usuario", built_in=True)
    _upsert_role(connection, "admin", "Administrador", built_in=True)

    # ``operator`` keeps its policies and assignments but stops being built-in.
    connection.execute(
        text("UPDATE identity_roles SET built_in = :built_in WHERE id = :id"),
        {
            "built_in": False,
            "id": "operator",
        },
    )

    # Reader assignments become ordinary users; existing custom roles and every
    # administrator identity are left untouched.
    connection.execute(
        text("UPDATE identity_identities SET role_id = 'user' WHERE role_id = 'reader'")
    )
    connection.execute(text("DELETE FROM identity_role_policies WHERE role_id = 'reader'"))
    connection.execute(text("DELETE FROM identity_roles WHERE id = 'reader'"))

    _grant(connection, "admin", BUSINESS_PERMISSIONS)
    _grant(connection, "superadmin", BUSINESS_PERMISSIONS + SYSTEM_PERMISSIONS)
    _grant(connection, "user", USER_PERMISSIONS)


def downgrade() -> None:
    connection = op.get_bind()
    _upsert_role(connection, "reader", "Lector", built_in=True)
    _grant(connection, "reader", USER_PERMISSIONS)

    connection.execute(
        text("UPDATE identity_identities SET role_id = 'admin' WHERE role_id = 'superadmin'")
    )
    connection.execute(
        text("UPDATE identity_identities SET role_id = 'reader' WHERE role_id = 'user'")
    )

    # Remove only the grants/Roles introduced by this revision; the pre-0021
    # admin policy set (including grants added by 0004/0018) is preserved.
    connection.execute(text("DELETE FROM identity_role_policies WHERE resource = 'system'"))
    connection.execute(
        text("DELETE FROM identity_role_policies WHERE role_id IN ('superadmin', 'user')")
    )
    connection.execute(text("DELETE FROM identity_roles WHERE id IN ('superadmin', 'user')"))
    connection.execute(
        text("UPDATE identity_roles SET built_in = :built_in WHERE id = 'operator'"),
        {"built_in": True},
    )

    op.drop_column("identity_identities", "role_owner")
