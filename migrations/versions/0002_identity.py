"""identity, roles, policies, sessions and audit trail

Revision ID: 0002_identity
Revises: 0001_foundation
Create Date: 2026-11-02

Portable schema for identity and authorization. Built-in roles, their policy
rows and the single security-settings row are seeded here; no user account is
created by a migration, so initial credentials always come from the explicit
installation CLI (``python -m itsm.identity.cli bootstrap-admin``).
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002_identity"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None

DEFAULT_SESSION_MINUTES = 480

BUILT_IN_ROLES: tuple[tuple[str, str], ...] = (
    ("admin", "Administrador"),
    ("operator", "Operador"),
    ("reader", "Lector"),
)

CATALOG: tuple[str, ...] = (
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

OPERATOR: tuple[str, ...] = (
    "assets.view",
    "assets.edit",
    "assets.assign",
    "assets.remote",
    "people.view",
    "people.create",
    "people.edit",
)

READER: tuple[str, ...] = ("assets.view", "people.view")


def _role_permissions() -> dict[str, tuple[str, ...]]:
    return {"admin": CATALOG, "operator": OPERATOR, "reader": READER}


def _timestamp() -> datetime:
    return datetime.now(UTC)


def upgrade() -> None:
    op.create_table(
        "identity_roles",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("built_in", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="uq_identity_roles_name"),
    )
    op.create_table(
        "identity_role_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column(
            "role_id",
            sa.String(length=64),
            sa.ForeignKey("identity_roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("resource", sa.String(length=64), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.UniqueConstraint(
            "role_id", "resource", "operation", name="uq_identity_role_policies_grant"
        ),
    )
    op.create_index("ix_identity_role_policies_role_id", "identity_role_policies", ["role_id"])
    op.create_table(
        "identity_identities",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=True),
        sa.Column("actor_kind", sa.String(length=32), nullable=False),
        sa.Column("person_id", sa.String(length=64), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column(
            "role_id",
            sa.String(length=64),
            sa.ForeignKey("identity_roles.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "delegated_by_id",
            sa.String(length=36),
            sa.ForeignKey("identity_identities.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_access_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("username", name="uq_identity_identities_username"),
    )
    op.create_index("ix_identity_identities_role_id", "identity_identities", ["role_id"])
    op.create_table(
        "identity_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column(
            "identity_id",
            sa.String(length=36),
            sa.ForeignKey("identity_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_access_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_digest", name="uq_identity_sessions_token_digest"),
    )
    op.create_index("ix_identity_sessions_identity_id", "identity_sessions", ["identity_id"])
    op.create_table(
        "identity_credentials",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column(
            "identity_id",
            sa.String(length=36),
            sa.ForeignKey("identity_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_digest", name="uq_identity_credentials_token_digest"),
    )
    op.create_index("ix_identity_credentials_identity_id", "identity_credentials", ["identity_id"])
    op.create_table(
        "identity_login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("username_key", sa.String(length=64), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("successful", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "ix_identity_login_attempts_username_key", "identity_login_attempts", ["username_key"]
    )
    op.create_index(
        "ix_identity_login_attempts_attempted_at", "identity_login_attempts", ["attempted_at"]
    )
    op.create_table(
        "identity_security_settings",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("session_minutes", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "identity_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=True),
        sa.Column("actor_kind", sa.String(length=32), nullable=False),
        sa.Column("actor_username", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=200), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=True),
        sa.Column("delegated_by", sa.String(length=36), nullable=True),
        sa.Column("authorization_ref", sa.String(length=120), nullable=True),
    )
    op.create_index("ix_identity_audit_events_created_at", "identity_audit_events", ["created_at"])

    now = _timestamp()
    roles_table = sa.table(
        "identity_roles",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("built_in", sa.Boolean),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        roles_table,
        [
            {"id": role_id, "name": name, "built_in": True, "created_at": now}
            for role_id, name in BUILT_IN_ROLES
        ],
    )

    policies_table = sa.table(
        "identity_role_policies",
        sa.column("role_id", sa.String),
        sa.column("resource", sa.String),
        sa.column("operation", sa.String),
    )
    rows: list[dict[str, str]] = []
    for role_id, codes in _role_permissions().items():
        for code in codes:
            resource, _, operation = code.partition(".")
            rows.append({"role_id": role_id, "resource": resource, "operation": operation})
    op.bulk_insert(policies_table, rows)

    settings_table = sa.table(
        "identity_security_settings",
        sa.column("id", sa.Integer),
        sa.column("session_minutes", sa.Integer),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        settings_table,
        [{"id": 1, "session_minutes": DEFAULT_SESSION_MINUTES, "updated_at": now}],
    )


def downgrade() -> None:
    op.drop_index("ix_identity_audit_events_created_at", table_name="identity_audit_events")
    op.drop_table("identity_audit_events")
    op.drop_table("identity_security_settings")
    op.drop_index("ix_identity_login_attempts_attempted_at", table_name="identity_login_attempts")
    op.drop_index("ix_identity_login_attempts_username_key", table_name="identity_login_attempts")
    op.drop_table("identity_login_attempts")
    op.drop_index("ix_identity_credentials_identity_id", table_name="identity_credentials")
    op.drop_table("identity_credentials")
    op.drop_index("ix_identity_sessions_identity_id", table_name="identity_sessions")
    op.drop_table("identity_sessions")
    op.drop_index("ix_identity_identities_role_id", table_name="identity_identities")
    op.drop_table("identity_identities")
    op.drop_index("ix_identity_role_policies_role_id", table_name="identity_role_policies")
    op.drop_table("identity_role_policies")
    op.drop_table("identity_roles")
