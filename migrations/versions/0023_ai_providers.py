"""AI provider records and the explicit personal-provider grant.

Revision ID: 0023_ai_providers
Revises: 0022_system_operations

The table stores only sealed credentials. The Fernet master key is supplied by
the process environment (``ITSM_AI_CREDENTIAL_KEY``) and is never part of this
schema or of the seeded data.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_ai_providers"
down_revision = "0022_system_operations"
branch_labels = None
depends_on = None

PERSONAL_PROVIDER_PERMISSION = "agents.providers.personal"


def _policy_table() -> sa.TableClause:
    return sa.table(
        "identity_role_policies",
        sa.column("role_id", sa.String),
        sa.column("resource", sa.String),
        sa.column("operation", sa.String),
    )


def upgrade() -> None:
    op.create_table(
        "agent_providers",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=True),
        sa.Column("base_url", sa.String(length=500), nullable=False),
        sa.Column("models", sa.JSON(), nullable=False),
        sa.Column("api_key_ciphertext", sa.String(length=4096), nullable=True),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_providers_owner_id", "agent_providers", ["owner_id"])

    resource, _, operation = PERSONAL_PROVIDER_PERMISSION.partition(".")
    policies = _policy_table()
    bind = op.get_bind()
    exists = bind.execute(
        sa.select(policies.c.role_id).where(
            policies.c.role_id == "superadmin",
            policies.c.resource == resource,
            policies.c.operation == operation,
        )
    ).first()
    if exists is None:
        bind.execute(
            policies.insert().values(
                role_id="superadmin",
                resource=resource,
                operation=operation,
            )
        )


def downgrade() -> None:
    resource, _, operation = PERSONAL_PROVIDER_PERMISSION.partition(".")
    policies = _policy_table()
    op.get_bind().execute(
        policies.delete().where(
            policies.c.role_id == "superadmin",
            policies.c.resource == resource,
            policies.c.operation == operation,
        )
    )
    op.drop_index("ix_agent_providers_owner_id", table_name="agent_providers")
    op.drop_table("agent_providers")
