"""Grant the personal-provider right to the built-in Admin and User profiles.

Revision ID: 0031_personal_provider_grants
Revises: 0030_demo_cycle

Personal-funded providers are a personal right, not business administration, so
every built-in human profile that can use the assistant may register its own key.
Nothing else is widened: the operator profile and custom roles keep their grants.
"""

import sqlalchemy as sa
from alembic import op

revision = "0031_personal_provider_grants"
down_revision = "0030_demo_cycle"
branch_labels = None
depends_on = None

PERSONAL_PROVIDER_PERMISSION = "agents.providers.personal"
BUILT_IN_ROLE_IDS = ("admin", "user")


def _policy_table() -> sa.TableClause:
    return sa.table(
        "identity_role_policies",
        sa.column("role_id", sa.String),
        sa.column("resource", sa.String),
        sa.column("operation", sa.String),
    )


def upgrade() -> None:
    resource, _, operation = PERSONAL_PROVIDER_PERMISSION.partition(".")
    policies = _policy_table()
    bind = op.get_bind()
    for role_id in BUILT_IN_ROLE_IDS:
        exists = bind.execute(
            sa.select(policies.c.role_id).where(
                policies.c.role_id == role_id,
                policies.c.resource == resource,
                policies.c.operation == operation,
            )
        ).first()
        if exists is None:
            bind.execute(
                policies.insert().values(
                    role_id=role_id,
                    resource=resource,
                    operation=operation,
                )
            )


def downgrade() -> None:
    resource, _, operation = PERSONAL_PROVIDER_PERMISSION.partition(".")
    policies = _policy_table()
    op.get_bind().execute(
        policies.delete().where(
            policies.c.role_id.in_(BUILT_IN_ROLE_IDS),
            policies.c.resource == resource,
            policies.c.operation == operation,
        )
    )
