"""Persist explicit managed routing and direct company exceptions.

Revision ID: 0026_ai_instance_quotas
Revises: 0025_ai_gateway
"""

import sqlalchemy as sa
from alembic import op

revision = "0026_ai_instance_quotas"
down_revision = "0025_ai_gateway"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_instances",
        sa.Column("quota_mode", sa.String(16), nullable=False, server_default="direct"),
    )
    op.add_column(
        "agent_instances",
        sa.Column(
            "direct_company_exception", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column("agent_instances", sa.Column("managed_provider_id", sa.String(36)))
    op.add_column("agent_instances", sa.Column("managed_context_tokens", sa.Integer()))


def downgrade() -> None:
    op.drop_column("agent_instances", "managed_context_tokens")
    op.drop_column("agent_instances", "managed_provider_id")
    op.drop_column("agent_instances", "direct_company_exception")
    op.drop_column("agent_instances", "quota_mode")
