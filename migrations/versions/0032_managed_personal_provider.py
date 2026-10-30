"""Let a session remember the managed provider it spends through.

A session keeps using the instance's managed global provider unless its owner
selects one of the providers visible to them, so the column is nullable and no
existing row changes meaning.

Revision ID: 0032_managed_personal_provider
Revises: 0031_personal_provider_grants
"""

import sqlalchemy as sa
from alembic import op

revision = "0032_managed_personal_provider"
down_revision = "0031_personal_provider_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_sessions", sa.Column("provider_id", sa.String(length=36), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_sessions", "provider_id")
