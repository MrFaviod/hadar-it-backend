"""Persist the shared demo cycle deadline, never seed business data.

Revision ID: 0030_demo_cycle
Revises: 0029_deployment_identity
"""

import sqlalchemy as sa
from alembic import op

revision = "0030_demo_cycle"
down_revision = "0029_deployment_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "demo_cycle",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("next_reset_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resetting", sa.Boolean(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_demo_cycle_singleton"),
    )


def downgrade() -> None:
    op.drop_table("demo_cycle")
