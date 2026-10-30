"""Durable demo installation marker (empty in ordinary installations).

Revision ID: 0028_demo_installation
Revises: 0027_native_extensions
"""

import sqlalchemy as sa
from alembic import op

revision = "0028_demo_installation"
down_revision = "0027_native_extensions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "demo_installation",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("dataset", sa.String(48), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_demo_installation_singleton"),
    )


def downgrade() -> None:
    op.drop_table("demo_installation")
