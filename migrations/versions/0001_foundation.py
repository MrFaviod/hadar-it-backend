"""infrastructure foundation table

Revision ID: 0001_foundation
Revises:
Create Date: 2026-10-23

Infrastructure-only schema: no inventory or other business tables yet.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "itsm_infrastructure",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("name", name="uq_itsm_infrastructure_name"),
    )


def downgrade() -> None:
    op.drop_table("itsm_infrastructure")
