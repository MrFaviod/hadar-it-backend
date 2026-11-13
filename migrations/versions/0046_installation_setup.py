"""installation_setup: the completion marker lives in the application database

Revision ID: 0046_installation_setup
Revises: 0045_machine_expiry
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0046_installation_setup"
down_revision = "0045_machine_expiry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "installation_setup",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_by", sa.String(length=36), nullable=True),
        sa.Column("instance_id", sa.String(length=64), nullable=True),
        sa.Column("setup_contract_version", sa.String(length=16), nullable=False),
        sa.Column("report_digest", sa.String(length=64), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_installation_setup_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("installation_setup")
