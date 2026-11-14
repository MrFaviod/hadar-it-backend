"""installation_backup_policy: the declared production backup policy

Revision ID: 0048_setup_backup_policy
Revises: 0046_installation_setup
Create Date: 2026-11-13

The declaration is installation metadata, not a domain setting: it records what
the operator says protects this installation and who declared it. The runtime
backup status keeps its own owner (``SystemService.backup_status``).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048_setup_backup_policy"
down_revision = "0046_installation_setup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "installation_backup_policy",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("target", sa.String(length=200), nullable=False),
        sa.Column("location_kind", sa.String(length=32), nullable=False),
        sa.Column("schedule", sa.String(length=120), nullable=False),
        sa.Column("retention", sa.String(length=120), nullable=False),
        sa.Column("responsible", sa.String(length=120), nullable=False),
        sa.Column("declared_by", sa.String(length=64), nullable=True),
        sa.Column("declared_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_installation_backup_policy_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("installation_backup_policy")
