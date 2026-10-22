"""Redundancy groups and their member replicas.

Revision ID: 0010_redundancy
Revises: 0009_asset_directory

Additive and reversible: two new tables, no new column on an existing table, no
backfill, no seeded group and no deletion. ``redundancy_group_members`` carries
real ``RESTRICT`` foreign keys to both ``redundancy_groups`` and ``assets`` so a
permanent asset purge can never leave a dangling membership row; the canonical
service still performs the permission and state checks before any write.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_redundancy"
down_revision = "0009_asset_directory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "redundancy_groups",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_redundancy_groups_active", "redundancy_groups", ["active"])
    op.create_table(
        "redundancy_group_members",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "group_id",
            sa.String(length=36),
            sa.ForeignKey("redundancy_groups.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=16), nullable=True),
        sa.Column("share", sa.String(length=8), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("group_id", "asset_id", name="uq_redundancy_group_member"),
    )
    op.create_index("ix_redundancy_group_members_asset", "redundancy_group_members", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_redundancy_group_members_asset", table_name="redundancy_group_members")
    op.drop_table("redundancy_group_members")
    op.drop_index("ix_redundancy_groups_active", table_name="redundancy_groups")
    op.drop_table("redundancy_groups")
