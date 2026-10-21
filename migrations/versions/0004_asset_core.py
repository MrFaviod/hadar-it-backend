"""asset core: common fields, lifecycle, history, tombstones and media

Revision ID: 0004_asset_core
Revises: 0003_inventory
Create Date: 2026-11-04

Adds the asset core approved for phase 4 T2: cost and bounded technical values,
an archive flag independent of status, an append-only history that survives a
permanent purge, UUID tombstones that keep a purged id reserved, and portable
SQL blob storage for the two bounded raster image roles.

The distinct ``assets.purge`` privilege is seeded for the built-in
administrator role only; the service additionally refuses a permanent purge for
any machine actor and requires the archived state, the exact typed UUID and a
reason in production. No asset rows are created or modified by this revision.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_asset_core"
down_revision = "0003_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("cost", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("technical", sa.JSON(), nullable=True))
    op.add_column("assets", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("archived_by", sa.String(length=64), nullable=True))

    op.create_table(
        "asset_history",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("quick_code_old", sa.String(length=32), nullable=True),
        sa.Column("quick_code_new", sa.String(length=32), nullable=True),
        sa.Column("status_old", sa.String(length=24), nullable=True),
        sa.Column("status_new", sa.String(length=24), nullable=True),
        sa.Column("archived_old", sa.Boolean(), nullable=True),
        sa.Column("archived_new", sa.Boolean(), nullable=True),
        sa.Column("changes", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("actor_id", sa.String(length=36), nullable=True),
        sa.Column("actor_username", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_asset_history_asset_sequence", "asset_history", ["asset_id", "sequence"])

    op.create_table(
        "asset_tombstones",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("quick_code", sa.String(length=32), nullable=True),
        sa.Column("purged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("purged_by", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
    )

    op.create_table(
        "asset_media",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content_type", sa.String(length=32), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("asset_id", "role", name="uq_asset_media_role"),
    )

    policies = sa.table(
        "identity_role_policies",
        sa.column("role_id", sa.String),
        sa.column("resource", sa.String),
        sa.column("operation", sa.String),
    )
    op.bulk_insert(
        policies,
        [{"role_id": "admin", "resource": "assets", "operation": "purge"}],
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DELETE FROM identity_role_policies "
            "WHERE role_id = 'admin' AND resource = 'assets' AND operation = 'purge'"
        )
    )
    op.drop_table("asset_media")
    op.drop_table("asset_tombstones")
    op.drop_index("ix_asset_history_asset_sequence", table_name="asset_history")
    op.drop_table("asset_history")
    op.drop_column("assets", "archived_by")
    op.drop_column("assets", "archived_at")
    op.drop_column("assets", "technical")
    op.drop_column("assets", "cost")
