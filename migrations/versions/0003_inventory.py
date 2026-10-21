"""inventory assets

Revision ID: 0003_inventory
Revises: 0002_identity
Create Date: 2026-11-03

First bounded inventory slice: one asset table with a permanent UUID id and a
case-normalized unique quick code. No seed rows and no delete path; custom
fields and advanced relations stay out of this revision.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_inventory"
down_revision = "0002_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("quick_code", sa.String(length=32), nullable=False),
        sa.Column("quick_code_key", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("type", sa.String(length=64), nullable=True),
        sa.Column("brand", sa.String(length=64), nullable=True),
        sa.Column("model", sa.String(length=80), nullable=True),
        sa.Column("serial", sa.String(length=80), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("site", sa.String(length=120), nullable=True),
        sa.Column("location", sa.String(length=120), nullable=True),
        sa.Column("responsible", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("quick_code_key", name="uq_assets_quick_code_key"),
    )
    op.create_index("ix_assets_quick_code_key", "assets", ["quick_code_key"], unique=True)
    op.create_index("ix_assets_category", "assets", ["category"])
    op.create_index("ix_assets_site", "assets", ["site"])
    op.create_index("ix_assets_status", "assets", ["status"])
    op.create_index("ix_assets_updated_at", "assets", ["updated_at"])


def downgrade() -> None:
    op.drop_index("ix_assets_updated_at", table_name="assets")
    op.drop_index("ix_assets_status", table_name="assets")
    op.drop_index("ix_assets_site", table_name="assets")
    op.drop_index("ix_assets_category", table_name="assets")
    op.drop_index("ix_assets_quick_code_key", table_name="assets")
    op.drop_table("assets")
