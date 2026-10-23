"""Add attachment metadata without moving existing image bytes.

Revision ID: 0011_attachments
Revises: 0010_redundancy
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_attachments"
down_revision = "0010_redundancy"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "asset_attachments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("blob_key", sa.String(32), nullable=False, unique=True),
        sa.Column("filename", sa.String(180), nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("content_type", sa.String(120), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(160), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_asset_attachments_asset_id", "asset_attachments", ["asset_id"])


def downgrade():
    op.drop_index("ix_asset_attachments_asset_id", table_name="asset_attachments")
    op.drop_table("asset_attachments")
