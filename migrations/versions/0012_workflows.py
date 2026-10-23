"""Durable import/bulk previews, receipts, profiles and warranties."""

import sqlalchemy as sa
from alembic import op

revision = "0012_workflows"
down_revision = "0011_attachments"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "inventory_operations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("owner_id", sa.String(36), nullable=False),
        sa.Column("approver_id", sa.String(36)),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("job_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "inventory_operation_rows",
        sa.Column(
            "operation_id",
            sa.String(36),
            sa.ForeignKey("inventory_operations.id"),
            primary_key=True,
        ),
        sa.Column("index", sa.Integer(), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_table(
        "inventory_import_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
    )
    op.create_table(
        "inventory_warranties",
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_table(
        "inventory_warranty_preferences",
        sa.Column("key", sa.String(20), primary_key=True),
        sa.Column("days", sa.Integer(), nullable=False),
    )


def downgrade():
    for table in (
        "inventory_warranty_preferences",
        "inventory_warranties",
        "inventory_import_profiles",
        "inventory_operation_rows",
        "inventory_operations",
    ):
        op.drop_table(table)
