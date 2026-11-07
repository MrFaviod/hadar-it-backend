"""Queryable preventive maintenance templates and asset plans."""

import sqlalchemy as sa
from alembic import op

revision = "0013_maintenance"
down_revision = "0012_workflows"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "maintenance_templates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("maintenance_type", sa.String(32), nullable=False),
        sa.Column("interval_months", sa.Integer(), nullable=False),
        sa.Column("tasks", sa.JSON(), nullable=False),
        sa.Column("responsible_person_id", sa.String(36)),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_maintenance_templates_category", "maintenance_templates", ["category"])
    op.create_index(
        "ix_maintenance_templates_responsible_person_id",
        "maintenance_templates",
        ["responsible_person_id"],
    )
    op.create_table(
        "maintenance_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("maintenance_type", sa.String(32), nullable=False),
        sa.Column("interval_months", sa.Integer(), nullable=False),
        sa.Column("tasks", sa.JSON(), nullable=False),
        sa.Column("responsible_person_id", sa.String(36)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("scheduled_on", sa.Date(), nullable=False),
        sa.Column("last_completed_on", sa.Date()),
        sa.Column("due_on", sa.Date(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("asset_id", "maintenance_type", name="uq_maintenance_plan_asset_type"),
    )
    op.create_index("ix_maintenance_plans_asset", "maintenance_plans", ["asset_id"])
    op.create_index("ix_maintenance_plans_due", "maintenance_plans", ["due_on"])
    op.create_index("ix_maintenance_plans_status", "maintenance_plans", ["status"])
    op.create_index("ix_maintenance_plans_type", "maintenance_plans", ["maintenance_type"])
    op.create_index(
        "ix_maintenance_plans_responsible_person_id",
        "maintenance_plans",
        ["responsible_person_id"],
    )


def downgrade():
    for index in (
        "ix_maintenance_plans_responsible_person_id",
        "ix_maintenance_plans_type",
        "ix_maintenance_plans_status",
        "ix_maintenance_plans_due",
        "ix_maintenance_plans_asset",
    ):
        op.drop_index(index, table_name="maintenance_plans")
    op.drop_table("maintenance_plans")
    op.drop_index(
        "ix_maintenance_templates_responsible_person_id",
        table_name="maintenance_templates",
    )
    op.drop_index("ix_maintenance_templates_category", table_name="maintenance_templates")
    op.drop_table("maintenance_templates")
