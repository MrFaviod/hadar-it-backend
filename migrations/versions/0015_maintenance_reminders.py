"""Durable due-date reminder preparation, without notification delivery."""

import sqlalchemy as sa
from alembic import op

revision = "0015_maintenance_reminders"
down_revision = "0014_interventions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "maintenance_reminders",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("due_on", sa.Date(), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("prepared_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("plan_id", "due_on", "stage", name="uq_maintenance_reminder_due_stage"),
    )
    op.create_index("ix_maintenance_reminders_plan_id", "maintenance_reminders", ["plan_id"])
    op.create_index("ix_maintenance_reminders_asset_id", "maintenance_reminders", ["asset_id"])


def downgrade():
    op.drop_table("maintenance_reminders")
