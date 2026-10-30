"""Deployment identity: the release mode that owns this database.

Revision ID: 0029_deployment_identity
Revises: 0028_demo_installation

The table is a singleton: ``id = 1`` and a mode restricted to the three release
modes. Startup code claims the row on a new installation and refuses a database
claimed by another mode; no migration ever guesses the mode.
"""

import sqlalchemy as sa
from alembic import op

revision = "0029_deployment_identity"
down_revision = "0028_demo_installation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deployment_identity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("release_mode", sa.String(8), nullable=False),
        sa.Column("instance_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_deployment_identity_singleton"),
        sa.CheckConstraint(
            "release_mode IN ('dev', 'prod', 'demo')",
            name="ck_deployment_identity_mode",
        ),
    )


def downgrade() -> None:
    op.drop_table("deployment_identity")
