"""Persist application-owned deployment preferences and provider selection.

Revision ID: 0022_system_operations
Revises: 0021_system_profiles
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_system_operations"
down_revision = "0021_system_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_preferences",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "classification",
            sa.String(length=20),
            nullable=False,
            server_default="development",
        ),
        sa.Column(
            "maintenance_window",
            sa.String(length=32),
            nullable=False,
            server_default="anytime",
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=36), nullable=True),
    )
    op.create_table(
        "system_provider_settings",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("system_provider_settings")
    op.drop_table("system_preferences")
