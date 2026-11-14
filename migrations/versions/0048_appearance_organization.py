"""appearance_organization: one installable organization name for the shell

Revision ID: 0048_appearance_organization
Revises: 0047_agent_provider_link
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048_appearance_organization"
down_revision = "0047_agent_provider_link"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "appearance_state",
        sa.Column("organization_name", sa.String(length=120), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("appearance_state", "organization_name")
