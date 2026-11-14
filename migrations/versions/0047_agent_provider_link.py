"""system_provider_settings: link the installation selection to a provider record

Revision ID: 0047_agent_provider_link
Revises: 0046_installation_setup
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0047_agent_provider_link"
down_revision = "0046_installation_setup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "system_provider_settings",
        sa.Column("provider_id", sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("system_provider_settings", "provider_id")
