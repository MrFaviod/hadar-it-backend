"""Persist automatic model discovery on OpenAI-compatible provider records.

Every provider discovers its models through the guarded transport, so the record
keeps the discovered ids, the provider/owner capability marks, the closed
discovery status and the last check time next to the offered ``models`` list.

``model_selection`` decides which list is offered: ``auto`` follows discovery,
``manual`` keeps the owner's list. Rows written before this revision are moved to
``manual`` so an existing provider keeps offering exactly the models its owner
configured by hand; new rows default to ``auto``.

Revision ID: 0033_provider_model_discovery
Revises: 0032_managed_personal_provider
"""

import sqlalchemy as sa
from alembic import op

revision = "0033_provider_model_discovery"
down_revision = "0032_managed_personal_provider"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_providers",
        sa.Column("model_selection", sa.String(length=16), nullable=False, server_default="auto"),
    )
    op.add_column("agent_providers", sa.Column("discovered_models", sa.JSON(), nullable=True))
    op.add_column("agent_providers", sa.Column("model_capabilities", sa.JSON(), nullable=True))
    op.add_column(
        "agent_providers", sa.Column("discovery_status", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "agent_providers",
        sa.Column("discovery_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Only the rows that existed before this revision: they predate discovery.
    op.execute("UPDATE agent_providers SET model_selection = 'manual'")


def downgrade() -> None:
    op.drop_column("agent_providers", "discovery_checked_at")
    op.drop_column("agent_providers", "discovery_status")
    op.drop_column("agent_providers", "model_capabilities")
    op.drop_column("agent_providers", "discovered_models")
    op.drop_column("agent_providers", "model_selection")
