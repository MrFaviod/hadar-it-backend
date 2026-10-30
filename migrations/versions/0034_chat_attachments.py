"""Store owner-scoped chat attachments and the gateway lease's input contract.

Chat attachments are bounded bytes over the existing independent blob store:
the row keeps the display metadata and the owner that may read it, and refers to
its agent session by id without a cross-module foreign key. The managed gateway
lease additionally records which non-text input kinds that turn may carry and
the encoded byte budget those parts may consume, so admission never has to
trust a caller-declared modality.

Revision ID: 0034_chat_attachments
Revises: 0033_provider_model_discovery
"""

import sqlalchemy as sa
from alembic import op

revision = "0034_chat_attachments"
down_revision = "0033_provider_model_discovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_chat_attachments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("blob_key", sa.String(length=32), nullable=False),
        sa.Column("filename", sa.String(length=180), nullable=False),
        sa.Column("media_type", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("blob_key", name="uq_agent_chat_attachments_blob_key"),
    )
    op.create_index(
        "ix_agent_chat_attachments_session_id", "agent_chat_attachments", ["session_id"]
    )
    op.create_index("ix_agent_chat_attachments_owner_id", "agent_chat_attachments", ["owner_id"])
    # Leases issued before this revision carry no attachment contract: empty.
    op.add_column(
        "ai_gateway_leases",
        sa.Column("input_modalities", sa.String(length=32), nullable=False, server_default=""),
    )
    op.add_column(
        "ai_gateway_leases",
        sa.Column("attachment_bytes", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("ai_gateway_leases", "attachment_bytes")
    op.drop_column("ai_gateway_leases", "input_modalities")
    op.drop_index("ix_agent_chat_attachments_owner_id", table_name="agent_chat_attachments")
    op.drop_index("ix_agent_chat_attachments_session_id", table_name="agent_chat_attachments")
    op.drop_table("agent_chat_attachments")
