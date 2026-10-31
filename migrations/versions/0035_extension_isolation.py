"""Add the core-owned replay ledger for extension core mutations.

Per-module business data moved out of the core database into SQLite files owned
by the module runtime.  The only table added here is host metadata: the
idempotency ledger that lets an authored capability mutation replay safely
without giving an extension SQL access to ITSM tables.

Revision ID: 0035_extension_isolation
Revises: 0034_chat_attachments
"""

import sqlalchemy as sa
from alembic import op

revision = "0035_extension_isolation"
down_revision = "0034_chat_attachments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "extension_core_calls",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(length=48), nullable=False),
        sa.Column("call_key", sa.String(length=128), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("extension_id", "call_key", name="uq_extension_core_call"),
    )
    op.create_index("ix_extension_core_calls_extension", "extension_core_calls", ["extension_id"])


def downgrade() -> None:
    op.drop_index("ix_extension_core_calls_extension", table_name="extension_core_calls")
    op.drop_table("extension_core_calls")
