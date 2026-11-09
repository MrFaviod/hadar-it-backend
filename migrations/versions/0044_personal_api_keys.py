"""Creator-bound personal API keys with immutable ceilings and optional expiry.

Revision ID: 0044_personal_api_keys
Revises: 0043_conversation_locale
"""

import sqlalchemy as sa
from alembic import op

revision = "0044_personal_api_keys"
down_revision = "0043_conversation_locale"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identity_api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "identity_id",
            sa.String(36),
            sa.ForeignKey("identity_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(64), nullable=False),
        sa.Column("permissions_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_identity_api_keys_identity_id", "identity_api_keys", ["identity_id"])


def downgrade() -> None:
    op.drop_index("ix_identity_api_keys_identity_id", table_name="identity_api_keys")
    op.drop_table("identity_api_keys")
