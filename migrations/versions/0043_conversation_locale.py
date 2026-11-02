"""Persist the locale of one agent conversation (S8).

A conversation created while the person uses Spanish keeps answering in Spanish
even when a later tool result is English. The column is nullable: conversations
created before this revision resolve their language from the owner's preference
and the installation default at read time.

Revision ID: 0043_conversation_locale
Revises: 0042_i18n_custom
"""

import sqlalchemy as sa
from alembic import op

revision = "0043_conversation_locale"
down_revision = "0042_i18n_custom"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agent_sessions") as batch:
        batch.add_column(sa.Column("locale", sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agent_sessions") as batch:
        batch.drop_column("locale")
