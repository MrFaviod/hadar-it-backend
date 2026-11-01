"""Store the stable message key and its parameters on notification events.

Notification text is localized per recipient at fan-out, so the event keeps the
language-neutral message instead of only the text one recipient happened to
need. ``notification_events.message`` is nullable and additive: rows written
before this revision keep their stored title and body and are delivered verbatim.

Revision ID: 0040_notification_i18n
Revises: 0038_i18n_preferences
"""

import sqlalchemy as sa
from alembic import op

revision = "0040_notification_i18n"
down_revision = "0039_i18n_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("notification_events") as batch:
        batch.add_column(sa.Column("message", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("notification_events") as batch:
        batch.drop_column("message")
