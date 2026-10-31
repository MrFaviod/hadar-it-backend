"""Core-owned transactional outbox for entity changes and consumer cursors.

Both tables belong to the core database and are created only by this migration;
an extension never adds or alters them (see ``docs/entity-events.md``).

``sequence`` is the integer primary key so the database allocates the ordering
key atomically on every supported engine. On SQLite the table is declared
``AUTOINCREMENT`` so a pruned sequence slot is never handed out again: a reused
number would look already delivered to a consumer cursor.

Revision ID: 0035_entity_change_events
Revises: 0034_chat_attachments
"""

import sqlalchemy as sa
from alembic import op

revision = "0035_entity_change_events"
down_revision = "0034_chat_attachments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_change_events",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("entity_type", sa.String(length=16), nullable=False),
        sa.Column("entity_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=True),
        sa.Column("changed_fields", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", name="uq_entity_change_events_id"),
        sqlite_autoincrement=True,
    )
    op.create_index(
        "ix_entity_change_events_entity",
        "entity_change_events",
        ["entity_type", "entity_id"],
    )
    op.create_index(
        "ix_entity_change_events_occurred_at",
        "entity_change_events",
        ["occurred_at"],
    )
    op.create_table(
        "entity_event_consumers",
        sa.Column("consumer_id", sa.String(length=96), primary_key=True),
        sa.Column("last_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(length=64), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("retry_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("entity_event_consumers")
    op.drop_index("ix_entity_change_events_occurred_at", table_name="entity_change_events")
    op.drop_index("ix_entity_change_events_entity", table_name="entity_change_events")
    op.drop_table("entity_change_events")
