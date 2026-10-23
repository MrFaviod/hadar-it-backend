"""notifications

Revision ID: 0017_notifications
Revises: 0016_monitoring
Create Date: 2026-10-23

Durable notification channels, rules, stable alert events, SQL outbox, owned
inbox and the single maintenance-lock row. No credential is stored here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0017_notifications"
down_revision = "0016_monitoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_runtime_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("secret_ref", sa.String(length=64), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "notification_rules",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("minimum_severity", sa.String(length=16), nullable=False),
        sa.Column("recipient_ids", sa.JSON(), nullable=False),
        sa.Column("channel_ids", sa.JSON(), nullable=False),
        sa.Column("escalation_recipient_ids", sa.JSON(), nullable=False),
        sa.Column("schedule_timezone", sa.String(length=64), nullable=True),
        sa.Column("schedule_start", sa.String(length=5), nullable=True),
        sa.Column("schedule_end", sa.String(length=5), nullable=True),
        sa.Column("acknowledge_after_seconds", sa.Integer(), nullable=False),
        sa.Column("retry_interval_seconds", sa.Integer(), nullable=False),
        sa.Column("escalate_after_seconds", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("built_in", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "notification_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("event_key", sa.String(length=200), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("recovered", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_id", "event_key", name="uq_notification_events_alert_event"),
    )
    op.create_index("ix_notification_events_alert_id", "notification_events", ["alert_id"])
    op.create_index("ix_notification_events_asset_id", "notification_events", ["asset_id"])
    op.create_index("ix_notification_events_occurred_at", "notification_events", ["occurred_at"])
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column(
            "event_id",
            sa.String(length=36),
            sa.ForeignKey("notification_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=True),
        sa.Column("recipient_id", sa.String(length=36), nullable=True),
        sa.Column("channel_id", sa.String(length=36), nullable=False),
        sa.Column("escalation_bucket", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("retry_interval_seconds", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_token", sa.String(length=36), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("dedupe_key", name="uq_notification_outbox_dedupe"),
    )
    op.create_index("ix_notification_outbox_event_id", "notification_outbox", ["event_id"])
    op.create_index("ix_notification_outbox_rule_id", "notification_outbox", ["rule_id"])
    op.create_index("ix_notification_outbox_recipient_id", "notification_outbox", ["recipient_id"])
    op.create_index("ix_notification_outbox_channel_id", "notification_outbox", ["channel_id"])
    op.create_index("ix_notification_outbox_alert", "notification_outbox", ["alert_id"])
    op.create_index(
        "ix_notification_outbox_due",
        "notification_outbox",
        ["status", "next_attempt_at"],
    )
    op.create_table(
        "notification_inbox",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "outbox_id",
            sa.String(length=36),
            sa.ForeignKey("notification_outbox.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("recipient_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("event_key", sa.String(length=200), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("outbox_id", name="uq_notification_inbox_outbox"),
    )
    op.create_index(
        "ix_notification_inbox_recipient_created",
        "notification_inbox",
        ["recipient_id", "created_at"],
    )

    now = datetime.now(UTC)
    channels = sa.table(
        "notification_channels",
        sa.column("id", sa.String()),
        sa.column("kind", sa.String()),
        sa.column("name", sa.String()),
        sa.column("enabled", sa.Boolean()),
        sa.column("secret_ref", sa.String()),
        sa.column("config", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        channels,
        [
            {
                "id": "internal-default",
                "kind": "internal",
                "name": "Notificaciones internas",
                "enabled": True,
                "secret_ref": None,
                "config": {},
                "created_at": now,
                "updated_at": now,
            }
        ],
    )
    rules = sa.table(
        "notification_rules",
        sa.column("id", sa.String()),
        sa.column("name", sa.String()),
        sa.column("enabled", sa.Boolean()),
        sa.column("minimum_severity", sa.String()),
        sa.column("recipient_ids", sa.JSON()),
        sa.column("channel_ids", sa.JSON()),
        sa.column("escalation_recipient_ids", sa.JSON()),
        sa.column("schedule_timezone", sa.String()),
        sa.column("schedule_start", sa.String()),
        sa.column("schedule_end", sa.String()),
        sa.column("acknowledge_after_seconds", sa.Integer()),
        sa.column("retry_interval_seconds", sa.Integer()),
        sa.column("escalate_after_seconds", sa.Integer()),
        sa.column("max_attempts", sa.Integer()),
        sa.column("built_in", sa.Boolean()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        rules,
        [
            {
                "id": "default-operations",
                "name": "Operaciones",
                "enabled": True,
                "minimum_severity": "info",
                "recipient_ids": [],
                "channel_ids": ["internal-default"],
                "escalation_recipient_ids": [],
                "schedule_timezone": None,
                "schedule_start": None,
                "schedule_end": None,
                "acknowledge_after_seconds": 900,
                "retry_interval_seconds": 60,
                "escalate_after_seconds": 0,
                "max_attempts": 3,
                "built_in": True,
                "created_at": now,
                "updated_at": now,
            }
        ],
    )
    state = sa.table(
        "notification_runtime_state",
        sa.column("id", sa.Integer()),
        sa.column("last_run_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(state, [{"id": 1, "last_run_at": None, "updated_at": now}])


def downgrade() -> None:
    op.drop_table("notification_inbox")
    op.drop_table("notification_outbox")
    op.drop_table("notification_events")
    op.drop_table("notification_rules")
    op.drop_table("notification_channels")
    op.drop_table("notification_runtime_state")
