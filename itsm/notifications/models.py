"""Durable notification state: channels, rules, events, outbox and inbox.

The database is the only queue. Nothing here stores a metric sample, a
credential, or a token-bearing URL: external channels point at a deployment
secret reference and their non-secret configuration is a small allowlist.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase

NotificationBase = InventoryBase


class NotificationChannel(NotificationBase):
    """One delivery channel; secrets live outside the database."""

    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    secret_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class NotificationRule(NotificationBase):
    """When and to whom one class of alert is delivered."""

    __tablename__ = "notification_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    minimum_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    recipient_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    channel_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    escalation_recipient_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    schedule_timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    schedule_start: Mapped[str | None] = mapped_column(String(5), nullable=True)
    schedule_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    acknowledge_after_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    retry_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    escalate_after_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    built_in: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class NotificationEvent(NotificationBase):
    """One stable alert event; repeated delivery never duplicates this row."""

    __tablename__ = "notification_events"
    __table_args__ = (
        UniqueConstraint("alert_id", "event_key", name="uq_notification_events_alert_event"),
        Index("ix_notification_events_occurred_at", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_key: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recovered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class NotificationOutbox(NotificationBase):
    """Durable delivery work; the unique key is the anti-duplicate invariant."""

    __tablename__ = "notification_outbox"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_notification_outbox_dedupe"),
        Index("ix_notification_outbox_due", "status", "next_attempt_at"),
        Index("ix_notification_outbox_alert", "alert_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("notification_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    recipient_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    channel_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    escalation_bucket: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    retry_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class NotificationInbox(NotificationBase):
    """One internal notification owned by exactly one recipient."""

    __tablename__ = "notification_inbox"
    __table_args__ = (
        UniqueConstraint("outbox_id", name="uq_notification_inbox_outbox"),
        Index("ix_notification_inbox_recipient_created", "recipient_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    outbox_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("notification_outbox.id", ondelete="CASCADE"),
        nullable=False,
    )
    recipient_id: Mapped[str] = mapped_column(String(36), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_key: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Native extension notices remain owned inbox rows, with live permission
    # filtering after a recipient's module grant is revoked.
    extension_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    required_permission: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationRuntimeState(NotificationBase):
    """Single row used as the serialized lock for notification maintenance."""

    __tablename__ = "notification_runtime_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
