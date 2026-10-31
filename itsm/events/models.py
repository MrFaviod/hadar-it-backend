"""Core-owned outbox rows and consumer cursors for the entity-change feed.

``sequence`` is the database-assigned ordering key: it is the integer primary key
of the outbox table, so allocation is atomic on PostgreSQL, MariaDB/MySQL and
SQLite without an application-side counter or a lock. The permanent event id is
a UUID that consumers use for idempotent delivery; it is never reused.

Nothing here is an extension table. Both tables are created only by the core
migration chain, and the event payload is deliberately descriptive: field names
plus the entity identifier, never field values.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sqlalchemy import JSON, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class EventBase(DeclarativeBase):
    """Declarative base for the core entity-change feed tables."""


ENTITY_TYPES: Final[tuple[str, ...]] = ("asset", "incident")

EVENT_TYPES: Final[tuple[str, ...]] = (
    "asset.created",
    "asset.updated",
    "asset.archived",
    "asset.restored",
    "asset.deleted",
    "incident.created",
    "incident.updated",
)

CONSUMER_STATES: Final[tuple[str, ...]] = ("active", "stalled")

# Closed failure vocabulary: a consumer reports why delivery failed, never a
# traceback, a payload or a storage detail. Anything else is rejected.
FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {
        "authorization_denied",
        "handler_error",
        "idempotency_conflict",
        "invalid_payload",
        "storage_unavailable",
        "timeout",
    }
)

MAX_CHANGED_FIELDS: Final[int] = 64
MAX_FIELD_NAME: Final[int] = 64


class EntityChangeEvent(EventBase):
    """One committed core change, written in the transaction that caused it."""

    __tablename__ = "entity_change_events"
    __table_args__ = (
        UniqueConstraint("id", name="uq_entity_change_events_id"),
        Index("ix_entity_change_events_entity", "entity_type", "entity_id"),
        Index("ix_entity_change_events_occurred_at", "occurred_at"),
        # Never reuse a pruned sequence slot on SQLite: a replayed number would
        # look like an already-delivered event to a consumer cursor.
        {"sqlite_autoincrement": True},
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    changed_fields: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class EntityEventConsumer(EventBase):
    """Per-consumer cursor, retry budget and visible stall state."""

    __tablename__ = "entity_event_consumers"

    consumer_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    retry_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


__all__ = [
    "CONSUMER_STATES",
    "ENTITY_TYPES",
    "EVENT_TYPES",
    "FAILURE_CODES",
    "MAX_CHANGED_FIELDS",
    "MAX_FIELD_NAME",
    "EntityChangeEvent",
    "EntityEventConsumer",
    "EventBase",
]
