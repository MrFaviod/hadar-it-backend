"""Durable search-sync state.

The search index is a disposable projection of the canonical SQL data.  Two
small tables make the projection reliable without touching any domain module:

* :class:`SearchSyncOutbox` receives one row per canonical entity change.  The
  row is written by a session ``before_flush`` hook, so it commits or rolls
  back in the very same transaction as the entity it describes.
* :class:`SearchIndexState` is the single-row health record exposed by
  ``GET /search/status`` and by the background rebuild.

Both tables use portable SQLAlchemy types only and deliberately carry no
foreign keys: a purged asset must not be kept alive by a pending outbox row.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class SearchBase(DeclarativeBase):
    """Declarative base for the search projection tables."""


def _identifier() -> str:
    return str(uuid4())


STATUS_PENDING = "pending"
STATUS_FAILED = "failed"

OPERATION_UPSERT = "upsert"
OPERATION_DELETE = "delete"


class SearchSyncOutbox(SearchBase):
    """One pending Meilisearch reconciliation for one canonical entity.

    Rows are append-only until a sync run drains them.  A later event for the
    same entity simply queues another row; the worker coalesces rows per
    entity and always rehydrates the current SQL state, which keeps the
    pipeline idempotent and avoids cross-session primary-key races.
    """

    __tablename__ = "search_sync_outbox"
    __table_args__ = (
        Index("ix_search_sync_outbox_due", "status", "available_at"),
        Index(
            "ix_search_sync_outbox_entity",
            "entity_type",
            "entity_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_identifier)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(
        String(8), nullable=False, default=OPERATION_UPSERT
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_PENDING)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class SearchIndexState(SearchBase):
    """Single-row operational state of the external index."""

    __tablename__ = "search_index_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="idle")
    last_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_rebuild_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    document_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


__all__ = [
    "OPERATION_DELETE",
    "OPERATION_UPSERT",
    "STATUS_FAILED",
    "STATUS_PENDING",
    "SearchBase",
    "SearchIndexState",
    "SearchSyncOutbox",
]
