"""Portable SQLAlchemy models for the inventory core.

Plain SQLAlchemy types only, so the same schema works on SQLite, PostgreSQL and
MariaDB/MySQL. The asset id is a permanent UUID; ``quick_code_key`` is the
case-normalized uniqueness key of the independent, editable quick code.

* ``cost`` is stored as a canonical decimal string so no engine converts money
  through a binary float.
* ``technical`` is a bounded JSON object until the catalog seam defines typed
  technical fields.
* History and tombstone rows are deliberately not linked by a foreign key: they
  must outlive a permanent purge so an asset id is never reused.
* Media rows keep small, already validated raster images in portable SQL blobs.
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
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class InventoryBase(DeclarativeBase):
    """Declarative base for inventory tables."""


class Asset(InventoryBase):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    quick_code: Mapped[str] = mapped_column(String(32), nullable=False)
    quick_code_key: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    brand: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(80), nullable=True)
    serial: Mapped[str | None] = mapped_column(String(80), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    site: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    location: Mapped[str | None] = mapped_column(String(120), nullable=True)
    responsible: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="in_use", index=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    cost: Mapped[str | None] = mapped_column(String(16), nullable=True)
    technical: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AssetHistory(InventoryBase):
    """Append-only audit trail of one asset; it survives a permanent purge."""

    __tablename__ = "asset_history"
    __table_args__ = (Index("ix_asset_history_asset_sequence", "asset_id", "sequence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    quick_code_old: Mapped[str | None] = mapped_column(String(32), nullable=True)
    quick_code_new: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status_old: Mapped[str | None] = mapped_column(String(24), nullable=True)
    status_new: Mapped[str | None] = mapped_column(String(24), nullable=True)
    archived_old: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    archived_new: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    changes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="internal")
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, default="asset")
    entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AssetTombstone(InventoryBase):
    """The permanent remainder of a purged asset: its UUID is never reused."""

    __tablename__ = "asset_tombstones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    quick_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    purged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    purged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)


class AssetMedia(InventoryBase):
    """One bounded raster image per asset and role (``photo`` or ``fov``)."""

    __tablename__ = "asset_media"
    __table_args__ = (UniqueConstraint("asset_id", "role", name="uq_asset_media_role"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content_type: Mapped[str] = mapped_column(String(32), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
