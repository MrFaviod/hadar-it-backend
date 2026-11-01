"""Portable SQLAlchemy models for typed directed relationships between assets.

A relationship is one directed edge: ``source_id -> target_id`` under a stable
``type_key``. The pair is unique, so the same endpoints can carry several
different relation types but never an exact duplicate. Containment flags live
on the type, not on the edge, so a configured type change applies uniformly.

Relationship rows use ``RESTRICT`` foreign keys: an asset that still has edges
cannot be permanently purged, and no purge may leave a dangling graph.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class RelationshipType(InventoryBase):
    """Configurable relation type: stable key plus forward/inverse display labels."""

    __tablename__ = "relationship_types"
    __table_args__ = (Index("ix_relationship_types_active", "active"),)

    key: Mapped[str] = mapped_column(String(32), primary_key=True)
    forward_label: Mapped[str] = mapped_column(String(80), nullable=False)
    inverse_label: Mapped[str] = mapped_column(String(80), nullable=False)
    # Additive S4/D9 maps; the strings above stay the source text for ``es``.
    forward_labels: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    inverse_labels: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    containment: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class Relationship(InventoryBase):
    """One directed edge; endpoints are permanent asset UUIDs."""

    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "type_key", name="uq_relationships_edge"),
        Index("ix_relationships_source", "source_id"),
        Index("ix_relationships_target", "target_id"),
        Index("ix_relationships_type", "type_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    type_key: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("relationship_types.key", ondelete="RESTRICT"),
        nullable=False,
    )
    source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
