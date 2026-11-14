"""Durable installation appearance: presets, opaque resources and active state.

The active identity is a snapshot, never a pointer: editing or deleting a
catalog preset cannot silently change what anonymous clients already render.
Graphic bytes live in the configured opaque blob storage; SQL keeps only the
resource metadata and content hash.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class AppearancePreset(InventoryBase):
    """One saved appearance preset. Built-ins are code constants, not rows."""

    __tablename__ = "appearance_presets"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    staged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AppearanceResource(InventoryBase):
    """A validated logo/favicon kept in ``BlobStorage`` under ``blob_key``."""

    __tablename__ = "appearance_resources"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    blob_key: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AppearanceState(InventoryBase):
    """Installation-global active snapshot plus the single previous snapshot."""

    __tablename__ = "appearance_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    active_id: Mapped[str] = mapped_column(String(80), nullable=False)
    previous_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    active: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    organization_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_by: Mapped[str] = mapped_column(String(160), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
