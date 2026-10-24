"""Portable workspace tables: preferences, personal/shared links, views and remote settings.

Plain SQLAlchemy types only. Owner columns are opaque identity ids: workspace
records never grant authorization and are always filtered by the canonical
identity service before they are returned.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class WorkspaceUserState(InventoryBase):
    """One row per user; a missing row means the built-in widget defaults."""

    __tablename__ = "workspace_user_state"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    widgets: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    favorites: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    usage: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)
    last_views: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    theme_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="auto")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class WorkspaceShortcut(InventoryBase):
    """External link owned by one actor; shared rows are installation-wide."""

    __tablename__ = "workspace_shortcuts"
    __table_args__ = (Index("ix_workspace_shortcuts_owner_scope", "owner_id", "scope"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    icon: Mapped[str | None] = mapped_column(String(64), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default="personal", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class WorkspaceView(InventoryBase):
    """A saved filter/layout snapshot, personal or published to the installation."""

    __tablename__ = "workspace_views"
    __table_args__ = (Index("ix_workspace_views_owner_scope", "owner_id", "scope"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    route: Mapped[str] = mapped_column(String(128), nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default="personal", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class WorkspaceIntegration(InventoryBase):
    """Installation-wide remote support destinations; one singleton row."""

    __tablename__ = "workspace_integrations"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    anydesk_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    rmm_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    anydesk_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rmm_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
