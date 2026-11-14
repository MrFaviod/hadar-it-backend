"""Persisted installation preferences and the active provider selection.

Both tables hold a single application-owned row. Nothing here stores external
credentials: provider secrets stay in the operator environment.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class SystemPreference(InventoryBase):
    __tablename__ = "system_preferences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    classification: Mapped[str] = mapped_column(String(20), nullable=False, default="development")
    maintenance_window: Mapped[str] = mapped_column(String(32), nullable=False, default="anytime")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    updated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class SystemProviderSettings(InventoryBase):
    __tablename__ = "system_provider_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    provider_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
