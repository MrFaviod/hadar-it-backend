"""Portable metadata rows; stable keys survive labels and form changes."""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from itsm.inventory.models import InventoryBase


class InventoryCatalogEntry(InventoryBase):
    __tablename__ = "inventory_catalog"

    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
