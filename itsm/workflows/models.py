"""Durable fixed operations, row receipts, profiles and individual warranties."""

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from itsm.inventory.models import InventoryBase


class Operation(InventoryBase):
    __tablename__ = "inventory_operations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False)
    approver_id: Mapped[str | None] = mapped_column(String(36))
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    job_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)


class OperationRow(InventoryBase):
    __tablename__ = "inventory_operation_rows"
    operation_id: Mapped[str] = mapped_column(
        ForeignKey("inventory_operations.id"), primary_key=True
    )
    index: Mapped[int] = mapped_column(Integer(), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class ImportProfile(InventoryBase):
    __tablename__ = "inventory_import_profiles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    options: Mapped[dict] = mapped_column(JSON, nullable=False)


class Warranty(InventoryBase):
    __tablename__ = "inventory_warranties"
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), primary_key=True
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class WarrantyPreference(InventoryBase):
    __tablename__ = "inventory_warranty_preferences"
    key: Mapped[str] = mapped_column(String(20), primary_key=True)
    days: Mapped[int] = mapped_column(Integer(), nullable=False)
