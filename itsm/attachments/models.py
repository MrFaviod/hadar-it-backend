"""Attachment metadata only; bytes belong to the configured blob storage."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from itsm.inventory.models import InventoryBase


class Attachment(InventoryBase):
    __tablename__ = "asset_attachments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    blob_key: Mapped[str] = mapped_column(String(32), unique=True)
    filename: Mapped[str] = mapped_column(String(180))
    category: Mapped[str] = mapped_column(String(16))
    content_type: Mapped[str] = mapped_column(String(120))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
