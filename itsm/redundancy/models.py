"""Portable persistence for redundancy groups and their member instances.

Groups never own the asset identity: every member is an existing inventory row
with its own permanent UUID and its own hosting relation. The group only records
the administrative fact that those rows are replicas of one workload, with a
mode, an activation state and (for active/active) configured traffic shares.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class RedundancyGroup(InventoryBase):
    __tablename__ = "redundancy_groups"
    __table_args__ = (Index("ix_redundancy_groups_active", "active"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class RedundancyGroupMember(InventoryBase):
    __tablename__ = "redundancy_group_members"
    __table_args__ = (
        UniqueConstraint("group_id", "asset_id", name="uq_redundancy_group_member"),
        Index("ix_redundancy_group_members_asset", "asset_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    group_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("redundancy_groups.id", ondelete="RESTRICT"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    share: Mapped[str | None] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


__all__ = ["RedundancyGroup", "RedundancyGroupMember"]
