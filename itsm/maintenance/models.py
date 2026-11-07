"""Portable SQLAlchemy models for preventive maintenance templates and plans.

A template is the reusable default for one category and maintenance type. An
asset plan stores only the effective values that differ from that template or
the state produced by a real transition; inherited plans are computed on read
and never written by a GET.

Plan ids are deterministic UUIDv5 values derived from the asset UUID and
maintenance type. They stay stable when a virtual plan is materialized, so a
scheduler reminder or an intervention link never points at a disappearing id.

Foreign keys use ``RESTRICT``: an asset or directory person referenced by a
persisted plan cannot be deleted while the reference exists.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class MaintenanceTemplate(InventoryBase):
    """Reusable preventive default for one authoritative category and type."""

    __tablename__ = "maintenance_templates"
    __table_args__ = (
        UniqueConstraint(
            "category", "maintenance_type", name="uq_maintenance_template_category_type"
        ),
        Index("ix_maintenance_templates_category", "category"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    maintenance_type: Mapped[str] = mapped_column(String(32), nullable=False)
    interval_months: Mapped[int] = mapped_column(Integer, nullable=False)
    tasks: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    responsible_person_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class MaintenancePlan(InventoryBase):
    """One persisted asset plan: an explicit override or a transitioned cycle."""

    __tablename__ = "maintenance_plans"
    __table_args__ = (
        UniqueConstraint("asset_id", "maintenance_type", name="uq_maintenance_plan_asset_type"),
        Index("ix_maintenance_plans_asset", "asset_id"),
        Index("ix_maintenance_plans_due", "due_on"),
        Index("ix_maintenance_plans_status", "status"),
        Index("ix_maintenance_plans_type", "maintenance_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    maintenance_type: Mapped[str] = mapped_column(String(32), nullable=False)
    interval_months: Mapped[int] = mapped_column(Integer, nullable=False)
    tasks: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    responsible_person_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    scheduled_on: Mapped[date] = mapped_column(Date, nullable=False)
    last_completed_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    due_on: Mapped[date] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
