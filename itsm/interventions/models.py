"""Persisted technical interventions, incidents and their structured links."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from itsm.inventory.models import InventoryBase


class Incident(InventoryBase):
    """One technical incident with an explicit lifecycle and one primary asset."""

    __tablename__ = "technical_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="normal")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    primary_asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    responsible_person_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    opened_on: Mapped[date] = mapped_column(Date, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    resolution_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolution_prepared_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolution_prepared_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IncidentAsset(InventoryBase):
    """Unique additional asset affected by an incident, in explicit input order."""

    __tablename__ = "technical_incident_assets"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("technical_incidents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        primary_key=True,
        index=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)


class IncidentEvent(InventoryBase):
    """Append-only actuation history of one incident."""

    __tablename__ = "technical_incident_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("technical_incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    changes: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Intervention(InventoryBase):
    """One technical job performed on an asset or planned maintenance visit."""

    __tablename__ = "technical_interventions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    technician_person_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    occurred_on: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    labor_cost: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("technical_incidents.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    plan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class InterventionAttachment(InventoryBase):
    """Canonical attachment reference; the blob belongs to the intervention asset."""

    __tablename__ = "technical_intervention_attachments"

    intervention_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("technical_interventions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    attachment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("asset_attachments.id", ondelete="RESTRICT"),
        primary_key=True,
        index=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)


__all__ = [
    "Incident",
    "IncidentAsset",
    "IncidentEvent",
    "Intervention",
    "InterventionAttachment",
]
