"""Portable SQLAlchemy models for monitoring configuration and operational alerts.

Plain SQLAlchemy types only so the same schema works on SQLite, PostgreSQL and
MariaDB/MySQL. Asset references are deliberate plain string columns: monitoring
configuration, alert history and maintenance windows must not block a guarded
permanent purge, and an alert record outlives the asset it referred to while it
remains readable through its stored labels.

Alert cycles are identified by ``(fingerprint, starts_at)``: a recurrence keeps
the same native fingerprint but a new ``starts_at`` and therefore a new row,
while a repeated delivery of the same payload can never create a second record
or a second history event.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class MonitorExporter(InventoryBase):
    """Administrator-controlled exporter reference; endpoints are never called from ITSM."""

    __tablename__ = "monitor_exporters"
    __table_args__ = (UniqueConstraint("name", name="uq_monitor_exporter_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    address: Mapped[str | None] = mapped_column(String(200), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class MonitorProfile(InventoryBase):
    """Default supervision profile for one inventory category."""

    __tablename__ = "monitor_profiles"

    category: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    check_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    metrics: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    thresholds: Mapped[dict[str, dict[str, float]]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    minimum_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    exporter_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    snmp_module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snmp_auth_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class MonitorAsset(InventoryBase):
    """Per-asset override; a NULL column inherits the category profile."""

    __tablename__ = "monitor_assets"

    asset_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    check_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target: Mapped[str | None] = mapped_column(String(500), nullable=True)
    interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metrics: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    thresholds: Mapped[dict[str, dict[str, float]] | None] = mapped_column(JSON, nullable=True)
    minimum_duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exporter_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    snmp_module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snmp_auth_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class MonitoringAlert(InventoryBase):
    """One alert cycle: a native fingerprint plus its ``starts_at`` occurrence."""

    __tablename__ = "monitoring_alerts"
    __table_args__ = (
        UniqueConstraint("fingerprint", "starts_at", name="uq_monitoring_alert_cycle"),
        Index("ix_monitoring_alerts_asset_id", "asset_id"),
        Index("ix_monitoring_alerts_state", "state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_name: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    group_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    annotations: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[str | None] = mapped_column(Text(), nullable=True)
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acknowledged_notes: Mapped[str | None] = mapped_column(Text(), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class MonitoringAlertEvent(InventoryBase):
    """Append-only alert history; ``event_key`` makes repeated deliveries idempotent."""

    __tablename__ = "monitoring_alert_events"
    __table_args__ = (
        UniqueConstraint("alert_id", "event_key", name="uq_monitoring_alert_event_key"),
        Index("ix_monitoring_alert_events_alert_id", "alert_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    note: Mapped[str | None] = mapped_column(Text(), nullable=True)
    changes: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    event_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class MonitoringSilence(InventoryBase):
    """Temporary suppression: native Alertmanager silence or local eligibility guard."""

    __tablename__ = "monitoring_silences"
    __table_args__ = (
        Index("ix_monitoring_silences_asset_id", "asset_id"),
        Index("ix_monitoring_silences_alert_id", "alert_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    comment: Mapped[str] = mapped_column(Text(), nullable=False)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    native_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class MaintenanceWindow(InventoryBase):
    """Recurring maintenance window; occurrences drive native Alertmanager silences."""

    __tablename__ = "maintenance_windows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    asset_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    days_of_week: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    start_time: Mapped[str] = mapped_column(String(5), nullable=False)
    end_time: Mapped[str] = mapped_column(String(5), nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    am_silence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    am_occurrence_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
