"""Portable SQLAlchemy models for the directory: people, departments, locations.

Plain SQLAlchemy types only, so the same schema works on SQLite, PostgreSQL and
MariaDB/MySQL.

* An inventory person is **not** an access account: there is no credential,
  session or identity foreign key here, and ``Identity.person_id`` is never
  matched to :class:`DirectoryPerson` automatically.
* Coordinates are stored as canonical decimal strings, like ``Asset.cost``, so
  no engine converts a geographic value through a binary float.
* ``name_key`` holds the case-normalized comparison key used for the
  case-insensitive uniqueness of a department name and of sibling locations.
* Directory events belong to the business transaction that produced them; they
  are append-only and carry before/after snapshots, actor, source and both the
  recorded and the effective timestamp.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class DirectoryBase(DeclarativeBase):
    """Declarative base for directory tables."""


class DirectoryDepartment(DirectoryBase):
    """A configurable organizational department (``Configuración``)."""

    __tablename__ = "directory_departments"
    __table_args__ = (UniqueConstraint("name_key", name="uq_directory_departments_name_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    name_key: Mapped[str] = mapped_column(String(120), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class DirectoryLocation(DirectoryBase):
    """One node of ``site -> building -> floor -> room|zone``."""

    __tablename__ = "directory_locations"
    __table_args__ = (
        UniqueConstraint("parent_id", "name_key", name="uq_directory_locations_sibling_name"),
        Index("ix_directory_locations_level", "level"),
        Index("ix_directory_locations_parent", "parent_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    parent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("directory_locations.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    name_key: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    latitude: Mapped[str | None] = mapped_column(String(24), nullable=True)
    longitude: Mapped[str | None] = mapped_column(String(24), nullable=True)
    plan_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plan_page: Mapped[str | None] = mapped_column(String(32), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class DirectoryPerson(DirectoryBase):
    """An inventory person: responsibility, never a login."""

    __tablename__ = "directory_people"
    __table_args__ = (
        Index("ix_directory_people_status", "status"),
        Index("ix_directory_people_department", "department_id"),
        Index("ix_directory_people_site", "site_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    job_title: Mapped[str | None] = mapped_column(String(120), nullable=True)
    department_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("directory_departments.id"), nullable=True
    )
    site_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("directory_locations.id"), nullable=True
    )
    contact_email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class DirectoryEvent(DirectoryBase):
    """Append-only structured event of the directory, per affected entity."""

    __tablename__ = "directory_events"
    __table_args__ = (Index("ix_directory_events_entity", "entity", "entity_id", "recorded_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    before_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(1000), nullable=True)
