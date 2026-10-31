"""Durable host state for native extension packages.

Names are deliberately explicit: one module row owns identity and enablement,
versions are immutable installed bytes, candidates are review records, and
collection rows are namespaced by module.  Notification inbox columns are added
by the same migration; this module never imports notification business code.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class ExtensionBase(DeclarativeBase):
    """Private declarative base; extension tables never join core metadata."""


class ExtensionModule(ExtensionBase):
    __tablename__ = "extension_modules"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    data_schema_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ExtensionVersion(ExtensionBase):
    __tablename__ = "extension_versions"
    __table_args__ = (
        UniqueConstraint("extension_id", "version", name="uq_extension_version"),
        Index("ix_extension_versions_extension", "extension_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    package_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    installed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ExtensionCandidate(ExtensionBase):
    __tablename__ = "extension_candidates"
    __table_args__ = (
        Index("ix_extension_candidates_extension_state", "extension_id", "state"),
        Index("ix_extension_candidates_submitted", "submitted_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    package_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    base_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    base_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    submitted_by: Mapped[str] = mapped_column(String(36), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    validation_report_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    validation_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExtensionCollectionRecord(ExtensionBase):
    __tablename__ = "extension_collection_records"
    __table_args__ = (
        UniqueConstraint("extension_id", "collection", "record_id", name="uq_extension_record"),
        Index("ix_extension_collection_lookup", "extension_id", "collection"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    collection: Mapped[str] = mapped_column(String(64), nullable=False)
    record_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ExtensionPermission(ExtensionBase):
    __tablename__ = "extension_permissions"
    __table_args__ = (Index("ix_extension_permissions_extension", "extension_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    code: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ExtensionEvent(ExtensionBase):
    __tablename__ = "extension_events"
    __table_args__ = (Index("ix_extension_events_extension", "extension_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ExtensionMigration(ExtensionBase):
    __tablename__ = "extension_migrations"
    __table_args__ = (
        UniqueConstraint(
            "extension_id",
            "package_version",
            "from_schema",
            "to_schema",
            name="uq_extension_migration_step",
        ),
        Index("ix_extension_migrations_extension", "extension_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    package_version: Mapped[str] = mapped_column(String(32), nullable=False)
    from_schema: Mapped[int] = mapped_column(Integer, nullable=False)
    to_schema: Mapped[int] = mapped_column(Integer, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    applied_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class ExtensionScheduleState(ExtensionBase):
    __tablename__ = "extension_schedule_state"
    __table_args__ = (
        UniqueConstraint("extension_id", "name", name="uq_extension_schedule"),
        Index("ix_extension_schedule_due", "next_due_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    next_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ExtensionCoreCall(ExtensionBase):
    """Replay ledger for authorized core mutations performed by an extension.

    The row is core-owned host metadata: it stores the caller-supplied
    idempotency key, the capability that consumed it, a digest of the request
    and the canonical service response.  Module business data never lands here.
    """

    __tablename__ = "extension_core_calls"
    __table_args__ = (
        UniqueConstraint("extension_id", "call_key", name="uq_extension_core_call"),
        Index("ix_extension_core_calls_extension", "extension_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension_id: Mapped[str] = mapped_column(String(48), nullable=False)
    call_key: Mapped[str] = mapped_column(String(128), nullable=False)
    capability: Mapped[str] = mapped_column(String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
