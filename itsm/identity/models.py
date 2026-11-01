"""Portable SQLAlchemy models owned by the identity module.

Plain SQLAlchemy types only (strings, integers, booleans, timestamps) so the
same schema works on SQLite, PostgreSQL, MariaDB/MySQL and SQL Server. Policies
live in ITSM-owned tables; Casbin evaluates them, it does not own persistence.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class IdentityBase(DeclarativeBase):
    """Declarative base for identity tables."""


class IdentityRole(IdentityBase):
    __tablename__ = "identity_roles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    built_in: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class IdentityRolePolicy(IdentityBase):
    __tablename__ = "identity_role_policies"
    __table_args__ = (
        UniqueConstraint(
            "role_id",
            "resource",
            "operation",
            name="uq_identity_role_policies_grant",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    role_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("identity_roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)


class Identity(IdentityBase):
    __tablename__ = "identity_identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="human")
    person_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("identity_roles.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    delegated_by_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("identity_identities.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Role held by the delegating human when the delegation was recorded.
    # Reserved machine grants additionally require this to stay ``superadmin``,
    # so a changed delegator cannot silently broaden a machine's authority.
    role_owner: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Personal language preference; ``NULL`` means "follow the installation".
    locale: Mapped[str | None] = mapped_column(String(35), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    last_access_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentitySession(IdentityBase):
    __tablename__ = "identity_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identity_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("identity_identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_access_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentityCredential(IdentityBase):
    """Static machine credential; only the token digest is stored."""

    __tablename__ = "identity_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    identity_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("identity_identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentityLoginAttempt(IdentityBase):
    """Durable login throttling evidence, bounded by pruning on each attempt."""

    __tablename__ = "identity_login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    successful: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class IdentitySecuritySettings(IdentityBase):
    """Single-row security configuration owned by the installation."""

    __tablename__ = "identity_security_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=480)
    # Installation i18n defaults. Columns, not seeded rows, so an untouched
    # installation still has no settings row until an administrator saves one.
    default_locale: Mapped[str] = mapped_column(String(35), nullable=False, default="es")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="America/Asuncion")
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="PYG")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class IdentityAuditEvent(IdentityBase):
    """Operational audit trail: actor, action, resource, time and outcome."""

    __tablename__ = "identity_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(200), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    execution_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delegated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    authorization_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
