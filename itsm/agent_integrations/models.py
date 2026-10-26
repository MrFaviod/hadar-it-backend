"""Persisted control-plane state for agent engines, sessions and integrations.

The tables intentionally use portable SQLAlchemy types only. Identity authority
stays in ``itsm.identity`` tables; these rows reference identity ids without
creating cross-module foreign keys, following the workspace/appearance pattern.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase


class AgentInstance(InventoryBase):
    """One selectable engine endpoint; the built-in Pydantic AI row is seeded."""

    __tablename__ = "agent_instances"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    secret_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    username: Mapped[str | None] = mapped_column(String(200), nullable=True)
    profile: Mapped[str | None] = mapped_column(String(200), nullable=True)
    directory: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    default_model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    integration_identity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentPreference(InventoryBase):
    """Per-person engine/model choice; missing simply means no preference yet."""

    __tablename__ = "agent_preferences"

    owner_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    instance_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentInstallationPreference(InventoryBase):
    """Installation-wide default selection written by a full administrator."""

    __tablename__ = "agent_installation_preferences"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    instance_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentSession(InventoryBase):
    """One human-owned chat session; never transferable to another person."""

    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="idle")
    external_session_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    capabilities: Mapped[dict[str, bool]] = mapped_column(JSON, nullable=False, default=dict)
    messages: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    results: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    approval_pending: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentRun(InventoryBase):
    """Durable run marker so a killed worker cannot leave a session stuck running."""

    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentDailyUsage(InventoryBase):
    """Daily token counters; measured and externally reported stay separate."""

    __tablename__ = "agent_daily_usage"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    day: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    measured_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reported_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentInstallation(InventoryBase):
    """Last truthful installer receipt for one instance/target binding."""

    __tablename__ = "agent_installations"
    __table_args__ = (
        UniqueConstraint(
            "instance_id",
            "engine",
            "path",
            "profile",
            name="uq_agent_installations_binding",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    profile: Mapped[str | None] = mapped_column(String(200), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operation: Mapped[str] = mapped_column(String(16), nullable=False, default="install")
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    receipt: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentModuleState(InventoryBase):
    """Administrator toggle for a registered extension module."""

    __tablename__ = "agent_module_states"

    module_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentProvider(InventoryBase):
    """Global or personal OpenAI-compatible provider selectable as a Pydantic engine.

    The record never stores raw credentials: ``api_key_ciphertext`` is a Fernet
    token sealed with the externally supplied process key.
    """

    __tablename__ = "agent_providers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    models: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    api_key_ciphertext: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


__all__ = [
    "AgentDailyUsage",
    "AgentInstallation",
    "AgentInstallationPreference",
    "AgentInstance",
    "AgentModuleState",
    "AgentPreference",
    "AgentProvider",
    "AgentRun",
    "AgentSession",
]
