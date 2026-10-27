"""Durable AI usage quota state: policies, reservations, receipts and balances.

The ledger is owned by ITSM. It stores only normalized token evidence: never
provider payloads, prompts or credentials. ``ai_usage_balances`` is the atomic
admission counter; reservations and receipts are the immutable/terminal
attribution record.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase

COMPANY = "company"
PERSONAL = "personal"
FUNDING_SCOPES = (COMPANY, PERSONAL)

PENDING = "pending"
SETTLED = "settled"
UNRESOLVED = "unresolved"
RELEASED = "released"

POLICY_ID = "installation"


class AiUsageQuotaPolicy(InventoryBase):
    """Installation-wide defaults. Overrides live per user and funding scope."""

    __tablename__ = "ai_usage_quota_policy"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    company_daily_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    company_configured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    personal_daily_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    personal_configured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    pending_timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pending_effective_day: Mapped[str | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AiUsageQuotaOverride(InventoryBase):
    """Explicit per-user limit. Row presence overrides; NULL means unlimited."""

    __tablename__ = "ai_usage_quota_overrides"
    __table_args__ = (
        UniqueConstraint("user_id", "scope", name="uq_ai_usage_quota_override_user_scope"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    daily_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AiUsageReservation(InventoryBase):
    """A durable hold created before provider work is admitted."""

    __tablename__ = "ai_usage_reservations"
    __table_args__ = (
        UniqueConstraint(
            "actor_id",
            "idempotency_key",
            name="uq_ai_usage_reservation_actor_idempotency",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    funding: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_scope: Mapped[str | None] = mapped_column(String(16), nullable=True)
    provider_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    engine: Mapped[str | None] = mapped_column(String(64), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    parent_reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    period_day: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    reserved_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=PENDING)
    settled_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    precision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    estimation_method: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AiUsageReceipt(InventoryBase):
    """Terminal or last-known evidence for one reservation, with snapshots."""

    __tablename__ = "ai_usage_receipts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    reservation_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    funding: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_scope: Mapped[str | None] = mapped_column(String(16), nullable=True)
    provider_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    engine: Mapped[str | None] = mapped_column(String(64), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    period_day: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cache_read_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cache_write_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reasoning_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    precision: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    total_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    estimation_method: Mapped[str | None] = mapped_column(String(120), nullable=True)
    cache_included_in_input: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reasoning_included_in_output: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AiUsageBalance(InventoryBase):
    """Atomic per-actor/funding/day counter used by reservation admission.

    ``consumed_tokens`` is settled usage, ``reserved_tokens`` is the sum of
    pending holds. Legacy UTC usage is read from ``agent_daily_usage`` at
    admission time and is never copied into personal or attributed rows.
    """

    __tablename__ = "ai_usage_balances"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    day: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    consumed_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reserved_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
