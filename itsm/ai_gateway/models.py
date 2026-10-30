"""Durable managed-gateway state: run-scoped leases and per-call accounting.

Only a hash of the opaque bearer token is stored. The provider selection
snapshot (base URL, model and real upstream credential) is sealed with the
process Fernet key and never leaves the server. Calls record the ledger
reservation they created and their terminal accounting state.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.clock import utcnow
from itsm.inventory.models import InventoryBase

CLAIMED = "claimed"
IN_FLIGHT = "in_flight"
SETTLED = "settled"
UNRESOLVED = "unresolved"
TERMINAL_CALL_STATES = (SETTLED, UNRESOLVED)

COMPANY = "company"
PERSONAL = "personal"
GLOBAL = "global"


class AiGatewayLease(InventoryBase):
    """One run-scoped data-plane authority; the raw token is never stored."""

    __tablename__ = "ai_gateway_leases"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_ai_gateway_leases_token_hash"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_reservation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    funding: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_scope: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_name: Mapped[str] = mapped_column(String(200), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    engine: Mapped[str] = mapped_column(String(64), nullable=False)
    context_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    # Which non-text input kinds (comma separated, e.g. "image,file") this lease
    # admits and the encoded byte budget their parts may consume.
    input_modalities: Mapped[str] = mapped_column(
        String(32), nullable=False, default="", server_default=""
    )
    attachment_bytes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    selection_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    allow_private: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AiGatewayCall(InventoryBase):
    """One admitted gateway call and its terminal accounting state."""

    __tablename__ = "ai_gateway_calls"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "idempotency_hash",
            name="uq_ai_gateway_calls_run_idempotency",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    lease_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    idempotency_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    precision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


__all__ = [
    "CLAIMED",
    "IN_FLIGHT",
    "SETTLED",
    "TERMINAL_CALL_STATES",
    "UNRESOLVED",
    "AiGatewayCall",
    "AiGatewayLease",
]
