"""Managed AI gateway leases and per-call accounting.

Revision ID: 0025_ai_gateway
Revises: 0024_ai_usage
Create Date: 2026-10-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_ai_gateway"
down_revision: str | None = "0024_ai_usage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_gateway_leases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("parent_reservation_id", sa.String(length=36), nullable=False),
        sa.Column("funding", sa.String(length=16), nullable=False),
        sa.Column("provider_id", sa.String(length=64), nullable=False),
        sa.Column("provider_scope", sa.String(length=16), nullable=False),
        sa.Column("provider_name", sa.String(length=200), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("engine", sa.String(length=64), nullable=False),
        sa.Column("context_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("selection_ciphertext", sa.Text(), nullable=False),
        sa.Column("allow_private", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_ai_gateway_leases_token_hash"),
    )
    op.create_index(
        "ix_ai_gateway_leases_actor_id", "ai_gateway_leases", ["actor_id"]
    )
    op.create_index("ix_ai_gateway_leases_run_id", "ai_gateway_leases", ["run_id"])
    op.create_index(
        "ix_ai_gateway_leases_expires_at", "ai_gateway_leases", ["expires_at"]
    )

    op.create_table(
        "ai_gateway_calls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("lease_id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_hash", sa.String(length=64), nullable=True),
        sa.Column("reservation_id", sa.String(length=36), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("total_tokens", sa.Integer(), nullable=True),
        sa.Column("precision", sa.String(length=16), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "idempotency_hash",
            name="uq_ai_gateway_calls_run_idempotency",
        ),
    )
    op.create_index("ix_ai_gateway_calls_lease_id", "ai_gateway_calls", ["lease_id"])
    op.create_index("ix_ai_gateway_calls_actor_id", "ai_gateway_calls", ["actor_id"])
    op.create_index("ix_ai_gateway_calls_run_id", "ai_gateway_calls", ["run_id"])
    op.create_index(
        "ix_ai_gateway_calls_reservation_id", "ai_gateway_calls", ["reservation_id"]
    )
    op.create_index("ix_ai_gateway_calls_state", "ai_gateway_calls", ["state"])


def downgrade() -> None:
    op.drop_index("ix_ai_gateway_calls_state", table_name="ai_gateway_calls")
    op.drop_index(
        "ix_ai_gateway_calls_reservation_id", table_name="ai_gateway_calls"
    )
    op.drop_index("ix_ai_gateway_calls_run_id", table_name="ai_gateway_calls")
    op.drop_index("ix_ai_gateway_calls_actor_id", table_name="ai_gateway_calls")
    op.drop_index("ix_ai_gateway_calls_lease_id", table_name="ai_gateway_calls")
    op.drop_table("ai_gateway_calls")

    op.drop_index("ix_ai_gateway_leases_expires_at", table_name="ai_gateway_leases")
    op.drop_index("ix_ai_gateway_leases_run_id", table_name="ai_gateway_leases")
    op.drop_index("ix_ai_gateway_leases_actor_id", table_name="ai_gateway_leases")
    op.drop_table("ai_gateway_leases")
