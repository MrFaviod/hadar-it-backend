"""AI usage quota schema and initial explicit defaults.

Revision ID: 0024_ai_usage
Revises: 0023_ai_providers

The policy row seeds the documented installation choice: company budget falls
back to ``ITSM_AGENT_DAILY_TOKEN_BUDGET`` until an administrator sets an
explicit policy, while personal usage defaults to unlimited. No environment
value is snapshotted into the database, so configuration remains the single
environment authority until changed through the explicit policy API.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0024_ai_usage"
down_revision = "0023_ai_providers"
branch_labels = None
depends_on = None


def _policy_table() -> sa.TableClause:
    return sa.table(
        "ai_usage_quota_policy",
        sa.column("id", sa.String),
        sa.column("company_daily_limit", sa.Integer),
        sa.column("company_configured", sa.Boolean),
        sa.column("personal_daily_limit", sa.Integer),
        sa.column("personal_configured", sa.Boolean),
        sa.column("timezone", sa.String),
        sa.column("pending_timezone", sa.String),
        sa.column("pending_effective_day", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )


def upgrade() -> None:
    op.create_table(
        "ai_usage_quota_policy",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("company_daily_limit", sa.Integer(), nullable=True),
        sa.Column(
            "company_configured",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("personal_daily_limit", sa.Integer(), nullable=True),
        sa.Column(
            "personal_configured",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("pending_timezone", sa.String(length=64), nullable=True),
        sa.Column("pending_effective_day", sa.String(length=10), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "ai_usage_quota_overrides",
        sa.Column("id", sa.String(length=80), primary_key=True, nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("daily_limit", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "scope", name="uq_ai_usage_quota_override_user_scope"),
    )
    op.create_index(
        "ix_ai_usage_quota_overrides_user_id",
        "ai_usage_quota_overrides",
        ["user_id"],
    )

    op.create_table(
        "ai_usage_reservations",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=False),
        sa.Column("funding", sa.String(length=16), nullable=False),
        sa.Column("provider_id", sa.String(length=64), nullable=True),
        sa.Column("provider_scope", sa.String(length=16), nullable=True),
        sa.Column("provider_name", sa.String(length=200), nullable=True),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("engine", sa.String(length=64), nullable=True),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.Column("parent_reservation_id", sa.String(length=36), nullable=True),
        sa.Column("idempotency_key", sa.String(length=200), nullable=True),
        sa.Column("period_day", sa.String(length=10), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("reserved_tokens", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("settled_tokens", sa.Integer(), nullable=True),
        sa.Column("precision", sa.String(length=16), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=True),
        sa.Column("estimation_method", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "actor_id",
            "idempotency_key",
            name="uq_ai_usage_reservation_actor_idempotency",
        ),
    )
    op.create_index("ix_ai_usage_reservations_actor_id", "ai_usage_reservations", ["actor_id"])
    op.create_index("ix_ai_usage_reservations_run_id", "ai_usage_reservations", ["run_id"])
    op.create_index(
        "ix_ai_usage_reservations_parent_reservation_id",
        "ai_usage_reservations",
        ["parent_reservation_id"],
    )
    op.create_index("ix_ai_usage_reservations_period_day", "ai_usage_reservations", ["period_day"])

    op.create_table(
        "ai_usage_receipts",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("reservation_id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=False),
        sa.Column("funding", sa.String(length=16), nullable=False),
        sa.Column("provider_id", sa.String(length=64), nullable=True),
        sa.Column("provider_scope", sa.String(length=16), nullable=True),
        sa.Column("provider_name", sa.String(length=200), nullable=True),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("engine", sa.String(length=64), nullable=True),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.Column("period_day", sa.String(length=10), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("cache_read_tokens", sa.Integer(), nullable=True),
        sa.Column("cache_write_tokens", sa.Integer(), nullable=True),
        sa.Column("reasoning_tokens", sa.Integer(), nullable=True),
        sa.Column("total_tokens", sa.Integer(), nullable=True),
        sa.Column("precision", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("total_source", sa.String(length=16), nullable=True),
        sa.Column("estimation_method", sa.String(length=120), nullable=True),
        sa.Column("cache_included_in_input", sa.Boolean(), nullable=True),
        sa.Column("reasoning_included_in_output", sa.Boolean(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("resolved_by", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("reservation_id", name="uq_ai_usage_receipt_reservation_id"),
    )
    op.create_index("ix_ai_usage_receipts_actor_id", "ai_usage_receipts", ["actor_id"])
    op.create_index("ix_ai_usage_receipts_run_id", "ai_usage_receipts", ["run_id"])
    op.create_index("ix_ai_usage_receipts_period_day", "ai_usage_receipts", ["period_day"])
    op.create_index(
        "ix_ai_usage_receipts_reservation_id",
        "ai_usage_receipts",
        ["reservation_id"],
    )

    op.create_table(
        "ai_usage_balances",
        sa.Column("id", sa.String(length=80), primary_key=True, nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("day", sa.String(length=10), nullable=False),
        sa.Column("consumed_tokens", sa.Integer(), nullable=False),
        sa.Column("reserved_tokens", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_usage_balances_user_id", "ai_usage_balances", ["user_id"])
    op.create_index("ix_ai_usage_balances_day", "ai_usage_balances", ["day"])

    policy = _policy_table()
    bind = op.get_bind()
    exists = bind.execute(sa.select(policy.c.id).where(policy.c.id == "installation")).first()
    if exists is None:
        now = datetime.now(UTC)
        bind.execute(
            policy.insert().values(
                id="installation",
                company_daily_limit=None,
                company_configured=False,
                personal_daily_limit=None,
                personal_configured=True,
                timezone="UTC",
                pending_timezone=None,
                pending_effective_day=None,
                created_at=now,
                updated_at=now,
            )
        )


def downgrade() -> None:
    op.drop_index("ix_ai_usage_balances_day", table_name="ai_usage_balances")
    op.drop_index("ix_ai_usage_balances_user_id", table_name="ai_usage_balances")
    op.drop_table("ai_usage_balances")

    op.drop_index("ix_ai_usage_receipts_reservation_id", table_name="ai_usage_receipts")
    op.drop_index("ix_ai_usage_receipts_period_day", table_name="ai_usage_receipts")
    op.drop_index("ix_ai_usage_receipts_run_id", table_name="ai_usage_receipts")
    op.drop_index("ix_ai_usage_receipts_actor_id", table_name="ai_usage_receipts")
    op.drop_table("ai_usage_receipts")

    op.drop_index("ix_ai_usage_reservations_period_day", table_name="ai_usage_reservations")
    op.drop_index(
        "ix_ai_usage_reservations_parent_reservation_id",
        table_name="ai_usage_reservations",
    )
    op.drop_index("ix_ai_usage_reservations_run_id", table_name="ai_usage_reservations")
    op.drop_index("ix_ai_usage_reservations_actor_id", table_name="ai_usage_reservations")
    op.drop_table("ai_usage_reservations")

    op.drop_index("ix_ai_usage_quota_overrides_user_id", table_name="ai_usage_quota_overrides")
    op.drop_table("ai_usage_quota_overrides")

    op.drop_table("ai_usage_quota_policy")
