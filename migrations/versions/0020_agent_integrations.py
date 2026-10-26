"""Agent integration control-plane tables.

Revision ID: 0020_agent_integrations
Revises: 0019_workspace_search_appearance
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_agent_integrations"
down_revision = "0019_workspace_search_appearance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_instances",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("base_url", sa.String(length=500), nullable=True),
        sa.Column("secret_ref", sa.String(length=128), nullable=True),
        sa.Column("username", sa.String(length=200), nullable=True),
        sa.Column("profile", sa.String(length=200), nullable=True),
        sa.Column("directory", sa.String(length=1024), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("default_model", sa.String(length=200), nullable=True),
        sa.Column("integration_identity_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "agent_preferences",
        sa.Column("owner_id", sa.String(length=36), primary_key=True),
        sa.Column("instance_id", sa.String(length=36), nullable=True),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "agent_installation_preferences",
        sa.Column("id", sa.String(length=16), primary_key=True),
        sa.Column("instance_id", sa.String(length=36), nullable=True),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("instance_id", sa.String(length=36), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("external_session_id", sa.String(length=200), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("messages", sa.JSON(), nullable=False),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.Column("approval_pending", sa.Boolean(), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_sessions_owner_id", "agent_sessions", ["owner_id"])
    op.create_index("ix_agent_sessions_instance_id", "agent_sessions", ["instance_id"])
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_runs_session_id", "agent_runs", ["session_id"])
    op.create_index("ix_agent_runs_owner_id", "agent_runs", ["owner_id"])
    op.create_table(
        "agent_daily_usage",
        sa.Column("id", sa.String(length=80), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("day", sa.String(length=10), nullable=False),
        sa.Column("measured_tokens", sa.Integer(), nullable=False),
        sa.Column("reported_tokens", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_daily_usage_owner_id", "agent_daily_usage", ["owner_id"])
    op.create_index("ix_agent_daily_usage_day", "agent_daily_usage", ["day"])
    op.create_table(
        "agent_installations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("instance_id", sa.String(length=36), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("profile", sa.String(length=200), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("operation", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("receipt", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "instance_id",
            "engine",
            "path",
            "profile",
            name="uq_agent_installations_binding",
        ),
    )
    op.create_index("ix_agent_installations_instance_id", "agent_installations", ["instance_id"])
    op.create_table(
        "agent_module_states",
        sa.Column("module_id", sa.String(length=120), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("agent_module_states")
    op.drop_index("ix_agent_installations_instance_id", table_name="agent_installations")
    op.drop_table("agent_installations")
    op.drop_index("ix_agent_daily_usage_day", table_name="agent_daily_usage")
    op.drop_index("ix_agent_daily_usage_owner_id", table_name="agent_daily_usage")
    op.drop_table("agent_daily_usage")
    op.drop_index("ix_agent_runs_owner_id", table_name="agent_runs")
    op.drop_index("ix_agent_runs_session_id", table_name="agent_runs")
    op.drop_table("agent_runs")
    op.drop_index("ix_agent_sessions_instance_id", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_owner_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")
    op.drop_table("agent_installation_preferences")
    op.drop_table("agent_preferences")
    op.drop_table("agent_instances")
