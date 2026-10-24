"""Workspace preferences, durable search synchronization and installation appearance.

Revision ID: 0019_workspace_search_appearance
Revises: 0018_reports
Create Date: 2026-10-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_workspace_search_appearance"
down_revision = "0018_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspace_user_state",
        sa.Column("user_id", sa.String(36), primary_key=True),
        sa.Column("widgets", sa.JSON(), nullable=True),
        sa.Column("favorites", sa.JSON(), nullable=True),
        sa.Column("usage", sa.JSON(), nullable=True),
        sa.Column("last_views", sa.JSON(), nullable=True),
        sa.Column("theme_mode", sa.String(16), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "workspace_shortcuts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("owner_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("url", sa.String(1000), nullable=False),
        sa.Column("icon", sa.String(64), nullable=True),
        sa.Column("category", sa.String(64), nullable=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_workspace_shortcuts_owner_id", "workspace_shortcuts", ["owner_id"])
    op.create_index("ix_workspace_shortcuts_scope", "workspace_shortcuts", ["scope"])
    op.create_index(
        "ix_workspace_shortcuts_owner_scope", "workspace_shortcuts", ["owner_id", "scope"]
    )
    op.create_table(
        "workspace_views",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("owner_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("route", sa.String(128), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_workspace_views_owner_id", "workspace_views", ["owner_id"])
    op.create_index("ix_workspace_views_scope", "workspace_views", ["scope"])
    op.create_index("ix_workspace_views_owner_scope", "workspace_views", ["owner_id", "scope"])
    op.create_table(
        "workspace_integrations",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("anydesk_url", sa.String(500), nullable=True),
        sa.Column("rmm_url", sa.String(500), nullable=True),
        sa.Column("anydesk_enabled", sa.Boolean(), nullable=False),
        sa.Column("rmm_enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "appearance_presets",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("staged", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(160), nullable=False),
        sa.Column("updated_by", sa.String(160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_appearance_presets_name", "appearance_presets", ["name"], unique=True)
    op.create_table(
        "appearance_resources",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("content_type", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("blob_key", sa.String(32), nullable=False),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("blob_key", name="uq_appearance_resources_blob_key"),
    )
    op.create_index(
        "ix_appearance_resources_sha256", "appearance_resources", ["sha256"], unique=True
    )
    op.create_table(
        "appearance_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("active_id", sa.String(80), nullable=False),
        sa.Column("previous_id", sa.String(80), nullable=True),
        sa.Column("active", sa.JSON(), nullable=False),
        sa.Column("previous", sa.JSON(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(160), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "search_sync_outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_search_sync_outbox_due", "search_sync_outbox", ["status", "available_at"])
    op.create_index(
        "ix_search_sync_outbox_entity",
        "search_sync_outbox",
        ["entity_type", "entity_id", "created_at"],
    )
    op.create_table(
        "search_index_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_rebuild_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("document_count", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("search_index_state")
    op.drop_index("ix_search_sync_outbox_entity", table_name="search_sync_outbox")
    op.drop_index("ix_search_sync_outbox_due", table_name="search_sync_outbox")
    op.drop_table("search_sync_outbox")
    op.drop_table("appearance_state")
    op.drop_index("ix_appearance_resources_sha256", table_name="appearance_resources")
    op.drop_table("appearance_resources")
    op.drop_index("ix_appearance_presets_name", table_name="appearance_presets")
    op.drop_table("appearance_presets")
    op.drop_table("workspace_integrations")
    op.drop_index("ix_workspace_views_owner_scope", table_name="workspace_views")
    op.drop_index("ix_workspace_views_scope", table_name="workspace_views")
    op.drop_index("ix_workspace_views_owner_id", table_name="workspace_views")
    op.drop_table("workspace_views")
    op.drop_index("ix_workspace_shortcuts_owner_scope", table_name="workspace_shortcuts")
    op.drop_index("ix_workspace_shortcuts_scope", table_name="workspace_shortcuts")
    op.drop_index("ix_workspace_shortcuts_owner_id", table_name="workspace_shortcuts")
    op.drop_table("workspace_shortcuts")
    op.drop_table("workspace_user_state")
