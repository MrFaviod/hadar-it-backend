"""Durable native extension modules, candidates, storage and permissions.

Revision ID: 0027_native_extensions
Revises: 0026_ai_instance_quotas
"""

import sqlalchemy as sa
from alembic import op

revision = "0027_native_extensions"
down_revision = "0026_ai_instance_quotas"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "extension_modules",
        sa.Column("id", sa.String(48), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("active_version", sa.String(32)),
        sa.Column("data_schema_version", sa.Integer()),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "extension_versions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("package_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("installed_by", sa.String(36)),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("extension_id", "version", name="uq_extension_version"),
    )
    op.create_index(
        "ix_extension_versions_extension", "extension_versions", ["extension_id"]
    )
    op.create_table(
        "extension_candidates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("package_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("base_version", sa.String(32)),
        sa.Column("base_revision", sa.Integer()),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("submitted_by", sa.String(36), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validation_report_json", sa.Text()),
        sa.Column("validation_digest", sa.String(64)),
        sa.Column("validated_at", sa.DateTime(timezone=True)),
        sa.Column("approved_by", sa.String(36)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("superseded_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_extension_candidates_extension_state",
        "extension_candidates",
        ["extension_id", "state"],
    )
    op.create_index(
        "ix_extension_candidates_submitted", "extension_candidates", ["submitted_at"]
    )
    op.create_table(
        "extension_collection_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("collection", sa.String(64), nullable=False),
        sa.Column("record_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "extension_id",
            "collection",
            "record_id",
            name="uq_extension_record",
        ),
    )
    op.create_index(
        "ix_extension_collection_lookup",
        "extension_collection_records",
        ["extension_id", "collection"],
    )
    op.create_table(
        "extension_permissions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("code", sa.String(128), nullable=False, unique=True),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_extension_permissions_extension", "extension_permissions", ["extension_id"]
    )
    op.create_table(
        "extension_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(36)),
        sa.Column("detail_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_extension_events_extension",
        "extension_events",
        ["extension_id", "created_at"],
    )
    op.create_table(
        "extension_migrations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("package_version", sa.String(32), nullable=False),
        sa.Column("from_schema", sa.Integer(), nullable=False),
        sa.Column("to_schema", sa.Integer(), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_by", sa.String(36)),
        sa.UniqueConstraint(
            "extension_id",
            "package_version",
            "from_schema",
            "to_schema",
            name="uq_extension_migration_step",
        ),
    )
    op.create_index(
        "ix_extension_migrations_extension", "extension_migrations", ["extension_id"]
    )
    op.create_table(
        "extension_schedule_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension_id", sa.String(48), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(36)),
        sa.Column("next_due_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("extension_id", "name", name="uq_extension_schedule"),
    )
    op.create_index(
        "ix_extension_schedule_due", "extension_schedule_state", ["next_due_at"]
    )
    op.add_column(
        "notification_inbox",
        sa.Column("extension_id", sa.String(64), nullable=True),
    )
    op.add_column(
        "notification_inbox",
        sa.Column("required_permission", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("notification_inbox", "required_permission")
    op.drop_column("notification_inbox", "extension_id")
    op.drop_index("ix_extension_schedule_due", table_name="extension_schedule_state")
    op.drop_table("extension_schedule_state")
    op.drop_index("ix_extension_migrations_extension", table_name="extension_migrations")
    op.drop_table("extension_migrations")
    op.drop_index("ix_extension_events_extension", table_name="extension_events")
    op.drop_table("extension_events")
    op.drop_index(
        "ix_extension_permissions_extension", table_name="extension_permissions"
    )
    op.drop_table("extension_permissions")
    op.drop_index(
        "ix_extension_collection_lookup", table_name="extension_collection_records"
    )
    op.drop_table("extension_collection_records")
    op.drop_index(
        "ix_extension_candidates_submitted", table_name="extension_candidates"
    )
    op.drop_index(
        "ix_extension_candidates_extension_state", table_name="extension_candidates"
    )
    op.drop_table("extension_candidates")
    op.drop_index("ix_extension_versions_extension", table_name="extension_versions")
    op.drop_table("extension_versions")
    op.drop_table("extension_modules")
