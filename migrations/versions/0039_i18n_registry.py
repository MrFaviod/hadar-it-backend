"""Add the versioned i18n catalog registry.

Owner catalogs (core files and extension packages) stay untouched, so these
tables only store the installed *overlay*: one row per provider catalog entry, the
locales a language pack installs, the localized docs it ships, the installation
custom translations (written by T7) and the singleton monotonic revision every
catalog response carries. No catalog content is seeded here.

Revision ID: 0039_i18n_registry
Revises: 0038_i18n_preferences
"""

import sqlalchemy as sa
from alembic import op

revision = "0039_i18n_registry"
down_revision = "0038_i18n_preferences"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "i18n_registry_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.execute(
        sa.text(
            "INSERT INTO i18n_registry_state (id, revision, updated_at)"
            " VALUES (1, 0, CURRENT_TIMESTAMP)"
        )
    )
    op.create_table(
        "i18n_providers",
        sa.Column("id", sa.String(length=48), primary_key=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("review_status", sa.String(length=16), nullable=False, server_default="reviewed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "i18n_provider_catalogs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider_id", sa.String(length=48), nullable=False),
        sa.Column("locale", sa.String(length=35), nullable=False),
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("is_override", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("provider_id", "locale", "key", name="uq_i18n_provider_catalogs_entry"),
    )
    op.create_index("ix_i18n_provider_catalogs_locale", "i18n_provider_catalogs", ["locale"])
    op.create_table(
        "i18n_provider_locales",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider_id", sa.String(length=48), nullable=False),
        sa.Column("tag", sa.String(length=35), nullable=False),
        sa.Column("canonical", sa.String(length=35), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("native_name", sa.String(length=120), nullable=False),
        sa.UniqueConstraint("provider_id", "tag", name="uq_i18n_provider_locales_tag"),
    )
    op.create_index("ix_i18n_provider_locales_tag", "i18n_provider_locales", ["tag"])
    op.create_table(
        "i18n_provider_docs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider_id", sa.String(length=48), nullable=False),
        sa.Column("locale", sa.String(length=35), nullable=False),
        sa.Column("canonical", sa.String(length=35), nullable=False),
        sa.Column("topic", sa.String(length=120), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.UniqueConstraint("provider_id", "locale", "topic", name="uq_i18n_provider_docs_topic"),
    )
    op.create_index("ix_i18n_provider_docs_locale", "i18n_provider_docs", ["locale"])
    op.create_table(
        "i18n_custom_translations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("locale", sa.String(length=35), nullable=False),
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("locale", "key", name="uq_i18n_custom_translations_entry"),
    )


def downgrade() -> None:
    op.drop_table("i18n_custom_translations")
    op.drop_index("ix_i18n_provider_docs_locale", table_name="i18n_provider_docs")
    op.drop_table("i18n_provider_docs")
    op.drop_index("ix_i18n_provider_locales_tag", table_name="i18n_provider_locales")
    op.drop_table("i18n_provider_locales")
    op.drop_index("ix_i18n_provider_catalogs_locale", table_name="i18n_provider_catalogs")
    op.drop_table("i18n_provider_catalogs")
    op.drop_table("i18n_providers")
    op.drop_table("i18n_registry_state")
