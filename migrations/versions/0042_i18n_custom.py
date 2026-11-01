"""Translator tooling support: source context for the custom layer (T7/S9).

The custom translation rows and the frontend ``ui.*`` source registration reuse
``i18n_providers``/``i18n_provider_catalogs`` from ``0039_i18n_registry``. The
only new state is the translator context a *source* provider brings with it:
core context ships as ``catalogs/context.json``, the frontend registers its own
per key, so it cannot live in a shipped file.

No row is seeded: a fresh installation has no source context until the frontend
registers its catalog, which keeps ``MIGRATION_REFERENCE_TABLES`` unchanged.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042_i18n_custom"
down_revision = "0041_i18n_labels"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "i18n_source_context",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider_id", sa.String(length=48), nullable=False),
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("context", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider_id", "key", name="uq_i18n_source_context_key"),
    )
    op.create_index("ix_i18n_source_context_provider", "i18n_source_context", ["provider_id"])


def downgrade() -> None:
    op.drop_index("ix_i18n_source_context_provider", table_name="i18n_source_context")
    op.drop_table("i18n_source_context")
