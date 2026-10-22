"""Portable relationship schema and the immutable default type snapshot.

Revision ID: 0007_relationships
Revises: 0006_inventory_codes

Adds the typed relationship edge and its configurable type table. The default
types are an immutable snapshot owned by this migration: they are not seeded by
application startup and no asset, identity or role row is created or changed.

The history columns are additive. Existing rows default to the trusted
``internal`` source and the ``asset`` entity, and ``entity_id`` is backfilled
with the row's ``asset_id`` so old histories stay meaningful. ``effective_at``
is separate from the insertion ``created_at`` and remains nullable.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0007_relationships"
down_revision = "0006_inventory_codes"
branch_labels = None
depends_on = None

_SEEDED_AT = datetime(2026, 2, 1, tzinfo=UTC)

DEFAULT_TYPES: tuple[dict[str, object], ...] = (
    {
        "key": "connected_to",
        "forward_label": "Conectado a",
        "inverse_label": "Conectado desde",
        "containment": False,
    },
    {
        "key": "installed_in",
        "forward_label": "Instalado en",
        "inverse_label": "Contiene",
        "containment": True,
    },
    {
        "key": "hosted_in",
        "forward_label": "Alojado en",
        "inverse_label": "Aloja",
        "containment": True,
    },
    {
        "key": "protected_by",
        "forward_label": "Protegido por",
        "inverse_label": "Protege a",
        "containment": False,
    },
    {
        "key": "depends_on",
        "forward_label": "Depende de",
        "inverse_label": "Requerido por",
        "containment": False,
    },
    {
        "key": "associated_with",
        "forward_label": "Asociado con",
        "inverse_label": "Asociado con",
        "containment": False,
    },
)


def upgrade() -> None:
    op.add_column(
        "asset_history",
        sa.Column("source", sa.String(length=16), nullable=False, server_default="internal"),
    )
    op.add_column(
        "asset_history",
        sa.Column("entity_type", sa.String(length=32), nullable=False, server_default="asset"),
    )
    op.add_column("asset_history", sa.Column("entity_id", sa.String(length=36), nullable=True))
    op.add_column(
        "asset_history",
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("asset_history", sa.Column("notes", sa.String(length=500), nullable=True))
    op.execute(sa.text("UPDATE asset_history SET entity_id = asset_id WHERE entity_id IS NULL"))

    types = op.create_table(
        "relationship_types",
        sa.Column("key", sa.String(length=32), primary_key=True),
        sa.Column("forward_label", sa.String(length=80), nullable=False),
        sa.Column("inverse_label", sa.String(length=80), nullable=False),
        sa.Column("containment", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_relationship_types_active", "relationship_types", ["active"])
    op.bulk_insert(
        types,
        [
            {
                **entry,
                "active": True,
                "created_at": _SEEDED_AT,
                "updated_at": _SEEDED_AT,
            }
            for entry in DEFAULT_TYPES
        ],
    )

    op.create_table(
        "relationships",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "type_key",
            sa.String(length=32),
            sa.ForeignKey("relationship_types.key", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("notes", sa.String(length=500), nullable=True),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source_id", "target_id", "type_key", name="uq_relationships_edge"),
    )
    op.create_index("ix_relationships_source", "relationships", ["source_id"])
    op.create_index("ix_relationships_target", "relationships", ["target_id"])
    op.create_index("ix_relationships_type", "relationships", ["type_key"])


def downgrade() -> None:
    op.drop_index("ix_relationships_type", table_name="relationships")
    op.drop_index("ix_relationships_target", table_name="relationships")
    op.drop_index("ix_relationships_source", table_name="relationships")
    op.drop_table("relationships")
    op.drop_index("ix_relationship_types_active", table_name="relationship_types")
    op.drop_table("relationship_types")
    op.drop_column("asset_history", "notes")
    op.drop_column("asset_history", "effective_at")
    op.drop_column("asset_history", "entity_id")
    op.drop_column("asset_history", "entity_type")
    op.drop_column("asset_history", "source")
