"""Canonical asset organization references and relative plan positions.

Revision ID: 0009_asset_directory
Revises: 0008_directory_relationships

Additive and portable: five nullable columns on ``assets`` plus their indexes.
The legacy ``site``, ``location`` and ``responsible`` text columns are untouched,
no existing row is backfilled and no directory row is created, so a database
upgraded from the pre-phase-5 schema keeps every stored value and every caller
that never sends an id keeps working exactly as before.

The reference columns carry no database foreign key: adding a constraint to an
existing table is not portable across the supported engines. Referential
integrity (existing, active, site-level and same-site descendant rules) is
enforced by ``InventoryService`` with ``DirectoryService``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_asset_directory"
down_revision = "0008_directory_relationships"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("site_id", sa.String(length=36), nullable=True))
    op.add_column("assets", sa.Column("location_id", sa.String(length=36), nullable=True))
    op.add_column("assets", sa.Column("responsible_person_id", sa.String(length=36), nullable=True))
    op.add_column("assets", sa.Column("position_x", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("position_y", sa.String(length=16), nullable=True))
    op.create_index("ix_assets_site_id", "assets", ["site_id"])
    op.create_index("ix_assets_location_id", "assets", ["location_id"])
    op.create_index(
        "ix_assets_responsible_person",
        "assets",
        ["responsible_person_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_assets_responsible_person", table_name="assets")
    op.drop_index("ix_assets_location_id", table_name="assets")
    op.drop_index("ix_assets_site_id", table_name="assets")
    op.drop_column("assets", "position_y")
    op.drop_column("assets", "position_x")
    op.drop_column("assets", "responsible_person_id")
    op.drop_column("assets", "location_id")
    op.drop_column("assets", "site_id")
