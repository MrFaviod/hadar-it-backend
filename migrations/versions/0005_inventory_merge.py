"""Merge independent catalog and asset-core schema additions.

Revision ID: 0005_inventory_merge
Revises: 0004_asset_core, 0004_inventory_catalog
"""

from __future__ import annotations

revision = "0005_inventory_merge"
down_revision = ("0004_asset_core", "0004_inventory_catalog")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
