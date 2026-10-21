"""Transaction-bound code sequences and a portable inventory write mutex.

Revision ID: 0006_inventory_codes
Revises: 0005_inventory_merge
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_inventory_codes"
down_revision = "0005_inventory_merge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    table = op.create_table(
        "inventory_code_sequences",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("next_value", sa.Integer(), nullable=False),
    )
    op.bulk_insert(table, [{"key": "__lock__", "next_value": 0}])


def downgrade() -> None:
    op.drop_table("inventory_code_sequences")
