"""Scope the extension idempotency ledger by the invoking principal.

The replay ledger answered a stored canonical response from
``(extension_id, call_key)`` alone, so any other caller holding the module
operation permission could replay the key and read the first caller's core
response (security readiness finding R3-F2).  The ledger key gains the
principal actor id and the unique constraint is recreated over the three
columns.

Existing rows cannot be attributed to a principal after the fact, so they are
backfilled with an empty principal id: such a row is never replayed again
(nobody resolves to an empty actor id) and it never blocks a new reservation
for a real principal.  Retiring the old response is the fail-closed choice.

Revision ID: 0037_extension_core_call_principal
Revises: 0036_entity_change_events
"""

import sqlalchemy as sa
from alembic import op

revision = "0037_extension_core_call_principal"
down_revision = "0036_entity_change_events"
branch_labels = None
depends_on = None

TABLE = "extension_core_calls"


def upgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(
            sa.Column("principal_id", sa.String(length=64), nullable=False, server_default="")
        )
        batch.drop_constraint("uq_extension_core_call", type_="unique")
        batch.create_unique_constraint(
            "uq_extension_core_call", ["extension_id", "principal_id", "call_key"]
        )


def downgrade() -> None:
    # Two principals may have reserved the same key for one module; keep the
    # oldest reservation per key so the narrower constraint can be restored.
    op.execute(
        sa.text(
            f"DELETE FROM {TABLE} WHERE id NOT IN ("
            f"SELECT MIN(id) FROM {TABLE} GROUP BY extension_id, call_key)"
        )
    )
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_constraint("uq_extension_core_call", type_="unique")
        batch.create_unique_constraint("uq_extension_core_call", ["extension_id", "call_key"])
        batch.drop_column("principal_id")
