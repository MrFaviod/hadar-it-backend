"""Bound machine credentials; legacy tokens receive one 90-day rotation window."""

from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision = "0045_machine_expiry"
down_revision = "0044_personal_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("identity_credentials", sa.Column("expires_at", sa.DateTime(timezone=True)))
    credentials = sa.table(
        "identity_credentials", sa.column("expires_at", sa.DateTime(timezone=True))
    )
    op.execute(credentials.update().values(expires_at=datetime.now(UTC) + timedelta(days=90)))
    with op.batch_alter_table("identity_credentials") as batch:
        batch.alter_column("expires_at", existing_type=sa.DateTime(timezone=True), nullable=False)


def downgrade() -> None:
    # Digests/revocations survive. Old application code has no expiry guarantee.
    with op.batch_alter_table("identity_credentials") as batch:
        batch.drop_column("expires_at")
