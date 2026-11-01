"""Add personal locale and installation i18n defaults.

``identity_identities.locale`` is the personal preference (``NULL`` follows the
installation). The singleton ``identity_security_settings`` row gains the
installation default locale, time zone and currency. No row is seeded: the
defaults are applied at read time, so an untouched installation behaves exactly
like one whose administrator saved the defaults.

Revision ID: 0038_i18n_preferences
Revises: 0037_ext_core_call_principal
"""

import sqlalchemy as sa
from alembic import op

revision = "0038_i18n_preferences"
down_revision = "0037_ext_core_call_principal"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("identity_identities") as batch:
        batch.add_column(sa.Column("locale", sa.String(length=35), nullable=True))
    with op.batch_alter_table("identity_security_settings") as batch:
        batch.add_column(
            sa.Column(
                "default_locale",
                sa.String(length=35),
                nullable=False,
                server_default="es",
            )
        )
        batch.add_column(
            sa.Column(
                "timezone",
                sa.String(length=64),
                nullable=False,
                server_default="America/Asuncion",
            )
        )
        batch.add_column(
            sa.Column(
                "currency",
                sa.String(length=3),
                nullable=False,
                server_default="PYG",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("identity_security_settings") as batch:
        batch.drop_column("currency")
        batch.drop_column("timezone")
        batch.drop_column("default_locale")
    with op.batch_alter_table("identity_identities") as batch:
        batch.drop_column("locale")
