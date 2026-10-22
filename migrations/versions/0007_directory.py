"""Directory: departments, people, hierarchical locations and their events.

Revision ID: 0007_directory
Revises: 0006_inventory_codes

Schema only; no seed rows. Sibling to ``0007_relationships`` from the
independent relations worker, so a later integration revision merges both
heads. An inventory person is never an access account: no credential, session
or identity reference is created here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_directory"
down_revision = "0006_inventory_codes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "directory_departments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("name_key", sa.String(120), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name_key", name="uq_directory_departments_name_key"),
    )
    op.create_table(
        "directory_locations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column(
            "parent_id",
            sa.String(36),
            sa.ForeignKey("directory_locations.id"),
            nullable=True,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("name_key", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=True),
        sa.Column("latitude", sa.String(24), nullable=True),
        sa.Column("longitude", sa.String(24), nullable=True),
        sa.Column("plan_ref", sa.String(64), nullable=True),
        sa.Column("plan_page", sa.String(32), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("parent_id", "name_key", name="uq_directory_locations_sibling_name"),
    )
    op.create_index("ix_directory_locations_level", "directory_locations", ["level"])
    op.create_index("ix_directory_locations_parent", "directory_locations", ["parent_id"])
    op.create_table(
        "directory_people",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("job_title", sa.String(120), nullable=True),
        sa.Column(
            "department_id",
            sa.String(36),
            sa.ForeignKey("directory_departments.id"),
            nullable=True,
        ),
        sa.Column("site_id", sa.String(36), sa.ForeignKey("directory_locations.id"), nullable=True),
        sa.Column("contact_email", sa.String(254), nullable=True),
        sa.Column("contact_phone", sa.String(40), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_directory_people_status", "directory_people", ["status"])
    op.create_index("ix_directory_people_department", "directory_people", ["department_id"])
    op.create_index("ix_directory_people_site", "directory_people", ["site_id"])
    op.create_table(
        "directory_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("entity", sa.String(16), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=True),
        sa.Column("actor_username", sa.String(64), nullable=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("before_snapshot", sa.JSON(), nullable=True),
        sa.Column("after_snapshot", sa.JSON(), nullable=True),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("notes", sa.String(1000), nullable=True),
    )
    op.create_index(
        "ix_directory_events_entity",
        "directory_events",
        ["entity", "entity_id", "recorded_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_directory_events_entity", table_name="directory_events")
    op.drop_table("directory_events")
    op.drop_index("ix_directory_people_site", table_name="directory_people")
    op.drop_index("ix_directory_people_department", table_name="directory_people")
    op.drop_index("ix_directory_people_status", table_name="directory_people")
    op.drop_table("directory_people")
    op.drop_index("ix_directory_locations_parent", table_name="directory_locations")
    op.drop_index("ix_directory_locations_level", table_name="directory_locations")
    op.drop_table("directory_locations")
    op.drop_table("directory_departments")
