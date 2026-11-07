"""Technical interventions, multi-asset incidents and assisted resolution."""

import sqlalchemy as sa
from alembic import op

revision = "0014_interventions"
down_revision = "0013_maintenance"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "technical_incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column(
            "primary_asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("responsible_person_id", sa.String(36)),
        sa.Column("opened_on", sa.Date(), nullable=False),
        sa.Column("resolved_at", sa.DateTime()),
        sa.Column("closed_at", sa.DateTime()),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("resolution_token", sa.String(64)),
        sa.Column("resolution_revision", sa.Integer()),
        sa.Column("resolution_prepared_at", sa.DateTime()),
        sa.Column("resolution_prepared_by", sa.String(64)),
        sa.Column("created_by", sa.String(36)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_technical_incidents_status", "technical_incidents", ["status"])
    op.create_index(
        "ix_technical_incidents_primary_asset_id",
        "technical_incidents",
        ["primary_asset_id"],
    )
    op.create_index(
        "ix_technical_incidents_responsible_person_id",
        "technical_incidents",
        ["responsible_person_id"],
    )
    op.create_table(
        "technical_incident_assets",
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("technical_incidents.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_technical_incident_assets_asset_id",
        "technical_incident_assets",
        ["asset_id"],
    )
    op.create_table(
        "technical_incident_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("technical_incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("from_status", sa.String(16)),
        sa.Column("to_status", sa.String(16)),
        sa.Column("note", sa.Text()),
        sa.Column("changes", sa.JSON()),
        sa.Column("actor_id", sa.String(36)),
        sa.Column("actor_username", sa.String(64)),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_technical_incident_events_incident_id",
        "technical_incident_events",
        ["incident_id"],
    )
    op.create_table(
        "technical_interventions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("technician_person_id", sa.String(36)),
        sa.Column("occurred_on", sa.Date(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text()),
        sa.Column("labor_cost", sa.String(16)),
        sa.Column("parts", sa.JSON(), nullable=False),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("technical_incidents.id", ondelete="RESTRICT"),
        ),
        sa.Column("plan_id", sa.String(36)),
        sa.Column("created_by", sa.String(36)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_technical_interventions_asset_id",
        "technical_interventions",
        ["asset_id"],
    )
    op.create_index(
        "ix_technical_interventions_technician_person_id",
        "technical_interventions",
        ["technician_person_id"],
    )
    op.create_index(
        "ix_technical_interventions_occurred_on",
        "technical_interventions",
        ["occurred_on"],
    )
    op.create_index(
        "ix_technical_interventions_incident_id",
        "technical_interventions",
        ["incident_id"],
    )
    op.create_index(
        "ix_technical_interventions_plan_id",
        "technical_interventions",
        ["plan_id"],
    )
    op.create_table(
        "technical_intervention_attachments",
        sa.Column(
            "intervention_id",
            sa.String(36),
            sa.ForeignKey("technical_interventions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "attachment_id",
            sa.String(36),
            sa.ForeignKey("asset_attachments.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_technical_intervention_attachments_attachment_id",
        "technical_intervention_attachments",
        ["attachment_id"],
    )


def downgrade():
    op.drop_index(
        "ix_technical_intervention_attachments_attachment_id",
        table_name="technical_intervention_attachments",
    )
    op.drop_table("technical_intervention_attachments")
    for name in (
        "ix_technical_interventions_plan_id",
        "ix_technical_interventions_incident_id",
        "ix_technical_interventions_occurred_on",
        "ix_technical_interventions_technician_person_id",
        "ix_technical_interventions_asset_id",
    ):
        op.drop_index(name, table_name="technical_interventions")
    op.drop_table("technical_interventions")
    op.drop_index(
        "ix_technical_incident_events_incident_id",
        table_name="technical_incident_events",
    )
    op.drop_table("technical_incident_events")
    op.drop_index("ix_technical_incident_assets_asset_id", table_name="technical_incident_assets")
    op.drop_table("technical_incident_assets")
    for name in (
        "ix_technical_incidents_responsible_person_id",
        "ix_technical_incidents_primary_asset_id",
        "ix_technical_incidents_status",
    ):
        op.drop_index(name, table_name="technical_incidents")
    op.drop_table("technical_incidents")
