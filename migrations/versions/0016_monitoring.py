"""Monitoring configuration, alert cycles, silences and maintenance windows."""

import sqlalchemy as sa
from alembic import op

revision = "0016_monitoring"
down_revision = "0015_maintenance_reminders"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "monitor_exporters",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("module", sa.String(64), nullable=False),
        sa.Column("address", sa.String(200)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("name", name="uq_monitor_exporter_name"),
    )
    op.create_table(
        "monitor_profiles",
        sa.Column("category", sa.String(64), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("check_type", sa.String(16)),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("thresholds", sa.JSON(), nullable=False),
        sa.Column("minimum_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("exporter_id", sa.String(36)),
        sa.Column("snmp_module", sa.String(64)),
        sa.Column("snmp_auth_ref", sa.String(64)),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "monitor_assets",
        sa.Column("asset_id", sa.String(36), primary_key=True),
        sa.Column("enabled", sa.Boolean()),
        sa.Column("check_type", sa.String(16)),
        sa.Column("target", sa.String(500)),
        sa.Column("interval_seconds", sa.Integer()),
        sa.Column("metrics", sa.JSON()),
        sa.Column("thresholds", sa.JSON()),
        sa.Column("minimum_duration_seconds", sa.Integer()),
        sa.Column("exporter_id", sa.String(36)),
        sa.Column("snmp_module", sa.String(64)),
        sa.Column("snmp_auth_ref", sa.String(64)),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "monitoring_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("alert_name", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("group_key", sa.String(256)),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("annotations", sa.JSON(), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("description", sa.Text()),
        sa.Column("starts_at", sa.DateTime(), nullable=False),
        sa.Column("ends_at", sa.DateTime()),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime()),
        sa.Column("acknowledged_by", sa.String(64)),
        sa.Column("acknowledged_notes", sa.Text()),
        sa.Column("incident_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("fingerprint", "starts_at", name="uq_monitoring_alert_cycle"),
    )
    op.create_index("ix_monitoring_alerts_asset_id", "monitoring_alerts", ["asset_id"])
    op.create_index("ix_monitoring_alerts_state", "monitoring_alerts", ["state"])
    op.create_table(
        "monitoring_alert_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("from_state", sa.String(16)),
        sa.Column("to_state", sa.String(16)),
        sa.Column("note", sa.Text()),
        sa.Column("changes", sa.JSON()),
        sa.Column("actor_id", sa.String(36)),
        sa.Column("actor_username", sa.String(64)),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("event_key", sa.String(255)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("alert_id", "event_key", name="uq_monitoring_alert_event_key"),
    )
    op.create_index("ix_monitoring_alert_events_alert_id", "monitoring_alert_events", ["alert_id"])
    op.create_table(
        "monitoring_silences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36)),
        sa.Column("alert_id", sa.String(36)),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("starts_at", sa.DateTime(), nullable=False),
        sa.Column("ends_at", sa.DateTime(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("native_id", sa.String(64)),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_monitoring_silences_asset_id", "monitoring_silences", ["asset_id"])
    op.create_index("ix_monitoring_silences_alert_id", "monitoring_silences", ["alert_id"])
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("asset_ids", sa.JSON(), nullable=False),
        sa.Column("days_of_week", sa.JSON(), nullable=False),
        sa.Column("start_time", sa.String(5), nullable=False),
        sa.Column("end_time", sa.String(5), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(36)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("am_silence_id", sa.String(64)),
        sa.Column("am_occurrence_start", sa.DateTime()),
    )


def downgrade():
    op.drop_table("maintenance_windows")
    for name in ("ix_monitoring_silences_alert_id", "ix_monitoring_silences_asset_id"):
        op.drop_index(name, table_name="monitoring_silences")
    op.drop_table("monitoring_silences")
    op.drop_index("ix_monitoring_alert_events_alert_id", table_name="monitoring_alert_events")
    op.drop_table("monitoring_alert_events")
    for name in ("ix_monitoring_alerts_state", "ix_monitoring_alerts_asset_id"):
        op.drop_index(name, table_name="monitoring_alerts")
    op.drop_table("monitoring_alerts")
    op.drop_table("monitor_assets")
    op.drop_table("monitor_profiles")
    op.drop_table("monitor_exporters")
