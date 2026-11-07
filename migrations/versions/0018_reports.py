"""reports

Revision ID: 0018_reports
Revises: 0017_notifications
Create Date: 2026-10-23

Report templates, branding/settings, durable report jobs, document metadata
(opaque blob keys only) and revocable public share digests. This revision also
grants the new independent ``reports.share`` capability to the administrator
role; it is not implied by any existing permission.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0018_reports"
down_revision = "0017_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_templates",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("family", sa.String(length=16), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "report_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(length=160), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "report_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("executor", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("processed", sa.Integer(), nullable=False),
        sa.Column("errors", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_report_jobs_owner_id", "report_jobs", ["owner_id"])
    op.create_index("ix_report_jobs_status", "report_jobs", ["status"])
    op.create_table(
        "report_documents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(length=36),
            sa.ForeignKey("report_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=180), nullable=False),
        sa.Column("mime", sa.String(length=120), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("blob_key", sa.String(length=32), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delete_error", sa.String(length=200), nullable=True),
        sa.UniqueConstraint("blob_key", name="uq_report_documents_blob_key"),
    )
    op.create_index("ix_report_documents_job_id", "report_documents", ["job_id"])
    op.create_index("ix_report_documents_owner_id", "report_documents", ["owner_id"])
    op.create_index("ix_report_documents_asset_id", "report_documents", ["asset_id"])
    op.create_table(
        "report_shares",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False),
        sa.Column("issuer_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_report_shares_asset_id", "report_shares", ["asset_id"])
    op.create_index("ix_report_shares_issuer_id", "report_shares", ["issuer_id"])

    policies = sa.table(
        "identity_role_policies",
        sa.column("role_id", sa.String),
        sa.column("resource", sa.String),
        sa.column("operation", sa.String),
    )
    op.bulk_insert(
        policies,
        [{"role_id": "admin", "resource": "reports", "operation": "share"}],
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DELETE FROM identity_role_policies "
            "WHERE role_id = 'admin' AND resource = 'reports' AND operation = 'share'"
        )
    )
    op.drop_index("ix_report_shares_issuer_id", table_name="report_shares")
    op.drop_index("ix_report_shares_asset_id", table_name="report_shares")
    op.drop_table("report_shares")
    op.drop_index("ix_report_documents_asset_id", table_name="report_documents")
    op.drop_index("ix_report_documents_owner_id", table_name="report_documents")
    op.drop_index("ix_report_documents_job_id", table_name="report_documents")
    op.drop_table("report_documents")
    op.drop_index("ix_report_jobs_status", table_name="report_jobs")
    op.drop_index("ix_report_jobs_owner_id", table_name="report_jobs")
    op.drop_table("report_jobs")
    op.drop_table("report_settings")
    op.drop_table("report_templates")
