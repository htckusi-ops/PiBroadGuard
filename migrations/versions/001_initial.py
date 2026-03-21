"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-21
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("manufacturer", sa.String, nullable=False),
        sa.Column("model", sa.String, nullable=False),
        sa.Column("device_type", sa.String, nullable=False),
        sa.Column("serial_number", sa.String),
        sa.Column("asset_tag", sa.String),
        sa.Column("hostname", sa.String),
        sa.Column("ip_address", sa.String, nullable=False),
        sa.Column("firmware_version", sa.String),
        sa.Column("location", sa.String),
        sa.Column("network_segment", sa.String),
        sa.Column("production_criticality", sa.String),
        sa.Column("owner_team", sa.String),
        sa.Column("notes", sa.String),
        sa.Column("deleted", sa.Boolean, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "assessments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("status", sa.String, default="draft"),
        sa.Column("scan_profile", sa.String),
        sa.Column("overall_rating", sa.String),
        sa.Column("technical_score", sa.Integer, default=100),
        sa.Column("operational_score", sa.Integer, default=100),
        sa.Column("compensation_score", sa.Integer, default=100),
        sa.Column("lifecycle_score", sa.Integer, default=100),
        sa.Column("vendor_score", sa.Integer, default=100),
        sa.Column("reviewer", sa.String),
        sa.Column("summary", sa.String),
        sa.Column("decision", sa.String),
        sa.Column("decision_notes", sa.String),
        sa.Column("reassessment_due", sa.Date),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "scan_results",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("port", sa.Integer),
        sa.Column("protocol", sa.String),
        sa.Column("service_name", sa.String),
        sa.Column("service_product", sa.String),
        sa.Column("service_version", sa.String),
        sa.Column("state", sa.String),
        sa.Column("extra_info", sa.String),
        sa.Column("raw_nmap_output", sa.Text),
        sa.Column("scanned_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("rule_key", sa.String),
        sa.Column("title", sa.String),
        sa.Column("severity", sa.String),
        sa.Column("description", sa.Text),
        sa.Column("evidence", sa.Text),
        sa.Column("recommendation", sa.Text),
        sa.Column("broadcast_context", sa.Text),
        sa.Column("compensating_control_required", sa.Boolean, default=False),
        sa.Column("compensating_control_description", sa.Text),
        sa.Column("status", sa.String, default="open"),
        sa.Column("cve_id", sa.String),
        sa.Column("cvss_score", sa.String),
        sa.Column("cwe_id", sa.String),
        sa.Column("kev_listed", sa.Boolean, default=False),
        sa.Column("kev_required_action", sa.Text),
        sa.Column("nvd_solution", sa.Text),
        sa.Column("vendor_advisory_url", sa.String),
        sa.Column("cwe_recommendation", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "manual_findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("category", sa.String),
        sa.Column("question_key", sa.String),
        sa.Column("answer_value", sa.String),
        sa.Column("comment", sa.Text),
        sa.Column("source", sa.String),
    )

    op.create_table(
        "vendor_information",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("support_end_date", sa.Date),
        sa.Column("security_update_policy", sa.Text),
        sa.Column("psirt_available", sa.Boolean),
        sa.Column("advisory_process", sa.Text),
        sa.Column("hardening_guide", sa.Boolean),
        sa.Column("security_contact", sa.String),
        sa.Column("notes", sa.Text),
        sa.Column("source_reference", sa.String),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=True),
        sa.Column("user", sa.String),
        sa.Column("action", sa.String),
        sa.Column("field_name", sa.String),
        sa.Column("old_value", sa.String),
        sa.Column("new_value", sa.String),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "cve_cache",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("vendor", sa.String),
        sa.Column("product", sa.String),
        sa.Column("version", sa.String),
        sa.Column("cve_id", sa.String),
        sa.Column("cvss_score", sa.Float),
        sa.Column("description", sa.String),
        sa.Column("published_date", sa.Date),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "kev_cache",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("cve_id", sa.String, unique=True),
        sa.Column("vendor_project", sa.String),
        sa.Column("product", sa.String),
        sa.Column("vulnerability_name", sa.String),
        sa.Column("required_action", sa.String),
        sa.Column("due_date", sa.Date),
        sa.Column("known_ransomware", sa.Boolean, default=False),
        sa.Column("date_added_to_kev", sa.Date),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "scan_authorizations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("authorized_by_name", sa.String, nullable=False),
        sa.Column("authorized_by_role", sa.String, nullable=False),
        sa.Column("authorized_by_contact", sa.String),
        sa.Column("authorization_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_profile", sa.String, nullable=False),
        sa.Column("target_ip", sa.String, nullable=False),
        sa.Column("time_window_start", sa.DateTime(timezone=True)),
        sa.Column("time_window_end", sa.DateTime(timezone=True)),
        sa.Column("notes", sa.Text),
        sa.Column("confirmed_by_user", sa.String, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "import_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("package_id", sa.String),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("imported_by", sa.String),
        sa.Column("source_host", sa.String),
        sa.Column("package_checksum", sa.String),
        sa.Column("status", sa.String),
        sa.Column("error_message", sa.String),
    )

    op.create_table(
        "action_items",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("assessment_id", sa.Integer, sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("title", sa.String),
        sa.Column("description", sa.Text),
        sa.Column("responsible_team", sa.String),
        sa.Column("priority", sa.String),
        sa.Column("due_date", sa.Date),
        sa.Column("status", sa.String, default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "system_settings",
        sa.Column("key", sa.String, primary_key=True),
        sa.Column("value", sa.String),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.Column("updated_by", sa.String),
    )


def downgrade() -> None:
    for table in [
        "system_settings", "action_items", "import_log",
        "scan_authorizations", "kev_cache", "cve_cache",
        "audit_log", "vendor_information", "manual_findings",
        "findings", "scan_results", "assessments", "devices",
    ]:
        op.drop_table(table)
