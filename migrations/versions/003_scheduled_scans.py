"""Add scheduled_scans table

Revision ID: 003
Revises: 002
Create Date: 2026-03-22
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("apscheduler_job_id", sa.Text, unique=True, nullable=False),
        sa.Column("trigger_type", sa.Text, nullable=False),
        sa.Column("run_at", sa.DateTime, nullable=True),
        sa.Column("interval_unit", sa.Text, nullable=True),
        sa.Column("interval_value", sa.Integer, nullable=True),
        sa.Column("cron_expression", sa.Text, nullable=True),
        sa.Column("scan_profile", sa.Text, nullable=False, server_default="passive"),
        sa.Column("authorized_by_name", sa.Text, nullable=False),
        sa.Column("authorized_by_role", sa.Text, nullable=False),
        sa.Column("active", sa.Boolean, default=True),
        sa.Column("last_run_at", sa.DateTime, nullable=True),
        sa.Column("last_run_status", sa.Text, nullable=True),
        sa.Column("next_run_at", sa.DateTime, nullable=True),
        sa.Column("run_count", sa.Integer, default=0),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("created_by", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("scheduled_scans")
