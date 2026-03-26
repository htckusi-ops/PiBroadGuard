"""Add probe_results table for device probes

Revision ID: 010
Revises: 009
Create Date: 2026-03-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "probe_results",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("profile_name", sa.String, nullable=False),
        sa.Column("profile_label", sa.String),
        sa.Column("status", sa.String, default="running"),
        sa.Column("reachable", sa.String),
        sa.Column("ports_json", sa.Text),
        sa.Column("raw_xml", sa.Text),
        sa.Column("scan_duration_seconds", sa.Float),
        sa.Column("nmap_exit_code", sa.Integer),
        sa.Column("nmap_version", sa.String),
        sa.Column("error_message", sa.Text),
        sa.Column("initiated_by", sa.String),
        sa.Column("observations_json", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_probe_results_device_id", "probe_results", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_probe_results_device_id", "probe_results")
    op.drop_table("probe_results")
