"""Add is_discovery to scan_profiles, scan_mode to assessments

Revision ID: 011
Revises: 010
Create Date: 2026-03-26
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _col_exists(inspector, table, col):
    return any(c["name"] == col for c in inspector.get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)

    # Add is_discovery to scan_profiles
    if "scan_profiles" in inspector.get_table_names():
        if not _col_exists(inspector, "scan_profiles", "is_discovery"):
            op.add_column(
                "scan_profiles",
                sa.Column("is_discovery", sa.Boolean, nullable=False, server_default="0"),
            )

    # Add scan_mode to assessments
    if "assessments" in inspector.get_table_names():
        if not _col_exists(inspector, "assessments", "scan_mode"):
            op.add_column(
                "assessments",
                sa.Column("scan_mode", sa.String, nullable=True, server_default="assessment"),
            )

    # Mark the built-in "passive" profile as a discovery profile candidate
    # (is_discovery stays False for all built-ins — admins can create dedicated discovery profiles)
    # Nothing to seed here; users create discovery profiles via the UI.


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)

    if "scan_profiles" in inspector.get_table_names():
        if _col_exists(inspector, "scan_profiles", "is_discovery"):
            op.drop_column("scan_profiles", "is_discovery")

    if "assessments" in inspector.get_table_names():
        if _col_exists(inspector, "assessments", "scan_mode"):
            op.drop_column("assessments", "scan_mode")
