"""Extend cve_cache and findings with enrichment fields (NVD, KEV, EPSS, ICS)

Revision ID: 014
Revises: 013
Create Date: 2026-04-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # cve_cache: add NVD enrichment fields that were returned by _fetch_from_nvd
    # but not persisted (only cve_id/cvss_score/description/published_date/fetched_at were stored)
    with op.batch_alter_table("cve_cache") as batch_op:
        batch_op.add_column(sa.Column("nvd_solution", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("vendor_advisory_url", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("cwe_id", sa.String(), nullable=True))

    # findings: add EPSS scores and ICS advisory reference
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("epss_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("epss_percentile", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("ics_advisory_ids", sa.Text(), nullable=True))  # JSON list


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("ics_advisory_ids")
        batch_op.drop_column("epss_percentile")
        batch_op.drop_column("epss_score")

    with op.batch_alter_table("cve_cache") as batch_op:
        batch_op.drop_column("cwe_id")
        batch_op.drop_column("vendor_advisory_url")
        batch_op.drop_column("nvd_solution")
