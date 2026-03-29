"""Add ICS advisory cache table

Revision ID: 013
Revises: 012
Create Date: 2026-03-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ics_advisory_cache",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("advisory_id", sa.String, nullable=False, unique=True, index=True),
        sa.Column("title", sa.String),
        sa.Column("vendor", sa.String, index=True),
        sa.Column("product", sa.String),
        sa.Column("summary", sa.Text),
        sa.Column("cve_ids", sa.Text),           # JSON array
        sa.Column("cvss_score", sa.String),
        sa.Column("advisory_url", sa.String),
        sa.Column("published_date", sa.Date),
        sa.Column("updated_date", sa.Date),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("ics_advisory_cache")
