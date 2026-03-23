"""Add start_hour/start_minute to scheduled_scans

Revision ID: 004
Revises: 003
Create Date: 2026-03-23
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scheduled_scans", sa.Column("start_hour", sa.Integer, nullable=True))
    op.add_column("scheduled_scans", sa.Column("start_minute", sa.Integer, nullable=True))


def downgrade() -> None:
    op.drop_column("scheduled_scans", "start_minute")
    op.drop_column("scheduled_scans", "start_hour")
