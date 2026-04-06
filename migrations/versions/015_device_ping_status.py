"""Add per-device ping status fields

Revision ID: 015
Revises: 014
Create Date: 2026-04-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "015"
down_revision: Union[str, None] = "014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.add_column(sa.Column("last_ping_status", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("last_ping_checked_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_seen_ping_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_ping_rtt_ms", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.drop_column("last_ping_rtt_ms")
        batch_op.drop_column("last_seen_ping_at")
        batch_op.drop_column("last_ping_checked_at")
        batch_op.drop_column("last_ping_status")
