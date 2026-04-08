"""Add device operating system and recurring ping monitor fields

Revision ID: 017
Revises: 016
Create Date: 2026-04-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "017"
down_revision: Union[str, None] = "016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.add_column(sa.Column("operating_system", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("ping_monitor_enabled", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("ping_interval_minutes", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.drop_column("ping_interval_minutes")
        batch_op.drop_column("ping_monitor_enabled")
        batch_op.drop_column("operating_system")
