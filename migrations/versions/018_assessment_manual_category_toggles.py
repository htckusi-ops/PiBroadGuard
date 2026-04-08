"""Add assessment-level toggles for optional manual question categories

Revision ID: 018
Revises: 017
Create Date: 2026-04-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "018"
down_revision: Union[str, None] = "017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.add_column(sa.Column("manual_nmos_enabled", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("manual_ptp_enabled", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("manual_network_arch_enabled", sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.drop_column("manual_network_arch_enabled")
        batch_op.drop_column("manual_ptp_enabled")
        batch_op.drop_column("manual_nmos_enabled")
