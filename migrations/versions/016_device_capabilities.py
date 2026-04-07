"""Add extensible device capabilities and NMOS metadata fields

Revision ID: 016
Revises: 015
Create Date: 2026-04-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "016"
down_revision: Union[str, None] = "015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.add_column(sa.Column("device_capabilities_json", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("nmos_registry_url", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("nmos_node_api_url", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("nmos_connection_api_url", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.drop_column("nmos_connection_api_url")
        batch_op.drop_column("nmos_node_api_url")
        batch_op.drop_column("nmos_registry_url")
        batch_op.drop_column("device_capabilities_json")
