"""Add nmap_interface to scan_authorizations

Revision ID: 007
Revises: 006
Create Date: 2026-03-23
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = [c["name"] for c in inspector.get_columns("scan_authorizations")]
    if "nmap_interface" not in existing_cols:
        with op.batch_alter_table("scan_authorizations") as batch_op:
            batch_op.add_column(sa.Column("nmap_interface", sa.String, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan_authorizations") as batch_op:
        batch_op.drop_column("nmap_interface")
