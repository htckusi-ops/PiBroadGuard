"""Add device_classes table and device_class_id FK on devices

Revision ID: 005
Revises: 004
Create Date: 2026-03-23
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEVICE_CLASSES_SEED = [
    ("broadcast",  "Broadcast-Gerät",          "Broadcast Device",       0),
    ("network",    "Netzwerkgerät",             "Network Device",         1),
    ("server",     "Server / Appliance",        "Server / Appliance",     2),
    ("camera",     "Kamera",                    "Camera",                 3),
    ("client",     "Client / Workstation",      "Client / Workstation",   4),
    ("printer",    "Drucker / Scanner",         "Printer / Scanner",      5),
    ("other",      "Sonstiges",                 "Other",                  6),
]


def upgrade() -> None:
    op.create_table(
        "device_classes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String, nullable=False, unique=True),
        sa.Column("label_de", sa.String, nullable=False),
        sa.Column("label_en", sa.String, nullable=False),
        sa.Column("sort_order", sa.Integer, default=0),
        sa.Column("active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    tbl = sa.table(
        "device_classes",
        sa.column("name", sa.String),
        sa.column("label_de", sa.String),
        sa.column("label_en", sa.String),
        sa.column("sort_order", sa.Integer),
        sa.column("active", sa.Boolean),
    )
    op.bulk_insert(
        tbl,
        [
            {"name": n, "label_de": de, "label_en": en, "sort_order": i, "active": True}
            for n, de, en, i in DEVICE_CLASSES_SEED
        ],
    )

    op.add_column(
        "devices",
        sa.Column("device_class_id", sa.Integer, sa.ForeignKey("device_classes.id"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("devices", "device_class_id")
    op.drop_table("device_classes")
