"""v1.5 extensions: rdns, mac, phpipam, device_types, remediation_sources, scan metadata

Revision ID: 002
Revises: 001
Create Date: 2026-03-21
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEVICE_TYPES_SEED = [
    "encoder", "decoder", "matrix", "intercom", "router", "switch",
    "camera", "monitor", "multiviewer", "playout", "transcoder",
    "signal_processor", "frame_sync", "other",
]


def upgrade() -> None:
    # --- devices: new fields ---
    op.add_column("devices", sa.Column("rdns_hostname", sa.String, nullable=True))
    op.add_column("devices", sa.Column("mac_address", sa.String, nullable=True))
    op.add_column("devices", sa.Column("mac_vendor", sa.String, nullable=True))
    op.add_column("devices", sa.Column("phpipam_id", sa.Integer, nullable=True))
    op.add_column("devices", sa.Column("phpipam_synced_at", sa.DateTime(timezone=True), nullable=True))

    # --- findings: remediation_sources JSON array ---
    op.add_column("findings", sa.Column("remediation_sources", sa.Text, nullable=True))

    # --- scan_results: metadata fields ---
    op.add_column("scan_results", sa.Column("scan_duration_seconds", sa.Float, nullable=True))
    op.add_column("scan_results", sa.Column("nmap_exit_code", sa.Integer, nullable=True))
    op.add_column("scan_results", sa.Column("nmap_version", sa.String, nullable=True))
    op.add_column("scan_results", sa.Column("total_ports_scanned", sa.Integer, nullable=True))

    # --- device_types table ---
    op.create_table(
        "device_types",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String, nullable=False, unique=True),
        sa.Column("label_de", sa.String, nullable=False),
        sa.Column("label_en", sa.String, nullable=False),
        sa.Column("sort_order", sa.Integer, default=0),
        sa.Column("active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Seed device types
    device_types_table = sa.table(
        "device_types",
        sa.column("name", sa.String),
        sa.column("label_de", sa.String),
        sa.column("label_en", sa.String),
        sa.column("sort_order", sa.Integer),
        sa.column("active", sa.Boolean),
    )
    label_map = {
        "encoder": ("Encoder", "Encoder"),
        "decoder": ("Decoder", "Decoder"),
        "matrix": ("Matrix / Router", "Matrix / Router"),
        "intercom": ("Intercom", "Intercom"),
        "router": ("IP-Router", "IP Router"),
        "switch": ("Switch", "Switch"),
        "camera": ("Kamera", "Camera"),
        "monitor": ("Monitor / Display", "Monitor / Display"),
        "multiviewer": ("Multiviewer", "Multiviewer"),
        "playout": ("Playout-Server", "Playout Server"),
        "transcoder": ("Transcoder", "Transcoder"),
        "signal_processor": ("Signalprozessor", "Signal Processor"),
        "frame_sync": ("Frame Synchroniser", "Frame Synchronizer"),
        "other": ("Sonstiges", "Other"),
    }
    op.bulk_insert(
        device_types_table,
        [
            {"name": k, "label_de": v[0], "label_en": v[1], "sort_order": i, "active": True}
            for i, (k, v) in enumerate(label_map.items())
        ],
    )


def downgrade() -> None:
    op.drop_table("device_types")
    op.drop_column("scan_results", "total_ports_scanned")
    op.drop_column("scan_results", "nmap_version")
    op.drop_column("scan_results", "nmap_exit_code")
    op.drop_column("scan_results", "scan_duration_seconds")
    op.drop_column("findings", "remediation_sources")
    op.drop_column("devices", "phpipam_synced_at")
    op.drop_column("devices", "phpipam_id")
    op.drop_column("devices", "mac_vendor")
    op.drop_column("devices", "mac_address")
    op.drop_column("devices", "rdns_hostname")
