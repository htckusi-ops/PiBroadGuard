"""Add scan_profiles table with 4 built-in profiles

Revision ID: 006
Revises: 005
Create Date: 2026-03-23
"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BUILT_IN_PROFILES = [
    {
        "name": "passive",
        "label": "Passive",
        "description": (
            "Schonender Scan bekannter Broadcast-Ports (ST 2110, SNMP, Modbus, RTSP …). "
            "Empfohlen für produktive Geräte. -T2, ~20 Ports."
        ),
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sV", "--version-light", "-T2",
            "-p", "21,22,23,25,53,80,102,161,443,502,554,623,1194,1883,2222,4840,8080,8443,9100,47808",
        ]),
        "timeout_seconds": 300,
    },
    {
        "name": "standard",
        "label": "Standard",
        "description": (
            "Normaler Assessment-Scan. Top 1000 TCP-Ports, T3, Version-Intensity 5."
        ),
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sV", "-T3", "--top-ports", "1000", "--version-intensity", "5",
        ]),
        "timeout_seconds": 300,
    },
    {
        "name": "extended",
        "label": "Extended",
        "description": (
            "TCP + UDP-Ports (SNMP, RTP, Discovery), T3, Version-Intensity 7. "
            "Dauert länger; UDP kann empfindliche Geräte belasten."
        ),
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sU", "-sV", "-T3",
            "-p", "T:1-1000,U:161,623,1194,1883,4840,47808",
            "--version-intensity", "7",
        ]),
        "timeout_seconds": 600,
    },
    {
        "name": "version_deep",
        "label": "Version Deep (CVSS)",
        "description": (
            "Intensiver Versionsfingerabdruck für CVE/CVSS-Bewertung. "
            "Führt NSE-Skripterkennung durch (banner, http-headers). "
            "NICHT für produktive Broadcast-Geräte empfohlen – nur in Wartungsfenstern."
        ),
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sV", "--version-intensity", "9",
            "-T3", "--top-ports", "1000",
            "-A", "--script", "banner,http-headers",
        ]),
        "timeout_seconds": 900,
    },
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)

    if "scan_profiles" in inspector.get_table_names():
        return

    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("label", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("nmap_flags", sa.Text, nullable=False),
        sa.Column("timeout_seconds", sa.Integer, default=300),
        sa.Column("built_in", sa.Boolean, default=False),
        sa.Column("active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    tbl = sa.table(
        "scan_profiles",
        sa.column("name", sa.Text),
        sa.column("label", sa.Text),
        sa.column("description", sa.Text),
        sa.column("nmap_flags", sa.Text),
        sa.column("timeout_seconds", sa.Integer),
        sa.column("built_in", sa.Boolean),
        sa.column("active", sa.Boolean),
    )
    op.bulk_insert(
        tbl,
        [
            {
                "name": p["name"],
                "label": p["label"],
                "description": p["description"],
                "nmap_flags": p["nmap_flags"],
                "timeout_seconds": p["timeout_seconds"],
                "built_in": True,
                "active": True,
            }
            for p in BUILT_IN_PROFILES
        ],
    )


def downgrade() -> None:
    op.drop_table("scan_profiles")
