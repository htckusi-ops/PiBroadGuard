"""Add NMOS & Broadcast scan profiles

Revision ID: 012
Revises: 011
Create Date: 2026-03-29
"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect, text

revision: str = "012"
down_revision: Union[str, None] = "011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_PROFILES = [
    {
        "name": "nmos_broadcast",
        "label": "NMOS & Broadcast",
        "description": (
            "Zielt auf NMOS IS-04/05/10 Registry-Ports (HTTP 8080, HTTPS 8443), "
            "PTP/ST 2059 (UDP 319/320), SSDP (UDP 1900) und mDNS (UDP 5353). "
            "Erkennt fehlende TLS-Absicherung und unsichere Discovery-Dienste. "
            "Empfohlen für NMOS-fähige Encoder, Decoder und Matrizen. "
            "Tiefergehende Compliance-Tests (BCP-003-01, IS-10) erfordern "
            "das AMWA nmos-testing Tool in einer isolierten Testumgebung."
        ),
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sU", "-sV", "--version-light", "-T2",
            "-p", "T:80,443,554,8080,8443,8010,8011,U:319,320,1900,5353",
            "--max-retries", "1",
        ]),
        "timeout_seconds": 300,
        "built_in": True,
        "active": True,
        "is_discovery": False,
    },
    {
        "name": "nmos_discovery",
        "label": "NMOS Discovery",
        "description": (
            "Discovery-Scan für NMOS-Geräte: erkennt NMOS-Registry (8080/8443), "
            "PTP-Ports (UDP 319/320) und Discovery-Protokolle (SSDP/mDNS). "
            "Kein Regelwerk, kein CVE-Lookup, kein Scoring – nur Bestandsaufnahme. "
            "Scan-Seiteneffekte (Reboots, Signalstörungen) werden im Findings-Tab dokumentiert."
        ),
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sU", "-sV", "--version-light", "-T2",
            "-p", "T:80,443,8080,8443,U:319,320,1900,5353",
            "--max-retries", "1",
        ]),
        "timeout_seconds": 180,
        "built_in": True,
        "active": True,
        "is_discovery": True,
    },
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)

    if "scan_profiles" not in inspector.get_table_names():
        return

    # Check if is_discovery column exists (added in migration 011)
    cols = [c["name"] for c in inspector.get_columns("scan_profiles")]
    has_is_discovery = "is_discovery" in cols

    for profile in NEW_PROFILES:
        existing = bind.execute(
            text("SELECT id FROM scan_profiles WHERE name = :name"),
            {"name": profile["name"]},
        ).fetchone()
        if existing:
            continue

        if not has_is_discovery:
            profile_data = {k: v for k, v in profile.items() if k != "is_discovery"}
        else:
            profile_data = profile

        columns = ", ".join(profile_data.keys())
        placeholders = ", ".join(f":{k}" for k in profile_data.keys())
        bind.execute(
            text(f"INSERT INTO scan_profiles ({columns}) VALUES ({placeholders})"),
            profile_data,
        )


def downgrade() -> None:
    bind = op.get_bind()
    for profile in NEW_PROFILES:
        bind.execute(
            text("DELETE FROM scan_profiles WHERE name = :name AND built_in = 1"),
            {"name": profile["name"]},
        )
