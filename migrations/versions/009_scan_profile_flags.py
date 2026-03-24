"""Improve built-in scan profile nmap flags

Changes per profile:
- passive:       add --max-retries 1 (prevents hanging on unresponsive OT devices)
- standard:      no flag changes (already safe; max-rate applied globally)
- extended:      add --max-retries 1 --defeat-icmp-ratelimit (safer UDP scanning)
- version_deep:  replace -A with targeted flags; use 'safe' NSE filter

Revision ID: 009
Revises: 008
Create Date: 2026-03-24
"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Updated flags per ChatGPT/NIST SP 800-115 / IEC 62443 recommendations
PROFILE_UPDATES = {
    "passive": {
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sV", "--version-light", "-T2",
            "-p", "21,22,23,25,53,80,102,161,443,502,554,623,1194,1883,2222,4840,8080,8443,9100,47808",
            "--max-retries", "1",
        ]),
        "description": (
            "Schonender Scan bekannter Broadcast-Ports (ST 2110, SNMP, Modbus, RTSP …). "
            "Empfohlen für produktive Geräte. -T2, ~20 Ports, max. 1 Retry. "
            "Entspricht NIST SP 800-115 'non-intrusive' / IEC 62443 'im Betrieb zulässig'."
        ),
    },
    "standard": {
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sV", "-T3", "--top-ports", "1000",
            "--version-intensity", "5",
            "--max-retries", "2",
        ]),
        "description": (
            "Normaler Assessment-Scan. Top 1000 TCP-Ports, T3, Version-Intensity 5. "
            "Für IT-Systeme und robuste Geräte geeignet. "
            "Rate-Limiting wird global via PIBG_NMAP_MAX_RATE gesteuert."
        ),
    },
    "extended": {
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sU", "-sV", "-T3",
            "-p", "T:1-1000,U:161,623,1194,1883,4840,47808",
            "--version-intensity", "7",
            "--max-retries", "1",
            "--defeat-icmp-ratelimit",
        ]),
        "description": (
            "TCP + gezielte UDP-Ports (SNMP, OPC UA, MQTT, BACnet), T3. "
            "max-retries 1 + defeat-icmp-ratelimit für sichereres UDP-Scanning. "
            "Vorsicht: UDP kann empfindliche Broadcast-Geräte belasten – "
            "nur in Wartungsfenstern empfohlen (BSI ICS / IEC 62443)."
        ),
    },
    "version_deep": {
        "nmap_flags": json.dumps([
            "-Pn", "-sT", "-sV", "--version-intensity", "9",
            "-T3", "--top-ports", "1000",
            "--script", "safe and (banner or http-headers)",
            "--osscan-limit",
        ]),
        "description": (
            "Intensiver Versionsfingerabdruck für CVE/CVSS-Bewertung. "
            "NSE-Scripts: nur 'safe'-Kategorie (banner, http-headers). "
            "--osscan-limit: OS-Detection nur wenn hohe Trefferwahrscheinlichkeit. "
            "Kein -A (verhindert Traceroute + aggressive Scripts). "
            "NICHT für produktive Broadcast-Geräte – nur in Wartungsfenstern."
        ),
    },
}


def upgrade() -> None:
    bind = op.get_bind()
    for name, updates in PROFILE_UPDATES.items():
        bind.execute(
            sa.text(
                "UPDATE scan_profiles SET nmap_flags = :flags, description = :desc "
                "WHERE name = :name AND built_in = 1"
            ),
            {"flags": updates["nmap_flags"], "desc": updates["description"], "name": name},
        )


def downgrade() -> None:
    # Restore original flags from migration 006
    original = {
        "passive": json.dumps([
            "-Pn", "-sT", "-sV", "--version-light", "-T2",
            "-p", "21,22,23,25,53,80,102,161,443,502,554,623,1194,1883,2222,4840,8080,8443,9100,47808",
        ]),
        "standard": json.dumps([
            "-Pn", "-sT", "-sV", "-T3", "--top-ports", "1000", "--version-intensity", "5",
        ]),
        "extended": json.dumps([
            "-Pn", "-sT", "-sU", "-sV", "-T3",
            "-p", "T:1-1000,U:161,623,1194,1883,4840,47808",
            "--version-intensity", "7",
        ]),
        "version_deep": json.dumps([
            "-Pn", "-sT", "-sV", "--version-intensity", "9",
            "-T3", "--top-ports", "1000",
            "-A", "--script", "banner,http-headers",
        ]),
    }
    bind = op.get_bind()
    for name, flags in original.items():
        bind.execute(
            sa.text("UPDATE scan_profiles SET nmap_flags = :flags WHERE name = :name AND built_in = 1"),
            {"flags": flags, "name": name},
        )
