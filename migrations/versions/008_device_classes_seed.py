"""Replace over-granular device_class seed with 6 broad architectural categories.

The original migration 008 seeded device_classes at the same level as device_types
(encoder, decoder, etc.) which was redundant. This replaces them with 6 high-level
categories that serve as architectural/risk-scoring context:

  broadcast   – All broadcast/media production equipment
  it          – Standard IT infrastructure (switches, servers, firewalls…)
  ot_ics      – Operational technology / industrial control systems
  av_pro      – Professional AV (non-broadcast, e.g. conference, digital signage)
  iot         – Internet-of-Things devices
  other       – Uncategorised

The original 005 seed (broadcast, network, server, camera, client, printer, other)
is updated with better labels and the granular 008 entries are removed.

Revision ID: 008
Revises: 007
Create Date: 2026-03-23
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None

# Broad categories – these complement (not duplicate) device_types
BROAD_CLASSES = [
    # name           label_de                             label_en                         sort
    ("broadcast",    "Broadcast / Medientechnik",         "Broadcast / Media Production",  0),
    ("it",           "IT-Infrastruktur",                  "IT Infrastructure",             1),
    ("ot_ics",       "OT / ICS (Betriebstechnik)",        "OT / ICS (Operational Tech)",   2),
    ("av_pro",       "Professionelles AV",                "Professional AV",               3),
    ("iot",          "IoT-Gerät",                         "IoT Device",                    4),
    ("other",        "Sonstiges",                         "Other",                         5),
]

# Granular names inserted by the previous (wrong) version of this migration
OLD_GRANULAR = [
    "encoder", "decoder", "matrix_router", "intercom", "multiviewer", "playout",
    "ingest", "transcoder", "signal_processor", "frame_sync", "clock_sync",
    "audio_device", "broadcast_camera", "monitor_display",
    "switch", "router_it", "firewall", "it_server", "storage", "ip_kvm",
    "workstation", "access_point", "ups_pdu", "it_camera",
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    if "device_classes" not in inspector.get_table_names():
        return

    # Remove granular entries that duplicate device_types (if they were already inserted)
    if OLD_GRANULAR:
        placeholders = ", ".join(f"'{n}'" for n in OLD_GRANULAR)
        op.execute(sa.text(f"DELETE FROM device_classes WHERE name IN ({placeholders})"))

    # Update labels of the original 005 seed entries to be cleaner
    label_updates = {
        "broadcast": ("Broadcast / Medientechnik", "Broadcast / Media Production"),
        "network":   ("Netzwerkgerät",              "Network Device"),
        "server":    ("Server / Appliance",         "Server / Appliance"),
        "camera":    ("Kamera (allgemein)",         "Camera (general)"),
        "client":    ("Client / Workstation",       "Client / Workstation"),
        "printer":   ("Drucker / Scanner",          "Printer / Scanner"),
        "other":     ("Sonstiges",                  "Other"),
    }
    for name, (de, en) in label_updates.items():
        op.execute(sa.text(
            f"UPDATE device_classes SET label_de=:de, label_en=:en WHERE name=:n"
        ).bindparams(de=de, en=en, n=name))

    tbl = sa.table(
        "device_classes",
        sa.column("name", sa.String),
        sa.column("label_de", sa.String),
        sa.column("label_en", sa.String),
        sa.column("sort_order", sa.Integer),
        sa.column("active", sa.Boolean),
    )
    existing = {row[0] for row in bind.execute(sa.text("SELECT name FROM device_classes")).fetchall()}
    rows = [
        {"name": n, "label_de": de, "label_en": en, "sort_order": so, "active": True}
        for n, de, en, so in BROAD_CLASSES
        if n not in existing
    ]
    if rows:
        op.bulk_insert(tbl, rows)


def downgrade() -> None:
    names = [n for n, *_ in BROAD_CLASSES if n != "other"]
    if names:
        placeholders = ", ".join(f"'{n}'" for n in names)
        op.execute(sa.text(f"DELETE FROM device_classes WHERE name IN ({placeholders})"))
