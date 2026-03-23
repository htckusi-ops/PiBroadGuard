"""Expand device_classes with IT and Broadcast entries

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

# (name, label_de, label_en, sort_order)
NEW_CLASSES = [
    # ── Broadcast ──────────────────────────────────────────────────────────────
    ("encoder",          "Encoder",                           "Encoder",                      10),
    ("decoder",          "Decoder",                           "Decoder",                      11),
    ("matrix_router",    "Matrix Router / Kreuzschiene",      "Matrix Router",                12),
    ("intercom",         "Intercom-System",                   "Intercom System",              13),
    ("multiviewer",      "Multiviewer",                       "Multiviewer",                  14),
    ("playout",          "Playout-Server",                    "Playout Server",               15),
    ("ingest",           "Ingest / Aufnahme",                 "Ingest / Recorder",            16),
    ("transcoder",       "Transcoder",                        "Transcoder",                   17),
    ("signal_processor", "Signalprozessor",                   "Signal Processor",             18),
    ("frame_sync",       "Bildsynchronisierer",               "Frame Synchronizer",           19),
    ("clock_sync",       "Sync-Referenz / Taktgeber",         "Sync Reference / Clock",       20),
    ("audio_device",     "Audio-Gerät (Mischpult / DSP)",     "Audio Device (Mixer / DSP)",   21),
    ("broadcast_camera", "Broadcast-Kamera",                  "Broadcast Camera",             22),
    ("monitor_display",  "Monitor / Videowall",               "Monitor / Video Wall",         23),
    # ── IT ─────────────────────────────────────────────────────────────────────
    ("switch",           "Netzwerk-Switch",                   "Network Switch",               30),
    ("router_it",        "Router",                            "Router",                       31),
    ("firewall",         "Firewall / UTM",                    "Firewall / UTM",               32),
    ("it_server",        "Server",                            "Server",                       33),
    ("storage",          "Storage / NAS / SAN",               "Storage / NAS / SAN",          34),
    ("ip_kvm",           "IP-KVM",                            "IP KVM",                       35),
    ("workstation",      "Workstation / PC",                  "Workstation / PC",             36),
    ("access_point",     "WLAN Access Point",                 "Wireless Access Point",        37),
    ("ups_pdu",          "USV / PDU",                         "UPS / PDU",                    38),
    ("it_camera",        "IP-Kamera (Überwachung)",           "IP Camera (Surveillance)",     39),
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    if "device_classes" not in inspector.get_table_names():
        return  # table not yet created – skip (migration 005 handles creation)

    tbl = sa.table(
        "device_classes",
        sa.column("name", sa.String),
        sa.column("label_de", sa.String),
        sa.column("label_en", sa.String),
        sa.column("sort_order", sa.Integer),
        sa.column("active", sa.Boolean),
    )

    # Fetch existing names to avoid duplicate-name constraint violations
    existing = {row[0] for row in bind.execute(sa.text("SELECT name FROM device_classes")).fetchall()}

    rows_to_insert = [
        {"name": n, "label_de": de, "label_en": en, "sort_order": so, "active": True}
        for n, de, en, so in NEW_CLASSES
        if n not in existing
    ]
    if rows_to_insert:
        op.bulk_insert(tbl, rows_to_insert)


def downgrade() -> None:
    names = [n for n, *_ in NEW_CLASSES]
    placeholders = ", ".join(f"'{n}'" for n in names)
    op.execute(sa.text(f"DELETE FROM device_classes WHERE name IN ({placeholders})"))
