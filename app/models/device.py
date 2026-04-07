from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    manufacturer = Column(String, nullable=False)
    model = Column(String, nullable=False)
    device_type = Column(String, nullable=False)
    serial_number = Column(String)
    asset_tag = Column(String)
    hostname = Column(String)
    ip_address = Column(String, nullable=False)
    firmware_version = Column(String)
    location = Column(String)
    network_segment = Column(String)
    production_criticality = Column(String)
    owner_team = Column(String)
    notes = Column(String)
    device_capabilities_json = Column(Text)      # JSON list, e.g. ["nmos", "ptp"]
    nmos_registry_url = Column(String)
    nmos_node_api_url = Column(String)
    nmos_connection_api_url = Column(String)
    deleted = Column(Boolean, default=False)
    # v1.5 extensions
    rdns_hostname = Column(String)
    mac_address = Column(String)
    mac_vendor = Column(String)
    phpipam_id = Column(Integer)
    phpipam_synced_at = Column(DateTime(timezone=True))
    # v1.9 extension
    device_class_id = Column(Integer, ForeignKey("device_classes.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_ping_status = Column(String)            # "reachable" | "unreachable"
    last_ping_checked_at = Column(DateTime(timezone=True))
    last_seen_ping_at = Column(DateTime(timezone=True))
    last_ping_rtt_ms = Column(Integer)

    assessments = relationship("Assessment", back_populates="device")
    scheduled_scans = relationship("ScheduledScan", back_populates="device")
    probes = relationship("ProbeResult", back_populates="device")
