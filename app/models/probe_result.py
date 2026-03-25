from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ProbeResult(Base):
    __tablename__ = "probe_results"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    profile_name = Column(String, nullable=False)
    profile_label = Column(String)
    status = Column(String, default="running")   # running | done | failed
    reachable = Column(String)                   # "yes" | "no" | "unknown"
    ports_json = Column(Text)                    # JSON list of port dicts
    raw_xml = Column(Text)
    scan_duration_seconds = Column(Float)
    nmap_exit_code = Column(Integer)
    nmap_version = Column(String)
    error_message = Column(Text)
    initiated_by = Column(String)               # username
    observations_json = Column(Text)            # JSON list of observation dicts
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))

    device = relationship("Device", back_populates="probes")
