from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, Text

from app.core.database import Base


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(Text, nullable=False, unique=True)      # e.g. "passive"
    label = Column(Text, nullable=False)                   # e.g. "Passive"
    description = Column(Text, nullable=True)
    nmap_flags = Column(Text, nullable=False)              # JSON array as string
    timeout_seconds = Column(Integer, default=300)
    built_in = Column(Boolean, default=False)              # True = cannot delete flags
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
