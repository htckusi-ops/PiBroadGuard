from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    port = Column(Integer)
    protocol = Column(String)
    service_name = Column(String)
    service_product = Column(String)
    service_version = Column(String)
    state = Column(String)
    extra_info = Column(String)
    raw_nmap_output = Column(Text)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

    assessment = relationship("Assessment", back_populates="scan_results")
