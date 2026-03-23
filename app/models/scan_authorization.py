from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ScanAuthorization(Base):
    __tablename__ = "scan_authorizations"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    authorized_by_name = Column(String, nullable=False)
    authorized_by_role = Column(String, nullable=False)
    authorized_by_contact = Column(String)
    authorization_date = Column(DateTime(timezone=True), nullable=False)
    scan_profile = Column(String, nullable=False)
    target_ip = Column(String, nullable=False)
    time_window_start = Column(DateTime(timezone=True))
    time_window_end = Column(DateTime(timezone=True))
    notes = Column(Text)
    nmap_interface = Column(String)  # None/"auto" = nmap decides; otherwise e.g. "eth0"
    confirmed_by_user = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    assessment = relationship("Assessment", back_populates="scan_authorization")
