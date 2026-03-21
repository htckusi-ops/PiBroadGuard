from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    rule_key = Column(String)
    title = Column(String)
    severity = Column(String)
    description = Column(Text)
    evidence = Column(Text)
    recommendation = Column(Text)
    broadcast_context = Column(Text)
    compensating_control_required = Column(Boolean, default=False)
    compensating_control_description = Column(Text)
    status = Column(String, default="open")
    cve_id = Column(String)
    cvss_score = Column(String)
    cwe_id = Column(String)
    kev_listed = Column(Boolean, default=False)
    kev_required_action = Column(Text)
    nvd_solution = Column(Text)
    vendor_advisory_url = Column(String)
    cwe_recommendation = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    assessment = relationship("Assessment", back_populates="findings")
