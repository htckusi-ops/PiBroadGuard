from sqlalchemy import Column, Integer, String, DateTime, Date, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class VendorInformation(Base):
    __tablename__ = "vendor_information"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    support_end_date = Column(Date)
    security_update_policy = Column(Text)
    psirt_available = Column(Boolean)
    advisory_process = Column(Text)
    hardening_guide = Column(Boolean)
    security_contact = Column(String)
    notes = Column(Text)
    source_reference = Column(String)

    assessment = relationship("Assessment", back_populates="vendor_information")
