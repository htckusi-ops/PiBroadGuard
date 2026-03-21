from sqlalchemy import Column, Integer, String, DateTime, Date, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    status = Column(String, default="draft")
    scan_profile = Column(String)
    overall_rating = Column(String)
    technical_score = Column(Integer, default=100)
    operational_score = Column(Integer, default=100)
    compensation_score = Column(Integer, default=100)
    lifecycle_score = Column(Integer, default=100)
    vendor_score = Column(Integer, default=100)
    reviewer = Column(String)
    summary = Column(String)
    decision = Column(String)
    decision_notes = Column(String)
    reassessment_due = Column(Date)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    device = relationship("Device", back_populates="assessments")
    scan_results = relationship("ScanResult", back_populates="assessment")
    findings = relationship("Finding", back_populates="assessment")
    manual_findings = relationship("ManualFinding", back_populates="assessment")
    vendor_information = relationship("VendorInformation", back_populates="assessment", uselist=False)
    audit_logs = relationship("AuditLog", back_populates="assessment")
    scan_authorization = relationship("ScanAuthorization", back_populates="assessment", uselist=False)
    action_items = relationship("ActionItem", back_populates="assessment")
