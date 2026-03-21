from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=True)
    user = Column(String)
    action = Column(String)
    field_name = Column(String)
    old_value = Column(String)
    new_value = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    assessment = relationship("Assessment", back_populates="audit_logs")
