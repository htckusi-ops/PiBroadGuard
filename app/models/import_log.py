from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ImportLog(Base):
    __tablename__ = "import_log"

    id = Column(Integer, primary_key=True, index=True)
    package_id = Column(String)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=True)
    imported_at = Column(DateTime(timezone=True), server_default=func.now())
    imported_by = Column(String)
    source_host = Column(String)
    package_checksum = Column(String)
    status = Column(String)
    error_message = Column(String)
