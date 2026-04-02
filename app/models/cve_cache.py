from sqlalchemy import Column, Integer, String, DateTime, Date, Float, Text
from sqlalchemy.sql import func
from app.core.database import Base


class CveCache(Base):
    __tablename__ = "cve_cache"

    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String)
    product = Column(String)
    version = Column(String)
    cve_id = Column(String)
    cvss_score = Column(Float)
    description = Column(String)
    published_date = Column(Date)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
    # NVD enrichment fields (added migration 014)
    nvd_solution = Column(Text, nullable=True)
    vendor_advisory_url = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
