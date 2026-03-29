from sqlalchemy import Column, Integer, String, DateTime, Date, Text
from sqlalchemy.sql import func
from app.core.database import Base


class IcsAdvisoryCache(Base):
    __tablename__ = "ics_advisory_cache"

    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(String, unique=True, index=True)  # e.g. "ICSA-24-011-01"
    title = Column(String)
    vendor = Column(String, index=True)
    product = Column(String)
    summary = Column(Text)
    cve_ids = Column(Text)          # JSON array: ["CVE-2024-1234", ...]
    cvss_score = Column(String)     # max CVSS score as string
    advisory_url = Column(String)
    published_date = Column(Date)
    updated_date = Column(Date)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
