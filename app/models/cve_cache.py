from sqlalchemy import Column, Integer, String, DateTime, Date, Float
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
