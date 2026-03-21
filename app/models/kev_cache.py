from sqlalchemy import Column, Integer, String, DateTime, Date, Boolean
from sqlalchemy.sql import func
from app.core.database import Base


class KevCache(Base):
    __tablename__ = "kev_cache"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    vendor_project = Column(String)
    product = Column(String)
    vulnerability_name = Column(String)
    required_action = Column(String)
    due_date = Column(Date)
    known_ransomware = Column(Boolean, default=False)
    date_added_to_kev = Column(Date)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
