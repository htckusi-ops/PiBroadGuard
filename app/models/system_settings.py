from sqlalchemy import Column, String, DateTime
from sqlalchemy.sql import func
from app.core.database import Base


class SystemSettings(Base):
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True)
    value = Column(String)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    updated_by = Column(String)
