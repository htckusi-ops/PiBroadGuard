from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from app.core.database import Base


class DeviceClass(Base):
    __tablename__ = "device_classes"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)   # e.g. "broadcast"
    label_de = Column(String, nullable=False)
    label_en = Column(String, nullable=False)
    sort_order = Column(Integer, default=0)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
