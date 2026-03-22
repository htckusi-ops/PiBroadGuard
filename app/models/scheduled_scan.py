from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    apscheduler_job_id = Column(Text, unique=True, nullable=False)

    # Trigger type: "once" | "interval" | "cron"
    trigger_type = Column(Text, nullable=False)

    # Once
    run_at = Column(DateTime, nullable=True)

    # Interval
    interval_unit = Column(Text, nullable=True)   # "hours" | "days" | "weeks" | "months"
    interval_value = Column(Integer, nullable=True)

    # Cron
    cron_expression = Column(Text, nullable=True)

    scan_profile = Column(Text, nullable=False, default="passive")
    authorized_by_name = Column(Text, nullable=False)
    authorized_by_role = Column(Text, nullable=False)

    active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(Text, nullable=True)  # "success" | "failed" | "skipped"
    next_run_at = Column(DateTime, nullable=True)
    run_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Text, nullable=True)

    device = relationship("Device", back_populates="scheduled_scans")
