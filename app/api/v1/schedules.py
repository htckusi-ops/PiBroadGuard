import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.device import Device
from app.models.scheduled_scan import ScheduledScan

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["schedules"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    device_id: int
    trigger_type: str               # "once" | "interval" | "cron"
    scan_profile: str = "passive"
    authorized_by_name: str
    authorized_by_role: str
    # once
    run_at: Optional[datetime] = None
    # interval
    interval_unit: Optional[str] = None   # "hours" | "days" | "weeks" | "months"
    interval_value: Optional[int] = None
    start_hour: Optional[int] = None      # time-of-day for interval/months
    start_minute: Optional[int] = None
    # cron
    cron_expression: Optional[str] = None


class ScheduleRead(BaseModel):
    id: int
    device_id: int
    device_name: Optional[str] = None
    trigger_type: str
    scan_profile: str
    authorized_by_name: str
    authorized_by_role: str
    active: bool
    run_at: Optional[datetime] = None
    interval_unit: Optional[str] = None
    interval_value: Optional[int] = None
    start_hour: Optional[int] = None
    start_minute: Optional[int] = None
    cron_expression: Optional[str] = None
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[str] = None
    next_run_at: Optional[datetime] = None
    run_count: int = 0
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


def _enrich_schedule(sched: ScheduledScan, db: Session) -> ScheduleRead:
    data = ScheduleRead.model_validate(sched)
    device = db.query(Device).filter(Device.id == sched.device_id).first()
    if device:
        data.device_name = f"{device.manufacturer} {device.model}"
    return data


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/schedules", response_model=List[ScheduleRead])
def list_schedules(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    from app.services.scheduler_service import update_next_run
    schedules = db.query(ScheduledScan).order_by(ScheduledScan.next_run_at).all()
    for s in schedules:
        update_next_run(db, s)
    return [_enrich_schedule(s, db) for s in schedules]


@router.get("/schedules/{schedule_id}", response_model=ScheduleRead)
def get_schedule(schedule_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    sched = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule nicht gefunden")
    return _enrich_schedule(sched, db)


@router.post("/schedules", response_model=ScheduleRead, status_code=201)
def create_schedule(
    body: ScheduleCreate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.core.config import settings
    from app.services import scheduler_service

    device = db.query(Device).filter(Device.id == body.device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")

    # Validate trigger params
    if body.trigger_type == "once" and not body.run_at:
        raise HTTPException(400, "run_at required for trigger_type=once")
    if body.trigger_type == "interval" and not (body.interval_unit and body.interval_value):
        raise HTTPException(400, "interval_unit and interval_value required for trigger_type=interval")
    if body.trigger_type == "cron" and not body.cron_expression:
        raise HTTPException(400, "cron_expression required for trigger_type=cron")

    try:
        sched = scheduler_service.create_schedule(
            db=db,
            device_id=body.device_id,
            trigger_type=body.trigger_type,
            scan_profile=body.scan_profile,
            authorized_by_name=body.authorized_by_name,
            authorized_by_role=body.authorized_by_role,
            db_url=settings.database_url,
            run_at=body.run_at,
            interval_unit=body.interval_unit,
            interval_value=body.interval_value,
            cron_expression=body.cron_expression,
            created_by=user,
            start_hour=body.start_hour,
            start_minute=body.start_minute,
        )
    except RuntimeError as e:
        raise HTTPException(503, f"Scheduler nicht verfügbar: {e}. Bitte App neu starten.")
    except Exception as e:
        logger.error(f"create_schedule failed: {e}", exc_info=True)
        raise HTTPException(500, f"Schedule konnte nicht erstellt werden: {e}")
    return _enrich_schedule(sched, db)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.services import scheduler_service
    sched = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule nicht gefunden")
    scheduler_service.delete_schedule(db, sched)


@router.post("/schedules/{schedule_id}/pause", status_code=200)
def pause_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.services import scheduler_service
    sched = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule nicht gefunden")
    scheduler_service.pause_schedule(db, sched)
    return {"status": "paused"}


@router.post("/schedules/{schedule_id}/resume", status_code=200)
def resume_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.services import scheduler_service
    sched = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule nicht gefunden")
    scheduler_service.resume_schedule(db, sched)
    return {"status": "active"}


@router.post("/schedules/{schedule_id}/run-now", status_code=200)
async def run_schedule_now(
    schedule_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Immediately trigger a scheduled scan (for testing)."""
    from app.services.scheduler_service import execute_scheduled_scan
    sched = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule nicht gefunden")
    import asyncio
    asyncio.create_task(execute_scheduled_scan(
        device_id=sched.device_id,
        scan_profile=sched.scan_profile,
        scheduled_scan_id=sched.id,
        authorized_by_name=sched.authorized_by_name,
        authorized_by_role=sched.authorized_by_role,
    ))
    return {"status": "triggered"}


@router.get("/devices/{device_id}/schedules", response_model=List[ScheduleRead])
def get_device_schedules(
    device_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.services.scheduler_service import update_next_run
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")
    schedules = db.query(ScheduledScan).filter(ScheduledScan.device_id == device_id).all()
    for s in schedules:
        update_next_run(db, s)
    return [_enrich_schedule(s, db) for s in schedules]
