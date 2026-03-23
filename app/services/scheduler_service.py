import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

logger = logging.getLogger("pibroadguard.scheduler")

_scheduler = None


def get_scheduler():
    return _scheduler


def init_scheduler(db_url: str, timezone_str: str = "Europe/Zurich"):
    """Initialize APScheduler with SQLite job store. Jobs survive app restarts."""
    global _scheduler
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

        jobstores = {"default": SQLAlchemyJobStore(url=db_url)}
        _scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            timezone=timezone_str,
        )
        _scheduler.start()
        logger.info(f"APScheduler started with timezone={timezone_str}")
        return _scheduler
    except Exception as e:
        logger.error(f"Failed to start APScheduler: {e}")
        return None


def shutdown_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("APScheduler shut down")


async def execute_scheduled_scan(
    device_id: int,
    scan_profile: str,
    scheduled_scan_id: int,
    authorized_by_name: str,
    authorized_by_role: str,
):
    """
    Called by APScheduler when a scheduled scan is due.
    Creates a new assessment and enqueues it in the scan queue.
    """
    from app.core.database import SessionLocal
    from app.models.assessment import Assessment
    from app.models.scan_authorization import ScanAuthorization
    from app.models.device import Device
    from app.models.scheduled_scan import ScheduledScan
    from app.services.scan_queue_service import get_queue, ScanJob

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
        if not device:
            logger.error(f"Scheduled scan: device {device_id} not found")
            return

        # Create new assessment
        assessment = Assessment(
            device_id=device_id,
            scan_profile=scan_profile,
            status="draft",
        )
        db.add(assessment)
        db.flush()

        # Create scan authorization record
        auth = ScanAuthorization(
            assessment_id=assessment.id,
            authorized_by_name=authorized_by_name,
            authorized_by_role=authorized_by_role,
            authorization_date=datetime.now(timezone.utc),
            scan_profile=scan_profile,
            target_ip=device.ip_address,
            confirmed_by_user="scheduler",
            notes=f"Automatischer Scan (Schedule #{scheduled_scan_id})",
        )
        db.add(auth)
        assessment.status = "scan_running"
        db.commit()

        # Update schedule metadata
        sched = db.query(ScheduledScan).filter(ScheduledScan.id == scheduled_scan_id).first()
        if sched:
            sched.last_run_at = datetime.now(timezone.utc)
            sched.last_run_status = "running"
            sched.run_count = (sched.run_count or 0) + 1
            db.commit()

        logger.info(
            f"Scheduled scan #{scheduled_scan_id}: created assessment {assessment.id} for device {device_id}"
        )

        # Enqueue in scan queue
        queue = get_queue()
        if not queue:
            logger.error("Scan queue not initialized, cannot execute scheduled scan")
            assessment.status = "draft"
            db.commit()
            return

        job = ScanJob(
            job_id=f"schedule_{device_id}_{uuid4().hex[:6]}",
            assessment_id=assessment.id,
            device_id=device_id,
            ip_address=device.ip_address,
            scan_profile=scan_profile,
            triggered_by="schedule",
            schedule_id=scheduled_scan_id,
        )
        result = await queue.enqueue(job)

        # Update schedule status after enqueue
        if sched:
            sched.last_run_status = "queued" if result.status.value == "queued" else result.status.value
            db.commit()

    except Exception as e:
        logger.error(f"execute_scheduled_scan failed for device {device_id}: {e}")
        # Update schedule with failure
        db_inner = SessionLocal()
        try:
            sched = db_inner.query(ScheduledScan).filter(ScheduledScan.id == scheduled_scan_id).first()
            if sched:
                sched.last_run_status = "failed"
                db_inner.commit()
        finally:
            db_inner.close()
    finally:
        db.close()


def create_schedule(
    db,
    device_id: int,
    trigger_type: str,
    scan_profile: str,
    authorized_by_name: str,
    authorized_by_role: str,
    db_url: str,
    run_at: Optional[datetime] = None,
    interval_unit: Optional[str] = None,
    interval_value: Optional[int] = None,
    cron_expression: Optional[str] = None,
    created_by: Optional[str] = None,
) -> "ScheduledScan":  # type: ignore
    from apscheduler.triggers.date import DateTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.cron import CronTrigger
    from app.models.scheduled_scan import ScheduledScan

    scheduler = get_scheduler()
    if not scheduler:
        raise RuntimeError("Scheduler not initialized")

    job_id = f"scan_{device_id}_{uuid4().hex[:8]}"

    if trigger_type == "once":
        trigger = DateTrigger(run_date=run_at)
    elif trigger_type == "interval":
        kwargs = {interval_unit: interval_value}
        trigger = IntervalTrigger(**kwargs)
    elif trigger_type == "cron":
        trigger = CronTrigger.from_crontab(cron_expression)
    else:
        raise ValueError(f"Unknown trigger_type: {trigger_type}")

    # Compute next run time
    next_run = trigger.get_next_fire_time(None, datetime.now(timezone.utc))

    sched = ScheduledScan(
        device_id=device_id,
        apscheduler_job_id=job_id,
        trigger_type=trigger_type,
        run_at=run_at,
        interval_unit=interval_unit,
        interval_value=interval_value,
        cron_expression=cron_expression,
        scan_profile=scan_profile,
        authorized_by_name=authorized_by_name,
        authorized_by_role=authorized_by_role,
        active=True,
        next_run_at=next_run,
        run_count=0,
        created_by=created_by,
    )
    db.add(sched)
    db.flush()

    scheduler.add_job(
        execute_scheduled_scan,
        trigger=trigger,
        id=job_id,
        kwargs={
            "device_id": device_id,
            "scan_profile": scan_profile,
            "scheduled_scan_id": sched.id,
            "authorized_by_name": authorized_by_name,
            "authorized_by_role": authorized_by_role,
        },
        replace_existing=True,
        misfire_grace_time=3600,
    )
    db.commit()
    db.refresh(sched)
    logger.info(f"Created schedule {sched.id} (job_id={job_id}) for device {device_id}")
    return sched


def delete_schedule(db, sched) -> None:
    scheduler = get_scheduler()
    if scheduler:
        try:
            scheduler.remove_job(sched.apscheduler_job_id)
        except Exception:
            pass
    db.delete(sched)
    db.commit()


def pause_schedule(db, sched) -> None:
    scheduler = get_scheduler()
    if scheduler:
        try:
            scheduler.pause_job(sched.apscheduler_job_id)
        except Exception:
            pass
    sched.active = False
    db.commit()


def resume_schedule(db, sched) -> None:
    scheduler = get_scheduler()
    if scheduler:
        try:
            scheduler.resume_job(sched.apscheduler_job_id)
        except Exception:
            pass
    sched.active = True
    db.commit()


def update_next_run(db, sched) -> None:
    """Refresh next_run_at from APScheduler."""
    scheduler = get_scheduler()
    if scheduler:
        try:
            job = scheduler.get_job(sched.apscheduler_job_id)
            if job and job.next_run_time:
                sched.next_run_at = job.next_run_time
                db.commit()
        except Exception:
            pass
