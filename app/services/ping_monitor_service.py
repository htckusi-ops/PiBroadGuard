import asyncio
import logging
from datetime import datetime, timezone, timedelta

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.device import Device
from app.services import ping_service

logger = logging.getLogger("pibroadguard.ping_monitor")


def _now_utc():
    return datetime.now(timezone.utc)


def ping_device_once(device: Device) -> None:
    result = ping_service.ping_host(device.ip_address, timeout_seconds=1)
    checked_at = _now_utc()
    device.last_ping_status = "reachable" if result.reachable else "unreachable"
    device.last_ping_checked_at = checked_at
    device.last_ping_rtt_ms = int(round(result.rtt_ms)) if result.rtt_ms is not None else None
    if result.reachable:
        device.last_seen_ping_at = checked_at


async def run_ping_monitor_loop() -> None:
    poll_seconds = max(5, int(getattr(settings, "pibg_ping_monitor_poll_seconds", 30)))
    logger.info(f"Ping monitor started (poll={poll_seconds}s)")
    while True:
        db = SessionLocal()
        try:
            now = _now_utc()
            devices = (
                db.query(Device)
                .filter(Device.deleted == False, Device.ping_monitor_enabled == True)
                .all()
            )
            for d in devices:
                interval_min = d.ping_interval_minutes or 5
                last_checked = d.last_ping_checked_at
                if last_checked and last_checked.tzinfo is None:
                    last_checked = last_checked.replace(tzinfo=timezone.utc)
                due = last_checked is None or (now - last_checked) >= timedelta(minutes=interval_min)
                if not due:
                    continue
                try:
                    ping_device_once(d)
                except Exception as ping_err:
                    logger.warning(f"Recurring ping failed for device {d.id}: {ping_err}")
            db.commit()
        except Exception as e:
            logger.error(f"Ping monitor loop failed: {e}")
            db.rollback()
        finally:
            db.close()
        await asyncio.sleep(poll_seconds)

