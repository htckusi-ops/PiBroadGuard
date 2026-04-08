import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.core.security import verify_credentials
from app.models.device import Device
from app.models.probe_result import ProbeResult
from app.services import ping_service

logger = logging.getLogger("pibroadguard.probe")
router = APIRouter(tags=["probes"])

# In-progress probes: probe_id -> asyncio.Task
_probe_tasks: dict = {}
_STALE_RUNNING_THRESHOLD = timedelta(minutes=2)


async def _run_probe_task(probe_id: int, ip: str):
    db = SessionLocal()
    try:
        probe = db.query(ProbeResult).filter(ProbeResult.id == probe_id).first()
        if not probe:
            return

        try:
            started = datetime.now(timezone.utc)
            result = ping_service.ping_host(ip, timeout_seconds=1)
            finished = datetime.now(timezone.utc)
            elapsed = max((finished - started).total_seconds(), 0.0)

            probe.status = "done"
            probe.reachable = "yes" if result.reachable else "no"
            probe.ports_json = json.dumps([])
            probe.raw_xml = ""
            probe.scan_duration_seconds = elapsed
            probe.nmap_exit_code = 0 if result.reachable else 1
            probe.nmap_version = "ping"
            probe.error_message = None if result.reachable else "Ping failed or timed out."
            probe.completed_at = finished
            device = db.query(Device).filter(Device.id == probe.device_id).first()
            if device:
                device.last_ping_status = "reachable" if result.reachable else "unreachable"
                device.last_ping_checked_at = finished
                device.last_ping_rtt_ms = int(round(result.rtt_ms)) if result.rtt_ms is not None else None
                if result.reachable:
                    device.last_seen_ping_at = finished

        except asyncio.CancelledError:
            probe.status = "cancelled"
            probe.error_message = probe.error_message or "Probe was cancelled."
            probe.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise
        except Exception as exc:
            logger.error(f"Probe {probe_id} failed: {exc}")
            probe.status = "failed"
            probe.error_message = str(exc)
            probe.completed_at = datetime.now(timezone.utc)

        db.commit()
    finally:
        db.close()
        _probe_tasks.pop(probe_id, None)


def _reconcile_probe_state(probe: ProbeResult, db: Session):
    """Ensure 'running' probe states are consistent with in-memory task state."""
    if probe.status != "running":
        return

    task = _probe_tasks.get(probe.id)
    now = datetime.now(timezone.utc)
    created = probe.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    # Task known and finished but DB still says running
    if task and task.done():
        probe.status = "failed"
        probe.error_message = probe.error_message or "Probe task finished unexpectedly."
        probe.completed_at = probe.completed_at or now
        db.commit()
        _probe_tasks.pop(probe.id, None)
        return

    # No task known anymore and probe is stale -> mark failed
    if not task and created and now - created > _STALE_RUNNING_THRESHOLD:
        probe.status = "failed"
        probe.error_message = probe.error_message or "Probe timed out or agent was restarted."
        probe.completed_at = probe.completed_at or now
        db.commit()


@router.post("/devices/{device_id}/probe", status_code=201)
def start_probe(
    device_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Device not found")

    profile_name = "ping"
    profile_label = "Ping"

    running_probe = (
        db.query(ProbeResult)
        .filter(ProbeResult.device_id == device_id, ProbeResult.status == "running")
        .order_by(ProbeResult.created_at.desc())
        .first()
    )
    if running_probe:
        _reconcile_probe_state(running_probe, db)
        db.refresh(running_probe)
        if running_probe.status == "running":
            raise HTTPException(
                409,
                {
                    "message": "A probe is already running for this device",
                    "probe_id": running_probe.id,
                },
            )

    probe = ProbeResult(
        device_id=device_id,
        profile_name=profile_name,
        profile_label=profile_label,
        status="running",
        initiated_by=user,
    )
    db.add(probe)
    db.commit()
    db.refresh(probe)

    # Fire and forget – independent of the scan queue
    task = asyncio.create_task(
        _run_probe_task(probe.id, device.ip_address)
    )
    _probe_tasks[probe.id] = task

    logger.info(f"Probe #{probe.id} started: device={device_id} profile={profile_name} by={user}")
    return {"probe_id": probe.id, "status": "running", "profile_name": profile_name}


@router.get("/devices/{device_id}/probes")
def list_probes(
    device_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Device not found")

    probes = (
        db.query(ProbeResult)
        .filter(ProbeResult.device_id == device_id)
        .order_by(ProbeResult.created_at.desc())
        .all()
    )
    for p in probes:
        _reconcile_probe_state(p, db)
    return [_serialize(p) for p in probes]


@router.get("/devices/{device_id}/probe/{probe_id}")
def get_probe(
    device_id: int,
    probe_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    probe = db.query(ProbeResult).filter(
        ProbeResult.id == probe_id, ProbeResult.device_id == device_id
    ).first()
    if not probe:
        raise HTTPException(404, "Probe not found")
    _reconcile_probe_state(probe, db)
    return _serialize(probe, include_ports=True)


@router.put("/devices/{device_id}/probe/{probe_id}/observations")
def save_observations(
    device_id: int,
    probe_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    probe = db.query(ProbeResult).filter(
        ProbeResult.id == probe_id, ProbeResult.device_id == device_id
    ).first()
    if not probe:
        raise HTTPException(404, "Probe not found")

    observations = payload.get("observations", [])
    probe.observations_json = json.dumps(observations)
    db.commit()
    return {"ok": True}


@router.post("/devices/{device_id}/probe/{probe_id}/cancel")
def cancel_probe(
    device_id: int,
    probe_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    probe = db.query(ProbeResult).filter(
        ProbeResult.id == probe_id, ProbeResult.device_id == device_id
    ).first()
    if not probe:
        raise HTTPException(404, "Probe not found")
    if probe.status != "running":
        return {"ok": True, "status": probe.status}

    task = _probe_tasks.get(probe.id)
    if task and not task.done():
        task.cancel()
        _probe_tasks.pop(probe.id, None)

    probe.status = "cancelled"
    probe.error_message = probe.error_message or f"Cancelled by {user}"
    probe.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True, "status": "cancelled"}


@router.delete("/devices/{device_id}/probe/{probe_id}", status_code=204)
def delete_probe(
    device_id: int,
    probe_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    probe = db.query(ProbeResult).filter(
        ProbeResult.id == probe_id, ProbeResult.device_id == device_id
    ).first()
    if not probe:
        raise HTTPException(404, "Probe not found")
    if probe.status == "running":
        raise HTTPException(409, "Running probe must be cancelled before deletion")

    db.delete(probe)
    db.commit()
    return


def _serialize(probe: ProbeResult, include_ports: bool = False) -> dict:
    ports = []
    if include_ports and probe.ports_json:
        try:
            ports = json.loads(probe.ports_json)
        except Exception:
            pass

    observations = []
    if probe.observations_json:
        try:
            observations = json.loads(probe.observations_json)
        except Exception:
            pass

    d = {
        "id": probe.id,
        "device_id": probe.device_id,
        "profile_name": probe.profile_name,
        "profile_label": probe.profile_label,
        "status": probe.status,
        "reachable": probe.reachable,
        "scan_duration_seconds": probe.scan_duration_seconds,
        "nmap_exit_code": probe.nmap_exit_code,
        "nmap_version": probe.nmap_version,
        "error_message": probe.error_message,
        "initiated_by": probe.initiated_by,
        "observations": observations,
        "created_at": probe.created_at.isoformat() if probe.created_at else None,
        "completed_at": probe.completed_at.isoformat() if probe.completed_at else None,
    }
    if include_ports:
        d["ports"] = ports
    else:
        d["port_count"] = len(json.loads(probe.ports_json)) if probe.ports_json else 0
    return d
