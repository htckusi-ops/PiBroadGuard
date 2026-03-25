import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.core.security import verify_credentials
from app.core.config import settings
from app.models.device import Device
from app.models.probe_result import ProbeResult
from app.models.scan_profile import ScanProfile
from app.services import nmap_service

logger = logging.getLogger("pibroadguard.probe")
router = APIRouter(tags=["probes"])

# In-progress probes: probe_id -> asyncio.Task
_probe_tasks: dict = {}


async def _run_probe_task(probe_id: int, ip: str, profile_name: str,
                          flags_override: Optional[list], timeout_override: Optional[int]):
    db = SessionLocal()
    try:
        probe = db.query(ProbeResult).filter(ProbeResult.id == probe_id).first()
        if not probe:
            return

        try:
            result = await nmap_service.run_scan(
                ip=ip,
                profile=profile_name,
                host_timeout=settings.pibg_nmap_host_timeout,
                max_rate=settings.pibg_nmap_max_rate,
                assessment_id=None,
                flags_override=flags_override,
                timeout_override=timeout_override,
            )

            ports = result.get("results", [])
            reachable = "yes" if ports else ("no" if result.get("returncode", 1) == 0 else "unknown")

            probe.status = "done"
            probe.reachable = reachable
            probe.ports_json = json.dumps(ports)
            probe.raw_xml = result.get("xml", "")
            probe.scan_duration_seconds = result.get("elapsed_seconds")
            probe.nmap_exit_code = result.get("returncode")
            probe.nmap_version = result.get("nmap_version")
            probe.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error(f"Probe {probe_id} failed: {exc}")
            probe.status = "failed"
            probe.error_message = str(exc)
            probe.completed_at = datetime.now(timezone.utc)

        db.commit()
    finally:
        db.close()
        _probe_tasks.pop(probe_id, None)


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

    profile_name = payload.get("profile_name", "passive")
    profile_label = profile_name
    flags_override = None
    timeout_override = None

    # Load profile from DB
    sp = db.query(ScanProfile).filter(
        ScanProfile.name == profile_name, ScanProfile.active == True
    ).first()
    if sp:
        profile_label = sp.label or profile_name
        try:
            flags_override = json.loads(sp.nmap_flags)
        except Exception:
            pass
        timeout_override = sp.timeout_seconds

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
        _run_probe_task(probe.id, device.ip_address, profile_name, flags_override, timeout_override)
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
