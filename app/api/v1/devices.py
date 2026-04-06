import logging
from typing import List, Optional
from datetime import date, timedelta, datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.models.device import Device
from app.schemas.device import DeviceCreate, DeviceRead, DeviceUpdate
from app.services import dns_service, nmos_service, ping_service

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["devices"])


def _enrich(device: Device, db: Session) -> DeviceRead:
    last = (
        db.query(Assessment)
        .filter(Assessment.device_id == device.id)
        .order_by(Assessment.created_at.desc())
        .first()
    )
    data = DeviceRead.model_validate(device)
    if last:
        data.last_assessment_status = last.status
        data.last_assessment_rating = last.overall_rating
        data.last_assessment_id = last.id
        data.last_assessment_date = last.created_at
    return data


@router.get("/devices", response_model=List[DeviceRead])
def list_devices(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    devices = db.query(Device).filter(Device.deleted == False).all()
    return [_enrich(d, db) for d in devices]


@router.post("/devices", response_model=DeviceRead, status_code=201)
def create_device(body: DeviceCreate, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    device = Device(**body.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    logger.info(f"Created device {device.id}: {device.manufacturer} {device.model}")
    return _enrich(device, db)


@router.get("/devices/{device_id}", response_model=DeviceRead)
def get_device(device_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")
    return _enrich(device, db)


@router.put("/devices/{device_id}", response_model=DeviceRead)
def update_device(device_id: int, body: DeviceUpdate, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(device, k, v)
    db.commit()
    db.refresh(device)
    return _enrich(device, db)


@router.delete("/devices/{device_id}", status_code=204)
def delete_device(device_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")
    device.deleted = True
    db.commit()
    logger.info(f"Soft-deleted device {device_id}")


@router.get("/devices/reassessment-due")
def list_reassessment_due(
    days_ahead: int = Query(30, ge=0, le=365),
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Return devices whose latest completed assessment has a reassessment_due date
    in the past or within `days_ahead` days from today."""
    cutoff = date.today() + timedelta(days=days_ahead)
    # subquery: latest completed assessment per device
    from sqlalchemy import func
    subq = (
        db.query(
            Assessment.device_id,
            func.max(Assessment.created_at).label("max_created"),
        )
        .filter(Assessment.status == "completed")
        .group_by(Assessment.device_id)
        .subquery()
    )
    rows = (
        db.query(Assessment, Device)
        .join(subq, (Assessment.device_id == subq.c.device_id) & (Assessment.created_at == subq.c.max_created))
        .join(Device, Device.id == Assessment.device_id)
        .filter(Device.deleted == False)
        .filter(Assessment.reassessment_due != None)
        .filter(Assessment.reassessment_due <= cutoff)
        .order_by(Assessment.reassessment_due.asc())
        .all()
    )
    result = []
    for assessment, device in rows:
        d = DeviceRead.model_validate(device)
        d.last_assessment_id = assessment.id
        d.last_assessment_status = assessment.status
        d.last_assessment_rating = assessment.overall_rating
        d.last_assessment_date = assessment.created_at
        result.append({
            **d.model_dump(),
            "reassessment_due": assessment.reassessment_due.isoformat() if assessment.reassessment_due else None,
            "days_overdue": (date.today() - assessment.reassessment_due).days if assessment.reassessment_due else None,
        })
    return result


@router.post("/devices/{device_id}/ping", response_model=DeviceRead)
def ping_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")

    result = ping_service.ping_host(device.ip_address, timeout_seconds=1)
    checked_at = datetime.now(timezone.utc)

    device.last_ping_status = "reachable" if result.reachable else "unreachable"
    device.last_ping_checked_at = checked_at
    device.last_ping_rtt_ms = int(round(result.rtt_ms)) if result.rtt_ms is not None else None
    if result.reachable:
        device.last_seen_ping_at = checked_at

    db.commit()
    db.refresh(device)
    return _enrich(device, db)


@router.post("/devices/{device_id}/nmos-check")
async def nmos_security_check(
    device_id: int,
    registry_url: str = "",
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """
    Run passive NMOS IS-04 security checks against a device's IP address.

    Checks performed (production-safe, no mDNS, no state changes):
    1. TLS check – is the NMOS IS-04 API served over HTTPS (BCP-003-01)?
    2. Auth check – does the IS-04 API require authentication (IS-10 / BCP-003-02)?
    3. Service discovery – which NMOS API endpoints are reachable?

    Optional: if registry_url is provided, also queries the NMOS IS-04 Registry
    for this device's nodes/devices/senders/receivers.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")

    host = device.ip_address
    tls_result, auth_result, services = await _run_nmos_checks(host)

    registry_data = None
    if registry_url:
        disc = await nmos_service.query_nmos_registry(registry_url)
        registry_data = {
            "nodes": disc.nodes,
            "devices": disc.devices,
            "senders": disc.senders,
            "receivers": disc.receivers,
            "error": disc.error,
        }

    def _fmt(r: nmos_service.NmosSecurityResult) -> dict:
        return {
            "check": r.check,
            "result": r.result,
            "detail": r.detail,
            "recommendation": r.recommendation,
            "severity": r.severity,
        }

    return {
        "device_id": device_id,
        "host": host,
        "tls_check": _fmt(tls_result),
        "auth_check": _fmt(auth_result),
        "discovered_services": [
            {"host": s.host, "port": s.port, "api_type": s.api_type,
             "api_version": s.api_version, "url": s.url}
            for s in services
        ],
        "registry_data": registry_data,
    }


async def _run_nmos_checks(host: str):
    tls = await nmos_service.check_nmos_tls(host)
    auth = await nmos_service.check_nmos_auth_required(host)
    services = await nmos_service.discover_nmos_services(host)
    return tls, auth, services


@router.get("/dns/reverse")
async def reverse_dns(
    ip: str = Query(..., description="IPv4 or IPv6 address to resolve"),
    user: str = Depends(verify_credentials),
):
    """Perform a reverse DNS lookup for the given IP address."""
    hostname = await dns_service.reverse_lookup(ip)
    return {"ip": ip, "hostname": hostname}
