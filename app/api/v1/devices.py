import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.models.device import Device
from app.schemas.device import DeviceCreate, DeviceRead, DeviceUpdate

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
