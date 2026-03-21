import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.schemas.system import UsbDevice, UsbExportRequest, UsbImportRequest
from app.services import package_service, usb_service
from typing import List

logger = logging.getLogger("pibroadguard.usb")
router = APIRouter(tags=["usb"])


@router.get("/usb/devices", response_model=List[UsbDevice])
def list_usb_devices(user: str = Depends(verify_credentials)):
    return usb_service.detect_usb_devices()


@router.post("/usb/eject")
def eject_usb(body: dict, user: str = Depends(verify_credentials)):
    path = body.get("path")
    if not path:
        raise HTTPException(400, "Pfad muss angegeben werden")
    ok = usb_service.safe_eject(path)
    return {"success": ok}


@router.post("/usb/export")
def usb_export(
    body: UsbExportRequest,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    validation = usb_service.validate_path(body.target_path)
    if not validation["valid"]:
        raise HTTPException(400, validation["error"])

    results = []
    ids = body.assessment_ids or []

    if body.export_type == "full_backup":
        from app.services import backup_service
        result = backup_service.create_backup(db, "usb", body.target_path, body.encrypt)
        return {"exported": [result]}

    for aid in ids:
        try:
            data = package_service.export_package(db, aid)
            filename = f"assessment-{aid}.bdsa"
            result = usb_service.write_to_usb(body.target_path, filename, data, body.encrypt)
            results.append(result)
        except Exception as e:
            logger.error(f"USB export of assessment {aid} failed: {e}")
            results.append({"assessment_id": aid, "error": str(e)})

    return {"exported": results}


@router.get("/usb/import/scan")
def scan_usb_for_packages(path: str, user: str = Depends(verify_credentials)):
    validation = usb_service.validate_path(path)
    if not validation["valid"]:
        raise HTTPException(400, validation["error"])
    return usb_service.list_packages_on_usb(path)


@router.post("/usb/import")
def import_from_usb(
    body: UsbImportRequest,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    results = []
    for filename in body.filenames:
        import os
        filepath = os.path.join(body.source_path, filename)
        try:
            data = usb_service.read_from_usb(filepath)
            result = package_service.import_package(db, data, user)
            results.append({"filename": filename, "result": result})
        except Exception as e:
            logger.error(f"USB import of {filename} failed: {e}")
            results.append({"filename": filename, "error": str(e)})
    return {"imported": results}
