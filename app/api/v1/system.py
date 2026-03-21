import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.system_settings import SystemSettings
from app.schemas.system import (
    BackupCreate, BackupInfo,
    ConnectivityModeUpdate, ConnectivityStatus,
)
from app.services import backup_service, connectivity_service, remediation_service

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["system"])


def _get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(SystemSettings).filter(SystemSettings.key == key).first()
    return row.value if row else default


def _set_setting(db: Session, key: str, value: str, user: str = "system"):
    row = db.query(SystemSettings).filter(SystemSettings.key == key).first()
    if row:
        row.value = value
        row.updated_by = user
        row.updated_at = datetime.now(timezone.utc)
    else:
        db.add(SystemSettings(key=key, value=value, updated_by=user, updated_at=datetime.now(timezone.utc)))
    db.commit()


@router.get("/system/connectivity", response_model=ConnectivityStatus)
def get_connectivity(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    mode = _get_setting(db, "connectivity_mode", "auto")
    effective = connectivity_service.get_effective_mode(mode)
    kev_age = None
    from app.models.kev_cache import KevCache
    latest = db.query(KevCache).order_by(KevCache.fetched_at.desc()).first()
    if latest and latest.fetched_at:
        delta = datetime.now(timezone.utc) - latest.fetched_at.replace(tzinfo=timezone.utc)
        kev_age = delta.total_seconds() / 3600
    return ConnectivityStatus(
        mode_setting=mode,
        auto_detected=connectivity_service._state.get("auto_detected"),
        effective_mode=effective,
        last_check=connectivity_service._state.get("last_check"),
        nvd_reachable=connectivity_service._state.get("auto_detected") or False,
        kev_cache_age_hours=kev_age,
        override_active=(mode != "auto"),
    )


@router.post("/system/connectivity/mode")
async def set_connectivity_mode(
    body: ConnectivityModeUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    if body.mode not in ("auto", "force_online", "force_offline"):
        raise HTTPException(400, "Ungültiger Modus")
    _set_setting(db, "connectivity_mode", body.mode, user)
    return {"mode": body.mode}


@router.post("/system/connectivity/check")
async def check_connectivity(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    reachable = await connectivity_service.check_internet()
    return {"nvd_reachable": reachable}


@router.post("/system/kev-sync")
async def kev_sync(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    mode = _get_setting(db, "connectivity_mode", "auto")
    if not connectivity_service.is_online(mode):
        raise HTTPException(503, "System ist im Offline-Modus")
    count = await remediation_service.sync_kev_cache(db)
    return {"synced": count}


@router.post("/system/backup")
def create_backup(
    body: BackupCreate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    try:
        result = backup_service.create_backup(db, body.destination, body.usb_path, body.encrypt)
        _set_setting(db, "last_backup_at", datetime.now(timezone.utc).isoformat(), user)
        _set_setting(db, "last_backup_path", result.get("path", ""), user)
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/system/backup/list", response_model=List[BackupInfo])
def list_backups(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    return backup_service.list_backups()


@router.get("/system/backup/{filename}")
def download_backup(filename: str, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    import os
    path = os.path.join("./data/backups", filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Backup nicht gefunden")
    with open(path, "rb") as f:
        data = f.read()
    return Response(content=data, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })


@router.get("/system/settings")
def get_all_settings(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    rows = db.query(SystemSettings).all()
    return {r.key: r.value for r in rows}


@router.get("/system/logs")
def get_logs(lines: int = 100, user: str = Depends(verify_credentials)):
    import os
    log_path = settings.pibg_log_path
    if not os.path.isfile(log_path):
        return {"lines": []}
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    return {"lines": all_lines[-lines:]}


@router.get("/system/logs/download")
def download_logs(user: str = Depends(verify_credentials)):
    import os
    log_path = settings.pibg_log_path
    if not os.path.isfile(log_path):
        raise HTTPException(404, "Logfile nicht gefunden")
    with open(log_path, "rb") as f:
        data = f.read()
    return Response(content=data, media_type="text/plain", headers={
        "Content-Disposition": 'attachment; filename="pibroadguard.log"'
    })


@router.get("/system/nmap-caps")
async def nmap_capabilities(user: str = Depends(verify_credentials)):
    return await nmap_service.get_nmap_capabilities()


from app.services import nmap_service
