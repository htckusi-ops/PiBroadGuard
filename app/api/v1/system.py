import json
import logging
from datetime import datetime, timezone
from pathlib import Path
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

_I18N_DIR = Path(__file__).parent.parent.parent / "i18n"
_PHPIPAM_NOT_CONFIGURED = "phpIPAM nicht konfiguriert (PIBG_PHPIPAM_URL / PIBG_PHPIPAM_TOKEN fehlt)"
_SUPPORTED_LANGS = {"de", "en"}


@router.get("/i18n/{lang}")
def get_translations(lang: str):
    """Return i18n translations for the given language (de or en)."""
    if lang not in _SUPPORTED_LANGS:
        raise HTTPException(400, f"Unsupported language: {lang}. Supported: {', '.join(_SUPPORTED_LANGS)}")
    path = _I18N_DIR / f"{lang}.json"
    if not path.exists():
        raise HTTPException(404, f"Translation file not found: {lang}")
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/i18n")
def list_languages():
    """List available UI languages."""
    return {"languages": [{"code": "de", "label": "Deutsch"}, {"code": "en", "label": "English"}]}


@router.get("/device-types")
def get_device_types(
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Return all active device types for dropdowns."""
    from app.models.device_type import DeviceType
    return db.query(DeviceType).filter(DeviceType.active == True).order_by(DeviceType.sort_order).all()


@router.post("/device-types")
def create_device_type(
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.device_type import DeviceType
    dt = DeviceType(
        name=payload["name"],
        label_de=payload.get("label_de", payload["name"]),
        label_en=payload.get("label_en", payload["name"]),
        sort_order=payload.get("sort_order", 99),
        active=True,
    )
    db.add(dt)
    db.commit()
    db.refresh(dt)
    return dt


@router.put("/device-types/{dt_id}")
def update_device_type(
    dt_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.device_type import DeviceType
    dt = db.query(DeviceType).filter(DeviceType.id == dt_id).first()
    if not dt:
        raise HTTPException(404, "Device type not found")
    for k in ("label_de", "label_en", "sort_order", "active"):
        if k in payload:
            setattr(dt, k, payload[k])
    db.commit()
    db.refresh(dt)
    return dt


@router.delete("/device-types/{dt_id}")
def delete_device_type(
    dt_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.device_type import DeviceType
    dt = db.query(DeviceType).filter(DeviceType.id == dt_id).first()
    if not dt:
        raise HTTPException(404, "Device type not found")
    dt.active = False
    db.commit()
    return {"deleted": True}


# ── Device Classes ────────────────────────────────────────────────────────────

@router.get("/device-classes")
def get_device_classes(
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Return all active device classes."""
    from app.models.device_class import DeviceClass
    return db.query(DeviceClass).filter(DeviceClass.active == True).order_by(DeviceClass.sort_order).all()


@router.get("/device-classes/all")
def get_all_device_classes(
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Return all device classes including inactive (admin)."""
    from app.models.device_class import DeviceClass
    return db.query(DeviceClass).order_by(DeviceClass.sort_order).all()


@router.post("/device-classes", status_code=201)
def create_device_class(
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.device_class import DeviceClass
    dc = DeviceClass(
        name=payload["name"],
        label_de=payload.get("label_de", payload["name"]),
        label_en=payload.get("label_en", payload["name"]),
        sort_order=payload.get("sort_order", 99),
        active=True,
    )
    db.add(dc)
    db.commit()
    db.refresh(dc)
    return dc


@router.put("/device-classes/{dc_id}")
def update_device_class(
    dc_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.device_class import DeviceClass
    dc = db.query(DeviceClass).filter(DeviceClass.id == dc_id).first()
    if not dc:
        raise HTTPException(404, "Device class not found")
    for k in ("label_de", "label_en", "sort_order", "active"):
        if k in payload:
            setattr(dc, k, payload[k])
    db.commit()
    db.refresh(dc)
    return dc


@router.delete("/device-classes/{dc_id}")
def delete_device_class(
    dc_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.device_class import DeviceClass
    dc = db.query(DeviceClass).filter(DeviceClass.id == dc_id).first()
    if not dc:
        raise HTTPException(404, "Device class not found")
    dc.active = False
    db.commit()
    return {"deleted": True}


# ── Scan Profiles ─────────────────────────────────────────────────────────────

@router.get("/scan-profiles")
def get_scan_profiles(
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Return all active scan profiles."""
    from app.models.scan_profile import ScanProfile
    return db.query(ScanProfile).filter(ScanProfile.active == True).order_by(ScanProfile.id).all()


@router.post("/scan-profiles", status_code=201)
def create_scan_profile(
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    import json as _json
    from app.models.scan_profile import ScanProfile
    flags = payload.get("nmap_flags", [])
    sp = ScanProfile(
        name=payload["name"],
        label=payload.get("label", payload["name"]),
        description=payload.get("description"),
        nmap_flags=_json.dumps(flags) if isinstance(flags, list) else flags,
        timeout_seconds=payload.get("timeout_seconds", 300),
        built_in=False,
        active=True,
    )
    db.add(sp)
    db.commit()
    db.refresh(sp)
    return _serialize_scan_profile(sp)


@router.put("/scan-profiles/{sp_id}")
def update_scan_profile(
    sp_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    import json as _json
    from app.models.scan_profile import ScanProfile
    sp = db.query(ScanProfile).filter(ScanProfile.id == sp_id).first()
    if not sp:
        raise HTTPException(404, "Scan profile not found")
    if sp.built_in and "nmap_flags" in payload:
        raise HTTPException(400, "Built-in profiles cannot have their flags modified")
    for k in ("label", "description", "timeout_seconds", "active"):
        if k in payload:
            setattr(sp, k, payload[k])
    if not sp.built_in and "nmap_flags" in payload:
        flags = payload["nmap_flags"]
        sp.nmap_flags = _json.dumps(flags) if isinstance(flags, list) else flags
    db.commit()
    db.refresh(sp)
    return _serialize_scan_profile(sp)


@router.delete("/scan-profiles/{sp_id}")
def delete_scan_profile(
    sp_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.scan_profile import ScanProfile
    sp = db.query(ScanProfile).filter(ScanProfile.id == sp_id).first()
    if not sp:
        raise HTTPException(404, "Scan profile not found")
    if sp.built_in:
        raise HTTPException(400, "Built-in profiles cannot be deleted")
    sp.active = False
    db.commit()
    return {"deleted": True}


def _serialize_scan_profile(sp) -> dict:
    import json as _json
    return {
        "id": sp.id,
        "name": sp.name,
        "label": sp.label,
        "description": sp.description,
        "nmap_flags": _json.loads(sp.nmap_flags) if sp.nmap_flags else [],
        "timeout_seconds": sp.timeout_seconds,
        "built_in": sp.built_in,
        "active": sp.active,
    }


# ── phpIPAM endpoints ────────────────────────────────────────────────────────

_PHPIPAM_NOT_CONFIGURED = "phpIPAM nicht konfiguriert (PIBG_PHPIPAM_URL / PIBG_PHPIPAM_TOKEN fehlt)"


@router.get("/phpipam/status")
async def phpipam_status(user: str = Depends(verify_credentials)):
    """Return phpIPAM configuration status and test connection."""
    from app.services.phpipam_service import get_phpipam_service
    svc = get_phpipam_service()
    if not svc:
        return {"configured": False, "message": _PHPIPAM_NOT_CONFIGURED}
    result = await svc.test_connection()
    return {"configured": True, **result}


@router.get("/phpipam/lookup")
async def phpipam_lookup(
    ip: str,
    user: str = Depends(verify_credentials),
):
    """Lookup a single IP in phpIPAM."""
    from app.services.phpipam_service import get_phpipam_service
    svc = get_phpipam_service()
    if not svc:
        raise HTTPException(503, _PHPIPAM_NOT_CONFIGURED)
    host = await svc.lookup_by_ip(ip)
    if not host:
        raise HTTPException(404, f"IP {ip} nicht in phpIPAM gefunden")
    return host


@router.get("/phpipam/subnets")
async def phpipam_subnets(user: str = Depends(verify_credentials)):
    """List all subnets from phpIPAM."""
    from app.services.phpipam_service import get_phpipam_service
    svc = get_phpipam_service()
    if not svc:
        raise HTTPException(503, _PHPIPAM_NOT_CONFIGURED)
    return await svc.get_subnets()


@router.get("/phpipam/subnets/{subnet_id}/hosts")
async def phpipam_subnet_hosts(subnet_id: int, user: str = Depends(verify_credentials)):
    """Get all hosts in a phpIPAM subnet."""
    from app.services.phpipam_service import get_phpipam_service
    svc = get_phpipam_service()
    if not svc:
        raise HTTPException(503, _PHPIPAM_NOT_CONFIGURED)
    return await svc.get_hosts_in_subnet(subnet_id)


@router.post("/phpipam/import")
async def phpipam_bulk_import(
    payload: dict,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Bulk import hosts from phpIPAM as devices."""
    from app.services.phpipam_service import get_phpipam_service
    from app.models.device import Device
    from datetime import datetime, timezone

    svc = get_phpipam_service()
    if not svc:
        raise HTTPException(503, _PHPIPAM_NOT_CONFIGURED)

    hosts = payload.get("hosts", [])
    device_type = payload.get("device_type", "other")
    created = []
    skipped = []

    for host in hosts:
        ip = host.get("ip_address", "")
        if not ip:
            skipped.append({"reason": "no ip", "host": host})
            continue
        existing = db.query(Device).filter(Device.ip_address == ip, Device.deleted == False).first()
        if existing:
            skipped.append({"reason": "duplicate_ip", "ip": ip})
            continue

        device = Device(
            manufacturer="",
            model=host.get("description", "") or "phpIPAM Import",
            device_type=device_type,
            hostname=host.get("hostname", ""),
            ip_address=ip,
            mac_address=host.get("mac_address", ""),
            notes=host.get("note", ""),
            phpipam_id=host.get("phpipam_id"),
            phpipam_synced_at=datetime.now(timezone.utc),
        )
        db.add(device)
        created.append(ip)

    db.commit()
    return {
        "created": len(created),
        "skipped": len(skipped),
        "created_ips": created,
        "skipped_details": skipped,
    }
