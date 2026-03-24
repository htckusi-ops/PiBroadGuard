import ipaddress
import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

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
        raise HTTPException(503, "System ist im Offline-Modus – KEV-Sync nicht möglich")
    try:
        count = await remediation_service.sync_kev_cache(db)
        return {"synced": count}
    except RuntimeError as e:
        raise HTTPException(502, str(e))


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


@router.post("/system/backup/restore/{filename}")
def restore_backup(filename: str, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    """
    Restore a local backup by replacing the current database file.
    Disposes all SQLAlchemy connections before copying, so the next
    request will open a fresh connection to the restored DB.
    """
    import shutil as _shutil
    from app.core.database import engine as _engine

    backup_dir = Path("./data/backups")
    src = backup_dir / filename

    # Security: only allow filenames from the backups dir (no path traversal)
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(400, "Ungültiger Dateiname")
    if not src.exists():
        raise HTTPException(404, f"Backup '{filename}' nicht gefunden")
    if src.suffix not in (".db", ".enc"):
        raise HTTPException(400, "Nur .db und .enc Dateien können wiederhergestellt werden")

    # Validate SQLite magic bytes (skip for encrypted files)
    if filename.endswith(".db"):
        with open(src, "rb") as f:
            magic = f.read(16)
        if not magic.startswith(b"SQLite format 3"):
            raise HTTPException(400, "Datei ist keine gültige SQLite-Datenbank")

    db_path = Path(settings.pibg_db_path)
    logger.warning(f"Backup restore initiated: {filename} → {db_path} by {user}")

    try:
        # Close all active connections
        _engine.dispose()
        # Replace the current DB with the backup
        _shutil.copy2(str(src), str(db_path))
        logger.info(f"Backup restored: {filename}")
        return {
            "restored": True,
            "filename": filename,
            "message": "Backup erfolgreich wiederhergestellt. Die Anwendung lädt Daten ab der nächsten Anfrage aus der wiederhergestellten Datenbank.",
        }
    except Exception as e:
        logger.error(f"Backup restore failed: {e}")
        raise HTTPException(500, f"Wiederherstellung fehlgeschlagen: {e}")


@router.delete("/system/backup/{filename}")
def delete_backup(filename: str, user: str = Depends(verify_credentials)):
    """Delete a single local backup file."""
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(400, "Ungültiger Dateiname")
    backup_dir = Path("./data/backups")
    target = backup_dir / filename
    if not target.exists():
        raise HTTPException(404, f"Backup '{filename}' nicht gefunden")
    target.unlink()
    logger.info(f"Backup deleted: {filename} by {user}")
    return {"deleted": True, "filename": filename}


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
    profiles = db.query(ScanProfile).filter(ScanProfile.active == True).order_by(ScanProfile.id).all()
    return [_serialize_scan_profile(sp) for sp in profiles]


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


# ── Network interfaces ────────────────────────────────────────────────────────

@router.get("/network-interfaces")
def get_network_interfaces(user: str = Depends(verify_credentials)):
    """Return available network interfaces for Nmap binding."""
    import subprocess, re
    interfaces = [{"name": "auto", "label": "Auto (Standard)", "addresses": []}]
    try:
        out = subprocess.check_output(["ip", "-o", "addr", "show"], text=True, timeout=5)
        seen = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            family = parts[2]
            addr_cidr = parts[3]
            addr = addr_cidr.split("/")[0]
            if iface in ("lo",):
                continue
            if iface not in seen:
                seen[iface] = []
            if family in ("inet", "inet6"):
                seen[iface].append(addr)
        for iface, addrs in seen.items():
            interfaces.append({"name": iface, "label": iface, "addresses": addrs})
    except Exception as e:
        logger.warning(f"Could not enumerate network interfaces: {e}")
    return interfaces


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


# ── Network Configuration ────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def _read_network_config() -> dict:
    """
    Read current network config using standard Linux tools.
    Returns dict with interfaces list (name, addresses, state)
    plus default route and DNS servers.
    """
    interfaces = {}

    # Parse ip -o addr show
    rc, out, _ = _run(["ip", "-o", "addr", "show"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            idx, iface, family, addr_cidr = parts[0], parts[1], parts[2], parts[3]
            if iface == "lo":
                continue
            if iface not in interfaces:
                interfaces[iface] = {"name": iface, "addresses": [], "state": "unknown"}
            if family in ("inet", "inet6"):
                interfaces[iface]["addresses"].append({
                    "family": family,
                    "address": addr_cidr,  # e.g. 192.168.1.10/24
                })

    # Parse ip link show to get UP/DOWN state
    rc2, out2, _ = _run(["ip", "-o", "link", "show"])
    if rc2 == 0:
        for line in out2.splitlines():
            m = re.search(r"^\d+:\s+(\S+):\s+<([^>]*)>", line)
            if m:
                name = m.group(1).rstrip("@eth0")
                flags = m.group(2)
                if name in interfaces:
                    interfaces[name]["state"] = "up" if "UP" in flags else "down"

    # Default gateway
    default_gw = ""
    rc3, out3, _ = _run(["ip", "route", "show", "default"])
    if rc3 == 0 and out3:
        m = re.search(r"default via (\S+)", out3)
        if m:
            default_gw = m.group(1)

    # DNS servers from resolv.conf
    dns_servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])
    except Exception:
        pass

    # Also try systemd-resolved if available
    if not dns_servers:
        rc4, out4, _ = _run(["resolvectl", "status", "--no-pager"], timeout=3)
        if rc4 == 0:
            for line in out4.splitlines():
                m = re.search(r"DNS Servers?:\s+(.+)", line)
                if m:
                    dns_servers.extend(m.group(1).split())

    return {
        "interfaces": list(interfaces.values()),
        "default_gateway": default_gw,
        "dns_servers": dns_servers,
        "nmcli_available": _run(["which", "nmcli"])[0] == 0,
        "ip_available": _run(["which", "ip"])[0] == 0,
    }


@router.get("/system/network-config")
def get_network_config(user: str = Depends(verify_credentials)):
    """Return current network configuration (IP addresses, gateway, DNS)."""
    return _read_network_config()


@router.post("/system/network-config/apply")
def apply_network_config(body: dict, user: str = Depends(verify_credentials)):
    """
    Apply network configuration changes via nmcli (if available).
    Supports: static IP, gateway, DNS for a given interface.
    Falls back to informational instructions if nmcli is unavailable.
    """
    iface = body.get("interface", "").strip()
    address = body.get("address", "").strip()       # e.g. 192.168.1.10/24
    gateway = body.get("gateway", "").strip()
    dns = body.get("dns", "").strip()               # comma-separated
    mode = body.get("mode", "static")               # static | dhcp

    if not iface:
        raise HTTPException(400, "interface is required")

    # Validate IP if static
    if mode == "static" and address:
        try:
            ipaddress.ip_interface(address)
        except ValueError:
            raise HTTPException(400, f"Invalid address: {address}")
    if gateway:
        try:
            ipaddress.ip_address(gateway)
        except ValueError:
            raise HTTPException(400, f"Invalid gateway: {gateway}")

    # Try nmcli
    rc, _, _ = _run(["which", "nmcli"])
    if rc != 0:
        # nmcli not available – return manual instructions
        logger.info(f"Network config change requested for {iface} (nmcli not available)")
        instructions = _build_manual_instructions(iface, address, gateway, dns, mode)
        return {"applied": False, "method": "manual", "instructions": instructions}

    try:
        cmds = []
        con_name = iface  # nmcli connection name often matches interface name

        if mode == "dhcp":
            cmds = [["nmcli", "connection", "modify", con_name, "ipv4.method", "auto"],
                    ["nmcli", "connection", "up", con_name]]
        else:
            if address:
                cmds.append(["nmcli", "connection", "modify", con_name,
                              "ipv4.method", "manual",
                              "ipv4.addresses", address])
            if gateway:
                cmds.append(["nmcli", "connection", "modify", con_name,
                              "ipv4.gateway", gateway])
            if dns:
                cmds.append(["nmcli", "connection", "modify", con_name,
                              "ipv4.dns", dns.replace(",", " ")])
            cmds.append(["nmcli", "connection", "up", con_name])

        errors = []
        for cmd in cmds:
            rc2, stdout, stderr = _run(cmd, timeout=15)
            if rc2 != 0:
                errors.append(f"{' '.join(cmd)}: {stderr.strip()}")

        if errors:
            logger.warning(f"Network config partial failure for {iface}: {errors}")
            return {"applied": False, "method": "nmcli", "errors": errors}

        logger.info(f"Network config applied for {iface}: mode={mode} addr={address} gw={gateway}")
        return {"applied": True, "method": "nmcli"}

    except Exception as e:
        logger.error(f"Network config apply failed: {e}")
        raise HTTPException(500, str(e))


def _build_manual_instructions(iface, address, gateway, dns, mode):
    """Build shell commands for manual application when nmcli is unavailable."""
    lines = [f"# Apply on the host as root / via sudo:"]
    if mode == "dhcp":
        lines += [f"dhclient {iface}",
                  f"# or: ip link set {iface} up && dhcpcd {iface}"]
    else:
        if address:
            lines.append(f"ip addr add {address} dev {iface}")
        if gateway:
            lines.append(f"ip route replace default via {gateway} dev {iface}")
        if dns:
            for srv in dns.split(","):
                lines.append(f"echo 'nameserver {srv.strip()}' >> /etc/resolv.conf")
    return "\n".join(lines)

# ── Rules Management ──────────────────────────────────────────────────────────

import yaml as _yaml
from threading import Lock as _Lock

_rules_lock = _Lock()


def _rules_path() -> Path:
    return Path(settings.pibg_rules_path)


def _load_rules_raw() -> list:
    p = _rules_path()
    if not p.exists():
        return []
    with open(p, "r", encoding="utf-8") as f:
        data = _yaml.safe_load(f)
    return data or []


def _save_rules_raw(rules: list) -> None:
    p = _rules_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write("# PiBroadGuard – Default Rules\n")
        f.write("# Regelwerk für Broadcast Device Security Assessment\n\n")
        _yaml.dump(rules, f, allow_unicode=True, default_flow_style=False,
                   sort_keys=False, width=120)


@router.get("/rules")
def list_rules(user: str = Depends(verify_credentials)):
    """Return all rules from the YAML ruleset."""
    return _load_rules_raw()


@router.post("/rules")
def create_rule(body: dict, user: str = Depends(verify_credentials)):
    """Add a new rule to the YAML ruleset."""
    rk = (body.get("rule_key") or "").strip()
    if not rk:
        raise HTTPException(400, "rule_key ist erforderlich")
    with _rules_lock:
        rules = _load_rules_raw()
        if any(r.get("rule_key") == rk for r in rules):
            raise HTTPException(409, f"Regel '{rk}' existiert bereits")
        rule = _build_rule_dict(body)
        rules.append(rule)
        _save_rules_raw(rules)
    logger.info(f"Rule created: {rk} by {user}")
    return rule


@router.put("/rules/{rule_key}")
def update_rule(rule_key: str, body: dict, user: str = Depends(verify_credentials)):
    """Update an existing rule in the YAML ruleset."""
    with _rules_lock:
        rules = _load_rules_raw()
        idx = next((i for i, r in enumerate(rules) if r.get("rule_key") == rule_key), None)
        if idx is None:
            raise HTTPException(404, f"Regel '{rule_key}' nicht gefunden")
        updated = _build_rule_dict(body, existing=rules[idx])
        updated["rule_key"] = rule_key  # key is immutable
        rules[idx] = updated
        _save_rules_raw(rules)
    logger.info(f"Rule updated: {rule_key} by {user}")
    return updated


@router.delete("/rules/{rule_key}")
def delete_rule(rule_key: str, user: str = Depends(verify_credentials)):
    """Delete a rule from the YAML ruleset."""
    with _rules_lock:
        rules = _load_rules_raw()
        new_rules = [r for r in rules if r.get("rule_key") != rule_key]
        if len(new_rules) == len(rules):
            raise HTTPException(404, f"Regel '{rule_key}' nicht gefunden")
        _save_rules_raw(new_rules)
    logger.info(f"Rule deleted: {rule_key} by {user}")
    return {"deleted": True, "rule_key": rule_key}


@router.post("/rules/{rule_key}/move")
def move_rule(rule_key: str, body: dict, user: str = Depends(verify_credentials)):
    """Move a rule up or down in the list (direction: 'up' or 'down')."""
    direction = body.get("direction", "up")
    with _rules_lock:
        rules = _load_rules_raw()
        idx = next((i for i, r in enumerate(rules) if r.get("rule_key") == rule_key), None)
        if idx is None:
            raise HTTPException(404, f"Regel '{rule_key}' nicht gefunden")
        if direction == "up" and idx > 0:
            rules[idx], rules[idx - 1] = rules[idx - 1], rules[idx]
        elif direction == "down" and idx < len(rules) - 1:
            rules[idx], rules[idx + 1] = rules[idx + 1], rules[idx]
        _save_rules_raw(rules)
    return {"moved": True}


def _build_rule_dict(body: dict, existing: dict = None) -> dict:
    """Build a validated rule dict from request body."""
    base = existing.copy() if existing else {}
    # Condition sub-dict
    cond_type = body.get("condition_type") or (base.get("condition") or {}).get("type", "port_open")
    condition: dict = {"type": cond_type}
    if cond_type == "port_open":
        port = body.get("condition_port")
        if port is not None:
            condition["port"] = int(port)
        proto = body.get("condition_protocol", "").strip()
        if proto and proto != "tcp":
            condition["protocol"] = proto
    elif cond_type == "service_detected":
        svc = body.get("condition_service", "").strip()
        if svc:
            condition["service"] = svc
    elif cond_type == "manual_answer":
        qk = body.get("condition_question_key", "").strip()
        ans = body.get("condition_answer", "no").strip()
        if qk:
            condition["question_key"] = qk
        condition["answer"] = ans

    severity = body.get("severity", base.get("severity", "medium"))
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "medium"
    affects = body.get("affects_score", base.get("affects_score", "technical"))
    if affects not in ("technical", "operational", "lifecycle", "vendor", "compensation"):
        affects = "technical"

    return {
        "rule_key": body.get("rule_key", base.get("rule_key", "")),
        "title": body.get("title", base.get("title", "")),
        "description": body.get("description", base.get("description", "")),
        "condition": condition,
        "severity": severity,
        "broadcast_context": body.get("broadcast_context", base.get("broadcast_context", "")),
        "recommendation": body.get("recommendation", base.get("recommendation", "")),
        "ask_compensation": bool(body.get("ask_compensation", base.get("ask_compensation", False))),
        "affects_score": affects,
    }


# ── Device-type → Scan Profile Suggestion ────────────────────────────────────
# Based on IEC 62443 / NIST SP 800-115 / BSI ICS recommendations.
# Broadcast/embedded devices: passive only in production.
# IT systems and network gear: standard or extended acceptable.
_DEVICE_TYPE_PROFILE_MAP = {
    # Broadcast – highly sensitive, low tolerance for active scanning
    "encoder":          {"profile": "passive",   "reason": "Broadcast-Encoder sind empfindlich auf Netzwerklast – Passive empfohlen (IEC 62443)."},
    "decoder":          {"profile": "passive",   "reason": "Broadcast-Decoder sind empfindlich auf Netzwerklast – Passive empfohlen (IEC 62443)."},
    "matrix":           {"profile": "passive",   "reason": "Signalmatrix – Passive empfohlen, Standard nur im Wartungsfenster."},
    "camera":           {"profile": "passive",   "reason": "Kameras reagieren empfindlich auf Scans – Passive zwingend in Produktion."},
    "monitor":          {"profile": "passive",   "reason": "Broadcast-Monitor – Passive empfohlen."},
    "multiviewer":      {"profile": "passive",   "reason": "Multiviewer – empfindlich, Passive empfohlen."},
    "frame_sync":       {"profile": "passive",   "reason": "Frame-Sync – eingebettetes Gerät, Passive empfohlen."},
    "signal_processor": {"profile": "passive",   "reason": "Signalprozessor – eingebettetes Gerät, Passive empfohlen."},
    "playout":          {"profile": "standard",  "reason": "Playout-Server – oft Linux/Windows-Basis, Standard akzeptabel."},
    "transcoder":       {"profile": "standard",  "reason": "Transcoder – oft Linux-Basis, Standard akzeptabel."},
    "intercom":         {"profile": "passive",   "reason": "Intercom-System – echtzeitkritisch, Passive empfohlen."},
    # Network gear
    "router":           {"profile": "standard",  "reason": "Router – robuste IT-Plattform, Standard akzeptabel."},
    "switch":           {"profile": "extended",  "reason": "Switch – Extended sinnvoll für SNMP/Discovery (UDP 161)."},
    # Generic
    "other":            {"profile": "passive",   "reason": "Unbekannter Gerätetyp – Passive als sicherster Ausgangspunkt."},
}


@router.get("/system/scan-profile-suggestion")
def get_scan_profile_suggestion(
    device_type: str,
    user: str = Depends(verify_credentials),
):
    """Return recommended scan profile for a given device type."""
    suggestion = _DEVICE_TYPE_PROFILE_MAP.get(
        device_type.lower(),
        {"profile": "passive", "reason": "Unbekannter Typ – Passive als sicherer Standard."},
    )
    return {
        "device_type": device_type,
        "suggested_profile": suggestion["profile"],
        "reason": suggestion["reason"],
        "standard_ref": "IEC 62443-3-2 / NIST SP 800-115 / BSI ICS Security Compendium",
    }
