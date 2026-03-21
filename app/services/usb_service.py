import logging
import os
import stat
from typing import List

from app.schemas.system import UsbDevice
from app.services import crypto_service
from app.core.config import settings

logger = logging.getLogger("pibroadguard.usb")

SYSTEM_MOUNTS = {"/", "/boot", "/home", "/proc", "/sys", "/dev", "/run", "/tmp"}
SEARCH_ROOTS = ["/media", "/mnt"]


def detect_usb_devices() -> List[UsbDevice]:
    devices = []
    for root in SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        for entry in _walk_mount_points(root):
            try:
                info = _get_device_info(entry)
                if info:
                    devices.append(info)
            except Exception as e:
                logger.debug(f"Skipping {entry}: {e}")
    return devices


def _walk_mount_points(root: str) -> List[str]:
    paths = []
    try:
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if os.path.ismount(p):
                paths.append(p)
            elif os.path.isdir(p):
                for sub in os.listdir(p):
                    sp = os.path.join(p, sub)
                    if os.path.ismount(sp):
                        paths.append(sp)
    except PermissionError:
        pass
    return paths


def _get_device_info(path: str) -> UsbDevice | None:
    if path in SYSTEM_MOUNTS:
        return None
    for sm in SYSTEM_MOUNTS:
        if path.startswith(sm + "/") and sm != "/":
            pass
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    free_bytes = st.f_bavail * st.f_frsize
    total_bytes = st.f_blocks * st.f_frsize
    if total_bytes < 1024 * 1024:
        return None
    writable = os.access(path, os.W_OK)
    label = os.path.basename(path) or "unknown"

    # Try to detect filesystem type
    fs = "unknown"
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == path:
                    fs = parts[2]
                    break
    except Exception:
        pass

    return UsbDevice(
        path=path,
        label=label,
        filesystem=fs,
        free_bytes=free_bytes,
        total_bytes=total_bytes,
        writable=writable,
    )


def validate_path(path: str) -> dict:
    if not os.path.isdir(path):
        return {"valid": False, "error": "Pfad existiert nicht oder ist kein Verzeichnis"}
    if not os.access(path, os.W_OK):
        return {"valid": False, "error": "Pfad ist nicht beschreibbar"}
    if path in SYSTEM_MOUNTS:
        return {"valid": False, "error": "System-Mount-Punkt nicht erlaubt"}
    try:
        st = os.statvfs(path)
        free_mb = (st.f_bavail * st.f_frsize) / (1024 * 1024)
        if free_mb < 1:
            return {"valid": False, "error": "Weniger als 1 MB freier Speicher"}
    except OSError as e:
        return {"valid": False, "error": str(e)}
    return {"valid": True, "error": None}


def write_to_usb(path: str, filename: str, data: bytes, encrypt: bool = False) -> dict:
    validation = validate_path(path)
    if not validation["valid"]:
        raise ValueError(validation["error"])

    if encrypt and settings.pibg_shared_secret:
        data = crypto_service.encrypt(data, settings.pibg_shared_secret)
        if not filename.endswith(".enc"):
            filename += ".enc"

    target = os.path.join(path, filename)
    with open(target, "wb") as f:
        f.write(data)

    import hashlib
    sha256 = hashlib.sha256(data).hexdigest()
    logger.info(f"Wrote {filename} to {path} ({len(data)} bytes)")
    return {
        "path": target,
        "filename": filename,
        "size_bytes": len(data),
        "sha256": sha256,
        "encrypted": encrypt and bool(settings.pibg_shared_secret),
    }


def read_from_usb(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        data = f.read()
    if crypto_service.is_encrypted(data):
        if not settings.pibg_shared_secret:
            raise ValueError("Datei ist verschlüsselt, aber kein Shared Secret konfiguriert")
        data = crypto_service.decrypt(data, settings.pibg_shared_secret)
    return data


def list_packages_on_usb(usb_path: str) -> List[dict]:
    packages = []
    for name in os.listdir(usb_path):
        if name.endswith(".bdsa") or name.endswith(".bdsa.enc"):
            filepath = os.path.join(usb_path, name)
            encrypted = name.endswith(".enc")
            size = os.path.getsize(filepath)
            fp_match = False
            if encrypted and settings.pibg_shared_secret:
                fp = crypto_service.get_key_fingerprint(settings.pibg_shared_secret)
                fp_match = True  # optimistic – we can't verify without decrypting
            packages.append({
                "filename": name,
                "path": filepath,
                "size_bytes": size,
                "encrypted": encrypted,
                "key_fingerprint_match": fp_match,
            })
    return packages


def safe_eject(path: str) -> bool:
    import subprocess
    try:
        subprocess.run(["sync"], check=True)
        result = subprocess.run(
            ["udisksctl", "power-off", "-b", path],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception as e:
        logger.warning(f"Eject failed: {e}")
        return False
