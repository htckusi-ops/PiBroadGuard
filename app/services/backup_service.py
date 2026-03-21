import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import text

from app.core.config import settings
from app.services import crypto_service

logger = logging.getLogger("pibroadguard.backup")


def create_backup(db_session, destination: str = "local", usb_path: str = None, encrypt: bool = False) -> dict:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"pibroadguard-backup-{timestamp}.db"
    if encrypt:
        filename += ".enc"

    if destination == "local":
        backup_dir = Path("./data/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)
        target = str(backup_dir / filename.replace(".enc", ""))
        db_session.execute(text(f"VACUUM INTO '{target}'"))
        db_session.commit()

        with open(target, "rb") as f:
            data = f.read()

        if encrypt and settings.pibg_shared_secret:
            data = crypto_service.encrypt(data, settings.pibg_shared_secret)
            os.unlink(target)
            target += ".enc"
            with open(target, "wb") as f:
                f.write(data)

        _cleanup_old_backups(backup_dir, settings.pibg_backup_max_count)
        logger.info(f"Backup created: {target}")
        return {"filename": os.path.basename(target), "path": target, "size_bytes": len(data)}

    elif destination == "usb":
        if not usb_path:
            raise ValueError("USB-Pfad muss angegeben werden")
        tmp_target = f"/tmp/pibroadguard-backup-{timestamp}.db"
        db_session.execute(text(f"VACUUM INTO '{tmp_target}'"))
        db_session.commit()
        with open(tmp_target, "rb") as f:
            data = f.read()
        os.unlink(tmp_target)

        if encrypt and settings.pibg_shared_secret:
            data = crypto_service.encrypt(data, settings.pibg_shared_secret)

        from app.services.usb_service import write_to_usb
        result = write_to_usb(usb_path, filename, data, encrypt=False)
        logger.info(f"Backup written to USB: {result['path']}")
        return result

    raise ValueError(f"Unbekanntes Ziel: {destination}")


def list_backups() -> list:
    backup_dir = Path("./data/backups")
    if not backup_dir.exists():
        return []
    backups = []
    for f in sorted(backup_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.suffix in (".db", ".enc"):
            backups.append({
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "created_at": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
                "encrypted": f.name.endswith(".enc"),
            })
    return backups


def _cleanup_old_backups(backup_dir: Path, max_count: int) -> None:
    files = sorted(backup_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)
    for old in files[max_count:]:
        try:
            old.unlink()
            logger.info(f"Deleted old backup: {old.name}")
        except Exception as e:
            logger.warning(f"Failed to delete old backup {old.name}: {e}")
