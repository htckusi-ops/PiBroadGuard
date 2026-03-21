import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.kev_cache import KevCache

logger = logging.getLogger("pibroadguard.remediation")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CWE_RECOMMENDATIONS = {
    "CWE-287": "Authentifizierung prüfen/verstärken; Default-Credentials ändern",
    "CWE-306": "Fehlende Authentifizierung – Zugangskontrolle implementieren",
    "CWE-319": "Klartextübertragung – Verschlüsselung aktivieren (TLS/SSH)",
    "CWE-321": "Hardcoded Credentials entfernen; Key-Management einführen",
    "CWE-326": "Schwache Kryptografie – auf TLS 1.2+ und starke Cipher upgraden",
    "CWE-522": "Schwache Passwörter – Passwortpolicy und -komplexität erzwingen",
    "CWE-693": "Fehlende Schutzebenen – Defense-in-Depth und Netzwerksegmentierung",
    "CWE-862": "Fehlende Autorisierungsprüfung – RBAC implementieren",
}


def check_kev(db: Session, cve_id: str) -> Optional[KevCache]:
    return db.query(KevCache).filter(KevCache.cve_id == cve_id).first()


def get_cwe_recommendation(cwe_id: str) -> Optional[str]:
    if not cwe_id:
        return None
    return CWE_RECOMMENDATIONS.get(cwe_id)


async def sync_kev_cache(db: Session) -> int:
    logger.info("Starting KEV cache sync")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        count = 0
        for v in vulns:
            cve_id = v.get("cveID")
            if not cve_id:
                continue
            due_raw = v.get("dueDate")
            added_raw = v.get("dateAdded")
            entry = KevCache(
                cve_id=cve_id,
                vendor_project=v.get("vendorProject"),
                product=v.get("product"),
                vulnerability_name=v.get("vulnerabilityName"),
                required_action=v.get("requiredAction"),
                due_date=_parse_date(due_raw),
                known_ransomware=v.get("knownRansomwareCampaignUse") == "Known",
                date_added_to_kev=_parse_date(added_raw),
                fetched_at=datetime.now(timezone.utc),
            )
            db.merge(entry)
            count += 1
        db.commit()
        logger.info(f"KEV sync complete: {count} entries")
        return count
    except Exception as e:
        logger.error(f"KEV sync failed: {e}")
        return 0


async def sync_kev_if_stale(db: Session, max_age_hours: int = 24) -> None:
    latest = db.query(KevCache).order_by(KevCache.fetched_at.desc()).first()
    if latest and latest.fetched_at:
        age = datetime.now(timezone.utc) - latest.fetched_at.replace(tzinfo=timezone.utc)
        if age.total_seconds() < max_age_hours * 3600:
            return
    await sync_kev_cache(db)


def _parse_date(raw: Optional[str]):
    if not raw:
        return None
    try:
        from datetime import date
        return date.fromisoformat(raw)
    except Exception:
        return None
