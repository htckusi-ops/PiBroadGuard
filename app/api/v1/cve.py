import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.services import cve_service, remediation_service

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["cve"])


@router.get("/cve/lookup")
async def cve_lookup(
    vendor: str,
    product: str,
    version: str = "",
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    results = await cve_service.lookup_cves(db, vendor, product, version)
    return {"vendor": vendor, "product": product, "cves": results}


@router.get("/findings/{finding_id}/remediation")
def get_remediation(
    finding_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.models.finding import Finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding nicht gefunden")

    kev = None
    if finding.cve_id:
        entry = remediation_service.check_kev(db, finding.cve_id)
        if entry:
            kev = {
                "cve_id": entry.cve_id,
                "required_action": entry.required_action,
                "known_ransomware": entry.known_ransomware,
                "due_date": str(entry.due_date) if entry.due_date else None,
            }

    cwe_rec = remediation_service.get_cwe_recommendation(finding.cwe_id) if finding.cwe_id else None

    return {
        "finding_id": finding_id,
        "rule_recommendation": finding.recommendation,
        "kev_entry": kev,
        "nvd_solution": finding.nvd_solution,
        "vendor_advisory_url": finding.vendor_advisory_url,
        "cwe_recommendation": cwe_rec,
    }
