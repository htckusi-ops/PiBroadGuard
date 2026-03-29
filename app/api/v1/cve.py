import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.services import csaf_service, cve_service, remediation_service

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["cve"])


@router.get("/cve/lookup")
async def cve_lookup(
    vendor: str,
    product: str,
    version: str = "",
    cpe_name: str = "",
    has_kev: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """
    Look up CVEs for a given vendor/product.

    Optional parameters:
    - cpe_name: CPE 2.3 identifier for precise lookup (e.g. cpe:2.3:h:lawo:mc2-56:*)
    - has_kev: if true, return only CVEs listed in the CISA KEV catalog
    """
    results = await cve_service.lookup_cves(
        db, vendor, product, version,
        cpe_name=cpe_name or None,
        has_kev=has_kev,
    )
    # Enrich with EPSS scores where available (graceful fallback if offline)
    cve_ids = [r["cve_id"] for r in results if r.get("cve_id")]
    epss_map = await cve_service.get_epss_scores(cve_ids) if cve_ids else {}
    for r in results:
        epss = epss_map.get(r["cve_id"], {})
        r["epss_score"] = epss.get("epss")       # float 0–1 or None
        r["epss_percentile"] = epss.get("percentile")  # float 0–1 or None
    return {"vendor": vendor, "product": product, "cves": results}


@router.get("/cve/epss")
async def epss_lookup(
    cve: str,
    user: str = Depends(verify_credentials),
):
    """
    EPSS (Exploit Prediction Scoring System) score for one or more CVEs.
    Pass comma-separated CVE IDs: ?cve=CVE-2021-44228,CVE-2022-26134
    Source: FIRST.org – free, no API key required.
    epss_score: probability (0–1) of exploitation in the wild within 30 days.
    epss_percentile: rank among all EPSS-scored CVEs.
    """
    cve_ids = [c.strip() for c in cve.split(",") if c.strip()]
    scores = await cve_service.get_epss_scores(cve_ids)
    return {"scores": scores}


@router.get("/cve/cpe-resolve")
async def resolve_cpe_endpoint(
    vendor: str,
    product: str,
    user: str = Depends(verify_credentials),
):
    """
    Resolve a CPE name for a given vendor+product via NVD CPE API v2.
    Returns the first matching CPE name for use in precise CVE lookups.
    """
    cpe_name = await cve_service.resolve_cpe(vendor, product)
    return {"vendor": vendor, "product": product, "cpe_name": cpe_name}


@router.post("/cve/csaf-import")
async def csaf_import(
    url: str = "",
    file: UploadFile = File(None),
    user: str = Depends(verify_credentials),
):
    """
    Import a CSAF 2.0 vendor advisory.

    Provide either:
    - url: public URL of a CSAF 2.0 JSON document
    - file: uploaded CSAF 2.0 JSON file

    Returns extracted CVEs, affected products, CVSS scores, and remediation actions.
    """
    if not url and not file:
        raise HTTPException(400, "Entweder 'url' oder 'file' muss angegeben werden")
    try:
        if url:
            result = await csaf_service.fetch_and_parse(url)
        else:
            content = await file.read()
            result = csaf_service.parse_uploaded(content)
    except csaf_service.CsafParseError as e:
        raise HTTPException(422, str(e))
    return result


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
