import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.cve_cache import CveCache

logger = logging.getLogger("pibroadguard.cve")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
# EPSS – Exploit Prediction Scoring System by FIRST.org
# Free, no API key required. Returns exploitation probability (0–1) per CVE.
# Spec: https://www.first.org/epss/api
EPSS_BASE = "https://api.first.org/data/v1/epss"


async def lookup_cves(
    db: Session,
    vendor: str,
    product: str,
    version: str = "",
    cpe_name: Optional[str] = None,
    has_kev: bool = False,
) -> List[dict]:
    """
    Look up CVEs for a given vendor/product.

    If cpe_name is provided, uses CPE-based NVD query (more precise).
    If has_kev=True, filters for CVEs that are in the CISA KEV catalog.
    """
    cache_cutoff = datetime.now(timezone.utc) - timedelta(days=settings.pibg_cve_cache_ttl_days)
    cached = (
        db.query(CveCache)
        .filter(
            CveCache.vendor == vendor,
            CveCache.product == product,
            CveCache.fetched_at > cache_cutoff,
        )
        .all()
    )
    if cached:
        return [_to_dict(c) for c in cached]

    results = await _fetch_from_nvd(vendor, product, cpe_name=cpe_name, has_kev=has_kev)
    for r in results:
        # Only pass fields that exist on the CveCache model (safe subset)
        cache_fields = {
            k: v for k, v in r.items()
            if k in {"cve_id", "cvss_score", "description", "published_date",
                     "fetched_at", "nvd_solution", "vendor_advisory_url", "cwe_id"}
        }
        db.merge(CveCache(**cache_fields, vendor=vendor, product=product, version=version))
    db.commit()
    return results


async def resolve_cpe(vendor: str, product: str) -> Optional[str]:
    """
    Query NVD CPE API to find a structured CPE name for a given vendor+product.
    Returns the first matching CPE name (e.g. 'cpe:2.3:h:lawo:mc2-56:*:*:*:*:*:*:*:*')
    or None if not found.
    """
    headers = {}
    if settings.pibg_nvd_api_key:
        headers["apiKey"] = settings.pibg_nvd_api_key
    keyword = f"{vendor} {product}"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                NVD_CPE_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                headers=headers,
            )
        resp.raise_for_status()
        data = resp.json()
        products = data.get("products", [])
        if products:
            return products[0].get("cpe", {}).get("cpeName")
    except Exception as e:
        logger.warning(f"CPE lookup failed for {vendor}/{product}: {e}")
    return None


async def _fetch_from_nvd(
    vendor: str,
    product: str,
    cpe_name: Optional[str] = None,
    has_kev: bool = False,
) -> List[dict]:
    headers = {}
    if settings.pibg_nvd_api_key:
        headers["apiKey"] = settings.pibg_nvd_api_key

    # Build query params – CPE-based search is more precise than keyword search
    params: dict = {"resultsPerPage": 10}
    if cpe_name:
        params["cpeName"] = cpe_name
        params["isVulnerable"] = ""  # only confirmed-vulnerable CVEs for this CPE
    else:
        params["keywordSearch"] = f"{vendor} {product}"
    if has_kev:
        params["hasKev"] = ""  # restrict to CISA KEV-listed CVEs

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                NVD_BASE,
                params=params,
                headers=headers,
            )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            cvss = 0.0
            metrics = cve.get("metrics", {})
            for m in metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []):
                cvss = m.get("cvssData", {}).get("baseScore", 0.0)
                break
            pub_date = cve.get("published", "")[:10] if cve.get("published") else None
            solution = cve.get("evaluatorSolution")
            advisory_url = None
            for ref in cve.get("references", []):
                if "Vendor Advisory" in ref.get("tags", []):
                    advisory_url = ref.get("url")
                    break
            cwe_id = None
            for w in cve.get("weaknesses", []):
                for wd in w.get("description", []):
                    cwe_id = wd.get("value")
                    break
            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss,
                "description": desc,
                "published_date": pub_date,
                "fetched_at": datetime.now(timezone.utc),
                "nvd_solution": solution,
                "vendor_advisory_url": advisory_url,
                "cwe_id": cwe_id,
            })
        return results
    except Exception as e:
        logger.error(f"NVD fetch failed: {e}")
        return []


def _to_dict(c: CveCache) -> dict:
    return {
        "cve_id": c.cve_id,
        "cvss_score": c.cvss_score,
        "description": c.description,
        "published_date": str(c.published_date) if c.published_date else None,
        "fetched_at": c.fetched_at.isoformat() if c.fetched_at else None,
        "nvd_solution": getattr(c, "nvd_solution", None),
        "vendor_advisory_url": getattr(c, "vendor_advisory_url", None),
        "cwe_id": getattr(c, "cwe_id", None),
    }


async def get_epss_scores(cve_ids: List[str]) -> dict:
    """
    Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

    Returns a dict mapping CVE ID → {"epss": float, "percentile": float}.
    EPSS score: probability (0–1) that a vulnerability will be exploited in
    the wild within 30 days. Percentile: rank among all scored CVEs.

    Free, no API key. Graceful fallback (empty dict) if offline/unavailable.
    """
    if not cve_ids:
        return {}
    # API accepts comma-separated CVE IDs: ?cve=CVE-a,CVE-b
    cve_param = ",".join(cve_ids[:100])  # API limit
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(EPSS_BASE, params={"cve": cve_param})
        resp.raise_for_status()
        data = resp.json()
        result = {}
        for entry in data.get("data", []):
            cve_id = entry.get("cve", "")
            if cve_id:
                result[cve_id] = {
                    "epss": float(entry.get("epss", 0)),
                    "percentile": float(entry.get("percentile", 0)),
                }
        return result
    except Exception as e:
        logger.warning(f"EPSS lookup failed: {e}")
        return {}
