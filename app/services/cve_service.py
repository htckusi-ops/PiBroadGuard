import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.cve_cache import CveCache

logger = logging.getLogger("pibroadguard.cve")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def lookup_cves(
    db: Session,
    vendor: str,
    product: str,
    version: str = "",
) -> List[dict]:
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

    results = await _fetch_from_nvd(vendor, product)
    for r in results:
        db.merge(CveCache(**r, vendor=vendor, product=product, version=version))
    db.commit()
    return results


async def _fetch_from_nvd(vendor: str, product: str) -> List[dict]:
    keyword = f"{vendor} {product}"
    headers = {}
    if settings.pibg_nvd_api_key:
        headers["apiKey"] = settings.pibg_nvd_api_key

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                NVD_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": 10},
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
    }
