"""
CSAF 2.0 Vendor Advisory Service
----------------------------------
CSAF (Common Security Advisory Framework) v2.0 is a machine-readable format for
security advisories. Vendors such as Siemens, Bosch, Cisco, and others publish
CSAF 2.0 documents.

This minimal implementation:
  - Fetches a CSAF 2.0 JSON document from a URL or accepts uploaded bytes
  - Extracts CVE IDs, product information, CVSS scores, and remediation actions
  - Returns structured results that can be attached to findings as remediation_sources

CSAF 2.0 spec: https://docs.oasis-open.org/csaf/csaf/v2.0/
"""
import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger("pibroadguard.csaf")


class CsafParseError(Exception):
    pass


def parse_csaf_document(data: dict) -> dict:
    """
    Parse a CSAF 2.0 JSON document and return a structured summary.

    Returns:
        {
            "title": str,
            "publisher": str,
            "tracking_id": str,
            "severity": str,           # "Critical" | "High" | "Medium" | "Low"
            "cve_ids": list[str],
            "products": list[str],     # affected product names
            "remediations": list[dict], # {category, details, url, product_ids}
            "cvss_scores": list[dict],  # {cve_id, score, vector}
            "initial_release": str,
            "current_release": str,
            "summary": str,
        }
    """
    doc_type = data.get("document", {}).get("category", "")
    if doc_type not in ("csaf_security_advisory", "csaf_vex", "csaf_base"):
        # Accept loosely – some vendors use custom categories
        if "vulnerabilities" not in data and "document" not in data:
            raise CsafParseError("Does not appear to be a valid CSAF 2.0 document")

    doc = data.get("document", {})
    tracking = doc.get("tracking", {})
    aggregate_severity = doc.get("aggregate_severity", {})

    # CVE IDs
    cve_ids = []
    cvss_scores = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve")
        if cve:
            cve_ids.append(cve)
        # CVSS scores
        scores = vuln.get("scores", [])
        for score_entry in scores:
            for version in ("cvss_v31", "cvss_v30", "cvss_v40"):
                if version in score_entry:
                    cvss_data = score_entry[version]
                    cvss_scores.append({
                        "cve_id": cve or "",
                        "score": cvss_data.get("baseScore"),
                        "vector": cvss_data.get("vectorString"),
                        "version": version,
                    })
                    break

    # Affected products from product tree
    products = []
    product_tree = data.get("product_tree", {})
    for branch in _walk_branches(product_tree.get("branches", [])):
        if branch.get("category") in ("product_name", "product_version"):
            name = branch.get("name", "")
            if name and name not in products:
                products.append(name)
    # Also check full_product_names
    for fp in product_tree.get("full_product_names", []):
        name = fp.get("name", "")
        if name and name not in products:
            products.append(name)

    # Remediations
    remediations = []
    for vuln in data.get("vulnerabilities", []):
        for rem in vuln.get("remediations", []):
            remediations.append({
                "category": rem.get("category", ""),  # vendor_fix, workaround, mitigation, none_available
                "details": rem.get("details", ""),
                "url": rem.get("url"),
                "product_ids": rem.get("product_ids", []),
                "date": rem.get("date"),
            })

    return {
        "title": doc.get("title", ""),
        "publisher": doc.get("publisher", {}).get("name", ""),
        "tracking_id": tracking.get("id", ""),
        "severity": aggregate_severity.get("text", ""),
        "cve_ids": cve_ids,
        "products": products[:20],
        "remediations": remediations,
        "cvss_scores": cvss_scores,
        "initial_release": tracking.get("initial_release_date"),
        "current_release": tracking.get("current_release_date"),
        "summary": (data.get("document", {}).get("notes") or [{}])[0].get("text", "") if data.get("document", {}).get("notes") else "",
    }


async def fetch_and_parse(url: str) -> dict:
    """
    Fetch a CSAF 2.0 document from a URL and parse it.
    Returns the structured summary or raises CsafParseError.
    """
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as e:
        raise CsafParseError(f"HTTP {e.response.status_code} fetching {url}") from e
    except Exception as e:
        raise CsafParseError(f"Failed to fetch CSAF document: {e}") from e

    return parse_csaf_document(data)


def parse_uploaded(content: bytes) -> dict:
    """Parse a CSAF 2.0 document from uploaded bytes."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise CsafParseError(f"Invalid JSON: {e}") from e
    return parse_csaf_document(data)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _walk_branches(branches: list) -> list:
    """Recursively flatten CSAF product tree branches."""
    result = []
    for branch in branches:
        result.append(branch)
        result.extend(_walk_branches(branch.get("branches", [])))
    return result
