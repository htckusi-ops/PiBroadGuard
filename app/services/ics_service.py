"""
CISA ICS Advisories Service
-----------------------------
Syncs CISA Industrial Control System (ICS) security advisories from the CISA RSS
feed into a local cache. ICS advisories cover embedded, appliance-type, and
OT/industrial devices – broadcast equipment frequently falls into this category.

Feed URL: https://www.cisa.gov/uscert/ics/advisories (RSS)
Advisory format: ICSA-YY-DDD-NN or ICSMA-YY-DDD-NN (medical)

Cache TTL: 24 h (same as KEV)
Offline capable: existing cache is used when feed is unavailable.
"""
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone, timedelta
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from app.models.ics_advisory_cache import IcsAdvisoryCache

logger = logging.getLogger("pibroadguard.ics")

ICS_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
# Fallback URL (alternative CISA feed path observed in practice)
ICS_RSS_URL_ALT = "https://www.cisa.gov/uscert/ics/advisories/allalerts.xml"

ADVISORY_ID_RE = re.compile(r"(ICS[MA]?-\d{2}-\d{3}-\d{2})", re.IGNORECASE)

# How many items to import per sync (RSS feeds typically show 20–100 recent items)
MAX_ITEMS_PER_SYNC = 100


def _parse_date(date_str: str) -> Optional[date]:
    for fmt in ("%Y-%m-%d", "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S GMT"):
        try:
            return datetime.strptime(date_str[:len(fmt.replace("%", "xx"))], fmt).date()
        except ValueError:
            pass
    try:
        # ISO 8601 datetime string
        return datetime.fromisoformat(date_str[:19]).date()
    except ValueError:
        pass
    return None


def _extract_advisory_id(text: str) -> Optional[str]:
    m = ADVISORY_ID_RE.search(text or "")
    return m.group(1).upper() if m else None


def _extract_cve_ids(text: str) -> list[str]:
    return re.findall(r"CVE-\d{4}-\d{4,7}", text or "")


def _extract_cvss(text: str) -> Optional[str]:
    m = re.search(r"CVSS\s+(?:v\d\s+)?[Ss]core[:\s]+(\d+(?:\.\d+)?)", text or "")
    return m.group(1) if m else None


async def sync_ics_advisories(db: Session) -> dict:
    """
    Download CISA ICS advisory RSS feed and upsert entries into ics_advisory_cache.
    Returns a summary dict with counts.
    """
    logger.info("Starting CISA ICS advisory sync")
    xml_bytes = await _fetch_rss()
    if not xml_bytes:
        logger.warning("ICS advisory sync skipped – feed unavailable")
        return {"synced": 0, "error": "feed unavailable"}

    items = _parse_rss(xml_bytes)
    new_count = 0
    for item in items[:MAX_ITEMS_PER_SYNC]:
        advisory_id = item.get("advisory_id")
        if not advisory_id:
            continue
        existing = db.query(IcsAdvisoryCache).filter_by(advisory_id=advisory_id).first()
        if existing:
            # Update fetched_at and any changed fields
            existing.title = item.get("title") or existing.title
            existing.summary = item.get("summary") or existing.summary
            existing.cve_ids = item.get("cve_ids") or existing.cve_ids
            existing.cvss_score = item.get("cvss_score") or existing.cvss_score
            existing.updated_date = item.get("updated_date") or existing.updated_date
            existing.fetched_at = datetime.now(timezone.utc)
        else:
            db.add(IcsAdvisoryCache(**item))
            new_count += 1

    db.commit()
    total = db.query(IcsAdvisoryCache).count()
    logger.info(f"ICS advisory sync done: {new_count} new, {total} total in cache")
    return {"synced": new_count, "total": total}


def search_advisories(
    db: Session,
    vendor: str = "",
    product: str = "",
    cve_id: str = "",
) -> list[IcsAdvisoryCache]:
    """
    Search cached ICS advisories for a given vendor, product, or CVE ID.
    Returns matching advisories (up to 20).
    """
    q = db.query(IcsAdvisoryCache)
    filters = []
    if vendor:
        filters.append(IcsAdvisoryCache.vendor.ilike(f"%{vendor}%"))
    if product:
        filters.append(IcsAdvisoryCache.product.ilike(f"%{product}%"))
    if cve_id:
        filters.append(IcsAdvisoryCache.cve_ids.contains(cve_id))
    if filters:
        from sqlalchemy import or_
        q = q.filter(or_(*filters))
    return q.order_by(IcsAdvisoryCache.published_date.desc()).limit(20).all()


def get_cache_age(db: Session) -> Optional[datetime]:
    """Return the fetched_at timestamp of the most recent advisory in cache."""
    latest = (
        db.query(IcsAdvisoryCache)
        .order_by(IcsAdvisoryCache.fetched_at.desc())
        .first()
    )
    return latest.fetched_at if latest else None


def is_stale(db: Session, max_age_hours: int = 24) -> bool:
    age = get_cache_age(db)
    if not age:
        return True
    if age.tzinfo is None:
        age = age.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - age > timedelta(hours=max_age_hours)


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _fetch_rss() -> Optional[bytes]:
    for url in (ICS_RSS_URL, ICS_RSS_URL_ALT):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(url)
            if resp.status_code == 200:
                return resp.content
            logger.warning(f"ICS RSS fetch returned {resp.status_code} for {url}")
        except Exception as e:
            logger.warning(f"ICS RSS fetch failed ({url}): {e}")
    return None


def _parse_rss(xml_bytes: bytes) -> list[dict]:
    items = []
    try:
        root = ET.fromstring(xml_bytes)
        # Handle both RSS 2.0 (<channel><item>) and Atom (<feed><entry>)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        rss_items = root.findall(".//item") or root.findall(".//atom:entry", ns)
        for elem in rss_items:
            title = _text(elem, "title")
            link = _text(elem, "link") or _text(elem, "atom:link", ns)
            pub_date = _text(elem, "pubDate") or _text(elem, "atom:published", ns)
            upd_date = _text(elem, "atom:updated", ns)
            description = _text(elem, "description") or _text(elem, "atom:summary", ns)

            advisory_id = _extract_advisory_id(title or "") or _extract_advisory_id(link or "")
            cve_ids = _extract_cve_ids((description or "") + " " + (title or ""))
            cvss = _extract_cvss(description or "")

            # Best-effort vendor/product extraction from title
            # CISA advisory titles often follow: "Vendor Product: Vulnerability"
            vendor = ""
            product = ""
            if title:
                parts = title.split(":")
                if len(parts) >= 2:
                    vp = parts[0].strip()
                    vp_words = vp.split()
                    if vp_words:
                        vendor = vp_words[0]
                        product = " ".join(vp_words[1:]) if len(vp_words) > 1 else ""

            items.append({
                "advisory_id": advisory_id or _fallback_id(link or ""),
                "title": title,
                "vendor": vendor,
                "product": product,
                "summary": description[:2000] if description else None,
                "cve_ids": json.dumps(cve_ids) if cve_ids else None,
                "cvss_score": cvss,
                "advisory_url": link,
                "published_date": _parse_date(pub_date) if pub_date else None,
                "updated_date": _parse_date(upd_date) if upd_date else None,
                "fetched_at": datetime.now(timezone.utc),
            })
    except ET.ParseError as e:
        logger.error(f"ICS RSS XML parse error: {e}")
    return [i for i in items if i.get("advisory_id")]


def _text(elem: ET.Element, tag: str, ns: dict = None) -> Optional[str]:
    child = elem.find(tag, ns) if ns else elem.find(tag)
    if child is not None:
        return (child.text or "").strip() or None
    return None


def _fallback_id(url: str) -> Optional[str]:
    """Extract a unique ID from an advisory URL when ICSA ID is not in title."""
    m = re.search(r"/([A-Za-z0-9_-]+)/?$", url)
    return m.group(1)[:30] if m else None
