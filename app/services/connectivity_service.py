import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("pibroadguard.connectivity")

_state = {
    "auto_detected": None,
    "last_check": None,
}


async def check_internet() -> bool:
    url = settings.pibg_connectivity_check_url
    timeout = settings.pibg_connectivity_timeout
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.head(url, timeout=timeout, follow_redirects=True)
        reachable = resp.status_code < 500
    except Exception:
        reachable = False
    _state["auto_detected"] = reachable
    _state["last_check"] = datetime.now(timezone.utc)
    logger.info(f"Connectivity check: nvd_reachable={reachable}")
    return reachable


def get_effective_mode(db_mode: str) -> str:
    if db_mode == "force_online":
        return "online"
    if db_mode == "force_offline":
        return "offline"
    return "online" if _state.get("auto_detected") else "offline"


def is_online(db_mode: str) -> bool:
    return get_effective_mode(db_mode) == "online"


async def periodic_check(interval_seconds: int = 3600):
    while True:
        try:
            await check_internet()
        except Exception as e:
            logger.error(f"Connectivity check error: {e}")
        await asyncio.sleep(interval_seconds)
