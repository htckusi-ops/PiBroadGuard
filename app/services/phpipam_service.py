"""phpIPAM REST API integration service."""
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("pibroadguard.phpipam")


class PhpIpamService:
    def __init__(self, base_url: str, app_id: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.app_id = app_id
        self.token = token
        self._headers = {
            "token": token,
            "Content-Type": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api/{self.app_id}/{path.lstrip('/')}"

    async def test_connection(self) -> Dict[str, Any]:
        """Test phpIPAM connection and authentication."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(self._url("sections/"), headers=self._headers)
            return {"ok": resp.status_code == 200, "status_code": resp.status_code}

    async def lookup_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Lookup a host by IP address. Returns phpIPAM address record or None."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                self._url(f"addresses/search/{ip}/"),
                headers=self._headers,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("success") and data.get("data"):
                host = data["data"][0]
                return self._normalize(host)
            return None

    async def lookup_by_id(self, phpipam_id: int) -> Optional[Dict[str, Any]]:
        """Lookup a host by phpIPAM address ID."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                self._url(f"addresses/{phpipam_id}/"),
                headers=self._headers,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("success") and data.get("data"):
                return self._normalize(data["data"])
            return None

    async def search_hosts(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search hosts by hostname or IP fragment."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                self._url(f"addresses/search/{query}/"),
                headers=self._headers,
                params={"limit": limit},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            if data.get("success") and data.get("data"):
                return [self._normalize(h) for h in data["data"]]
            return []

    async def get_subnets(self) -> List[Dict[str, Any]]:
        """Get all subnets from phpIPAM."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(self._url("subnets/"), headers=self._headers)
            if resp.status_code != 200:
                return []
            data = resp.json()
            return data.get("data", []) if data.get("success") else []

    async def get_hosts_in_subnet(self, subnet_id: int) -> List[Dict[str, Any]]:
        """Get all hosts in a specific subnet."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"subnets/{subnet_id}/addresses/"),
                headers=self._headers,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            if data.get("success") and data.get("data"):
                return [self._normalize(h) for h in data["data"]]
            return []

    @staticmethod
    def _normalize(host: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a phpIPAM address record to BDSA device fields."""
        return {
            "phpipam_id": int(host.get("id", 0)),
            "ip_address": host.get("ip", ""),
            "hostname": host.get("hostname", ""),
            "mac_address": host.get("mac", ""),
            "description": host.get("description", ""),
            "owner": host.get("owner", ""),
            "location": host.get("location", ""),
            "note": host.get("note", ""),
            "subnet_id": host.get("subnetId", ""),
        }


def get_phpipam_service() -> Optional[PhpIpamService]:
    """Create a PhpIpamService from app settings. Returns None if not configured."""
    from app.core.config import settings
    if not settings.pibg_phpipam_url or not settings.pibg_phpipam_token:
        return None
    return PhpIpamService(
        base_url=settings.pibg_phpipam_url,
        app_id=settings.pibg_phpipam_app_id,
        token=settings.pibg_phpipam_token,
    )
