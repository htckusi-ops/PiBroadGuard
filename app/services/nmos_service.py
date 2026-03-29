"""
NMOS Passive Security Service
-------------------------------
Production-safe NMOS security checks that can be run against live Broadcast devices.

All checks are purely passive (no mDNS announcements, no state changes on the device):
  - TLS check: HTTP GET against NMOS IS-04 registry/node endpoint
  - Auth check: GET without Bearer token → expects 401 if IS-10 is active
  - IS-04 Registry discovery: query a known registry URL for nodes/devices/senders

NOT included here (Priorität 3 / optional):
  - AMWA nmos-testing sidecar: creates mDNS announcements, not production-safe.

References:
  - AMWA IS-04: https://specs.amwa.tv/is-04/
  - AMWA IS-10: https://specs.amwa.tv/is-10/
  - AMWA BCP-003-01: https://specs.amwa.tv/bcp-003-01/
  - AMWA BCP-003-02: https://specs.amwa.tv/bcp-003-02/
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger("pibroadguard.nmos")

# Common NMOS IS-04 path patterns
NMOS_QUERY_PATHS = [
    "/x-nmos/query/v1.3/nodes",
    "/x-nmos/query/v1.2/nodes",
    "/x-nmos/query/v1.1/nodes",
    "/x-nmos/node/v1.3/self",
    "/x-nmos/node/v1.2/self",
    "/x-nmos/node/v1.1/self",
]

# NMOS IS-04 Registry paths for enumerating managed resources
NMOS_REGISTRY_PATHS = {
    "nodes": "/x-nmos/query/v1.3/nodes",
    "devices": "/x-nmos/query/v1.3/devices",
    "senders": "/x-nmos/query/v1.3/senders",
    "receivers": "/x-nmos/query/v1.3/receivers",
    "flows": "/x-nmos/query/v1.3/flows",
    "sources": "/x-nmos/query/v1.3/sources",
}

DEFAULT_NMOS_PORTS = [8080, 8443, 80, 443]
TIMEOUT = 5.0  # seconds


@dataclass
class NmosSecurityResult:
    host: str
    port: int
    check: str
    result: str         # "pass" | "fail" | "warning" | "unknown"
    detail: str = ""
    recommendation: str = ""
    severity: str = "medium"   # "info" | "low" | "medium" | "high" | "critical"


@dataclass
class NmosService:
    host: str
    port: int
    api_type: str   # "query" | "node"
    api_version: str
    url: str


@dataclass
class NmosDiscoveryResult:
    registry_url: str
    nodes: list = field(default_factory=list)
    devices: list = field(default_factory=list)
    senders: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    error: Optional[str] = None


async def check_nmos_tls(host: str, port: int = 0) -> NmosSecurityResult:
    """
    Check whether NMOS IS-04 APIs are served over HTTPS (BCP-003-01 compliant).

    Tests HTTP first; if the endpoint responds on HTTP 200, it is unencrypted.
    Then tests HTTPS; if HTTPS responds, that's positive.

    Returns a NmosSecurityResult:
    - result="fail"    → HTTP (unencrypted) responding, no HTTPS
    - result="pass"    → HTTPS responding (HTTP may redirect or refuse)
    - result="warning" → HTTPS responding but HTTP also serving content (no redirect)
    - result="unknown" → neither HTTP nor HTTPS responded on any known NMOS path
    """
    ports_to_check = [port] if port else DEFAULT_NMOS_PORTS
    http_ok = False
    https_ok = False
    responding_port = port or 0

    for p in ports_to_check:
        for path in NMOS_QUERY_PATHS[:3]:
            http_url = f"http://{host}:{p}{path}"
            https_url = f"https://{host}:{p}{path}"
            try:
                async with httpx.AsyncClient(timeout=TIMEOUT, verify=False, follow_redirects=False) as client:
                    r_http = await client.get(http_url)
                if r_http.status_code in (200, 401, 403):
                    http_ok = True
                    responding_port = p
                    break
            except Exception:
                pass
            try:
                async with httpx.AsyncClient(timeout=TIMEOUT, verify=False, follow_redirects=False) as client:
                    r_https = await client.get(https_url)
                if r_https.status_code in (200, 401, 403):
                    https_ok = True
                    responding_port = p
                    break
            except Exception:
                pass
        if http_ok or https_ok:
            break

    if not http_ok and not https_ok:
        return NmosSecurityResult(
            host=host, port=responding_port, check="nmos_tls",
            result="unknown",
            detail="Kein NMOS-Endpunkt auf bekannten Ports gefunden.",
            severity="info",
        )

    if https_ok and not http_ok:
        return NmosSecurityResult(
            host=host, port=responding_port, check="nmos_tls",
            result="pass",
            detail="NMOS IS-04 API ist via HTTPS gesichert (BCP-003-01 konform).",
            severity="info",
        )

    if https_ok and http_ok:
        return NmosSecurityResult(
            host=host, port=responding_port, check="nmos_tls",
            result="warning",
            detail="NMOS IS-04 API ist sowohl via HTTP als auch HTTPS erreichbar. HTTP sollte deaktiviert oder auf HTTPS umgeleitet werden.",
            recommendation="HTTP-Endpunkt deaktivieren oder 301-Redirect auf HTTPS konfigurieren (AMWA BCP-003-01).",
            severity="medium",
        )

    # http_ok and not https_ok
    return NmosSecurityResult(
        host=host, port=responding_port, check="nmos_tls",
        result="fail",
        detail="NMOS IS-04 API ist nur via unverschlüsseltem HTTP erreichbar. TLS ist nicht konfiguriert.",
        recommendation="NMOS Registry/Node auf HTTPS (Port 8443) migrieren. TLS-Zertifikat einrichten (AMWA BCP-003-01).",
        severity="high",
    )


async def check_nmos_auth_required(host: str, port: int = 0) -> NmosSecurityResult:
    """
    Check whether NMOS IS-04 APIs require authentication (IS-10 / BCP-003-02).

    Sends a GET request WITHOUT an Authorization header to the NMOS query/node endpoint.
    - HTTP 401 → IS-10 auth is enforced (PASS)
    - HTTP 200 → no auth required (FAIL – unauthenticated access)
    - HTTP 403 → access denied but not auth challenge (WARNING)
    """
    ports_to_check = [port] if port else DEFAULT_NMOS_PORTS
    for p in ports_to_check:
        for path in NMOS_QUERY_PATHS[:3]:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{p}{path}"
                try:
                    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                        resp = await client.get(url)
                    status = resp.status_code
                    if status == 401:
                        return NmosSecurityResult(
                            host=host, port=p, check="nmos_auth",
                            result="pass",
                            detail=f"NMOS IS-04 API fordert Authentifizierung ({url} → HTTP 401). IS-10 ist aktiv.",
                            severity="info",
                        )
                    if status == 200:
                        return NmosSecurityResult(
                            host=host, port=p, check="nmos_auth",
                            result="fail",
                            detail=f"NMOS IS-04 API ist ohne Authentifizierung zugänglich ({url} → HTTP 200).",
                            recommendation="NMOS IS-10 Authorization aktivieren. Unauthentifizierter Zugriff erlaubt Enumeration aller Nodes, Devices, Senders und Receivers (AMWA BCP-003-02).",
                            severity="high",
                        )
                    if status == 403:
                        return NmosSecurityResult(
                            host=host, port=p, check="nmos_auth",
                            result="warning",
                            detail=f"NMOS IS-04 API gibt HTTP 403 zurück (kein explizites 401). IS-10 möglicherweise nicht standard-konform konfiguriert.",
                            recommendation="Prüfen ob IS-10 korrekt als Bearer Token Challenge (WWW-Authenticate: Bearer) implementiert ist.",
                            severity="low",
                        )
                except Exception:
                    continue

    return NmosSecurityResult(
        host=host, port=port or 0, check="nmos_auth",
        result="unknown",
        detail="Kein NMOS-Endpunkt auf bekannten Ports gefunden – Auth-Check nicht möglich.",
        severity="info",
    )


async def discover_nmos_services(host: str) -> list[NmosService]:
    """
    Detect NMOS IS-04 service endpoints on a host by probing well-known paths.
    Returns a list of discovered NmosService objects.
    """
    found: list[NmosService] = []
    for port in DEFAULT_NMOS_PORTS:
        for scheme in ("https", "http"):
            for path in NMOS_QUERY_PATHS:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                        resp = await client.get(url)
                    if resp.status_code in (200, 401):
                        # Determine api_type and version from path
                        parts = path.strip("/").split("/")
                        api_type = parts[1] if len(parts) > 1 else "query"
                        api_version = parts[2] if len(parts) > 2 else "v1.3"
                        found.append(NmosService(
                            host=host,
                            port=port,
                            api_type=api_type,
                            api_version=api_version,
                            url=url,
                        ))
                        break  # found on this port/scheme
                except Exception:
                    continue
    return found


async def query_nmos_registry(registry_url: str) -> NmosDiscoveryResult:
    """
    Query an NMOS IS-04 Registry for all managed resources.

    Fetches: nodes, devices, senders, receivers.
    Returns a NmosDiscoveryResult. Skips resources that fail to load gracefully.

    Note: Only works if the registry URL is known (e.g. configured in device settings
    or discovered via IS-04 DNS-SD). Does NOT perform mDNS lookups.
    """
    result = NmosDiscoveryResult(registry_url=registry_url)
    base = registry_url.rstrip("/")

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        for resource, path in NMOS_REGISTRY_PATHS.items():
            if resource not in ("nodes", "devices", "senders", "receivers"):
                continue
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    setattr(result, resource, data if isinstance(data, list) else [])
                elif resp.status_code == 401:
                    result.error = "Registry erfordert Authentifizierung (IS-10). Bearer Token konfigurieren."
                    break
            except Exception as e:
                logger.warning(f"NMOS registry query failed ({url}): {e}")

    return result
