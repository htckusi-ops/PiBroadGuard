import asyncio
import ipaddress
import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("pibroadguard.scan")

# SSE queues: assessment_id → asyncio.Queue of str messages
scan_queues: Dict[int, asyncio.Queue] = {}

SCAN_PROFILES = {
    "passive": [
        "-Pn", "-sT", "-sV", "--version-light", "-T2",
        "-p", "21,22,23,25,53,80,102,161,443,502,554,623,1194,1883,2222,4840,8080,8443,9100,47808",
    ],
    "standard": [
        "-Pn", "-sT", "-sV", "-T3", "--top-ports", "1000", "--version-intensity", "5",
    ],
    "extended": [
        "-Pn", "-sT", "-sU", "-sV", "-T3",
        "-p", "T:1-1000,U:161,623,1194,1883,4840,47808",
        "--version-intensity", "7",
    ],
}

# Per-profile host timeouts (overrides the global setting when tighter).
# -T2 with up to ~10s RTT per port: 20 ports worst-case = 200s, use 300s.
# -T3 with top-1000: typically < 120s on LAN, use 300s as safe upper bound.
PROFILE_HOST_TIMEOUT = {
    "passive":  "300s",
    "standard": "300s",
    "extended": "600s",   # includes UDP which is slower
}


def _validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def _parse_nmap_xml(xml_data: str) -> List[dict]:
    """Parse nmap XML output. Includes open and open|filtered states."""
    results = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            # Extract MAC and vendor if present
            mac_address = ""
            mac_vendor = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") == "mac":
                    mac_address = addr.get("addr", "")
                    mac_vendor = addr.get("vendor", "")

            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                service_elem = port_elem.find("service")
                state = state_elem.get("state") if state_elem is not None else "unknown"
                if state not in ("open", "filtered", "open|filtered"):
                    continue
                result = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": state,
                    "service_name": "",
                    "service_product": "",
                    "service_version": "",
                    "extra_info": "",
                    "mac_address": mac_address,
                    "mac_vendor": mac_vendor,
                }
                if service_elem is not None:
                    result["service_name"] = service_elem.get("name", "")
                    result["service_product"] = service_elem.get("product", "")
                    result["service_version"] = service_elem.get("version", "")
                    result["extra_info"] = service_elem.get("extrainfo", "")
                results.append(result)
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
    return results


def _extract_nmap_version(xml_data: str) -> str:
    """Extract nmap version from XML scanner attribute."""
    try:
        root = ET.fromstring(xml_data)
        return root.get("version", "unknown")
    except ET.ParseError:
        return "unknown"


def _count_total_ports_scanned(xml_data: str) -> int:
    """Extract total ports scanned from scanstats element."""
    try:
        root = ET.fromstring(xml_data)
        stats = root.find("runstats/hosts") or root.find("runstats")
        scanstats = root.find("scanstats")
        if scanstats is not None:
            total = scanstats.get("totalhosts", "0")
            return int(total) if total.isdigit() else 0
    except (ET.ParseError, ValueError):
        pass
    return 0


async def run_scan(
    ip: str,
    profile: str,
    host_timeout: str = "300s",
    max_rate: int = 100,
    assessment_id: Optional[int] = None,
    flags_override: Optional[List] = None,
    timeout_override: Optional[int] = None,
    interface: Optional[str] = None,
) -> dict:
    safe_ip = _validate_ip(ip)
    flags = flags_override if flags_override is not None else SCAN_PROFILES.get(profile, SCAN_PROFILES["passive"])

    if timeout_override is not None:
        effective_timeout = f"{timeout_override}s"
    else:
        effective_timeout = PROFILE_HOST_TIMEOUT.get(profile, host_timeout)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        output_file = tmp.name

    iface_flags = ["-e", interface] if interface and interface != "auto" else []
    cmd = ["nmap"] + flags + iface_flags + [
        "--host-timeout", effective_timeout,
        "--max-rate", str(max_rate),
        "-oX", output_file,
        safe_ip,
    ]

    logger.info(f"Starting nmap scan: profile={profile} target={safe_ip} timeout={effective_timeout} cmd={' '.join(cmd)}")
    start = datetime.now(timezone.utc)

    queue = None
    if assessment_id is not None:
        queue = asyncio.Queue()
        scan_queues[assessment_id] = queue
        await queue.put(f"data: Starte Scan ({profile}) auf {safe_ip}...\n\n")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Stream stdout to SSE queue AND drain stderr concurrently.
        # Both pipes must be consumed to prevent the subprocess from blocking
        # when its write-buffer fills up.
        async def _stream_stdout():
            if proc.stdout:
                async for line in proc.stdout:
                    text = line.decode(errors="replace").rstrip()
                    if text and queue is not None:
                        await queue.put(f"data: {text}\n\n")

        async def _drain_stderr():
            if proc.stderr:
                stderr_lines = []
                async for line in proc.stderr:
                    stderr_lines.append(line.decode(errors="replace").rstrip())
                if stderr_lines:
                    logger.debug(f"nmap stderr: {' | '.join(stderr_lines)}")

        await asyncio.gather(_stream_stdout(), _drain_stderr(), proc.wait())
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        with open(output_file, "r", errors="replace") as f:
            xml_data = f.read()

        if proc.returncode != 0:
            logger.error(f"Nmap exited with code {proc.returncode}")

        nmap_version = _extract_nmap_version(xml_data)
        parsed = _parse_nmap_xml(xml_data)

        logger.info(
            f"Scan completed: elapsed={elapsed:.1f}s exit={proc.returncode} "
            f"ports={len(parsed)} nmap={nmap_version}"
        )

        if queue is not None:
            await queue.put(
                f"data: Scan abgeschlossen: {len(parsed)} Ports gefunden "
                f"({elapsed:.1f}s)\n\n"
            )
            await queue.put("data: __DONE__\n\n")

        return {
            "returncode": proc.returncode,
            "xml": xml_data,
            "results": parsed,
            "elapsed_seconds": elapsed,
            "nmap_version": nmap_version,
            "total_ports_scanned": len(parsed),
        }
    except FileNotFoundError:
        logger.error("nmap binary not found")
        if queue is not None:
            await queue.put("data: FEHLER: nmap nicht gefunden\n\ndata: __DONE__\n\n")
        raise RuntimeError("nmap is not installed or not in PATH")
    finally:
        try:
            os.unlink(output_file)
        except OSError:
            pass


async def check_nmap_capabilities() -> dict:
    try:
        result = subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True, timeout=10
        )
        version_line = result.stdout.splitlines()[0] if result.stdout else "unknown"
        version = (
            version_line.split("version ")[-1].split(" ")[0]
            if "version" in version_line
            else "unknown"
        )

        # Quick test for raw socket availability
        test = subprocess.run(
            ["nmap", "-sS", "-p", "1", "--host-timeout", "2s", "127.0.0.1"],
            capture_output=True, text=True, timeout=15,
        )
        has_raw = "SYN Stealth Scan" in test.stdout or test.returncode == 0
        logger.info(f"Nmap version: {version}, raw_sockets={has_raw}")
        return {"version": version, "raw_sockets": has_raw, "available": True}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("nmap not available")
        return {"version": None, "raw_sockets": False, "available": False}


_nmap_caps: Optional[dict] = None


async def get_nmap_capabilities() -> dict:
    global _nmap_caps
    if _nmap_caps is None:
        _nmap_caps = await check_nmap_capabilities()
    return _nmap_caps
