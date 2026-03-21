import asyncio
import ipaddress
import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger("pibroadguard.scan")

SCAN_PROFILES = {
    "passive": [
        "-sV", "--version-light", "-T2",
        "-p", "21,22,23,25,80,161,443,502,554,8080,8443,9100",
    ],
    "standard": [
        "-sV", "-T3", "--top-ports", "1000", "--version-intensity", "5",
    ],
    "extended": [
        "-sV", "-sU", "--top-ports", "500", "-T3", "--version-intensity", "7",
    ],
}


def _validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def _parse_nmap_xml(xml_data: str) -> List[dict]:
    results = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                service_elem = port_elem.find("service")
                state = state_elem.get("state") if state_elem is not None else "unknown"
                if state not in ("open", "filtered"):
                    continue
                result = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": state,
                    "service_name": "",
                    "service_product": "",
                    "service_version": "",
                    "extra_info": "",
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


async def run_scan(ip: str, profile: str, host_timeout: str = "60s", max_rate: int = 100) -> dict:
    safe_ip = _validate_ip(ip)
    flags = SCAN_PROFILES.get(profile, SCAN_PROFILES["passive"])

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        output_file = tmp.name

    cmd = ["nmap"] + flags + [
        "--host-timeout", host_timeout,
        "--max-rate", str(max_rate),
        "-oX", output_file,
        safe_ip,
    ]

    logger.info(f"Starting nmap scan: profile={profile} target={safe_ip}")
    start = datetime.now(timezone.utc)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        with open(output_file, "r", errors="replace") as f:
            xml_data = f.read()

        if proc.returncode != 0:
            logger.error(f"Nmap exited with code {proc.returncode}: {stderr.decode()}")

        logger.info(f"Scan completed in {elapsed:.1f}s, exit code={proc.returncode}")
        return {
            "returncode": proc.returncode,
            "xml": xml_data,
            "results": _parse_nmap_xml(xml_data),
            "elapsed_seconds": elapsed,
        }
    except FileNotFoundError:
        logger.error("nmap binary not found")
        raise RuntimeError("nmap is not installed or not in PATH")
    finally:
        import os
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
        version = version_line.split("version ")[-1].split(" ")[0] if "version" in version_line else "unknown"

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
