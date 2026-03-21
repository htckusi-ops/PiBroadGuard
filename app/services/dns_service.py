"""Reverse DNS lookup service."""
import asyncio
import ipaddress
import logging
import socket
from typing import Optional

logger = logging.getLogger("pibroadguard.dns")


async def reverse_lookup(ip: str) -> Optional[str]:
    """
    Perform an async reverse DNS lookup.
    Returns the hostname or None on failure.
    """
    try:
        # Validate IP first
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning(f"Invalid IP for rDNS: {ip}")
        return None

    loop = asyncio.get_event_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(
            None, socket.gethostbyaddr, ip
        )
        logger.info(f"rDNS {ip} → {hostname}")
        return hostname
    except (socket.herror, socket.gaierror, OSError) as e:
        logger.debug(f"rDNS lookup failed for {ip}: {e}")
        return None


def reverse_lookup_sync(ip: str) -> Optional[str]:
    """Synchronous reverse DNS lookup (for use outside async context)."""
    try:
        ipaddress.ip_address(ip)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (ValueError, socket.herror, socket.gaierror, OSError):
        return None
