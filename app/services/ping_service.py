import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class PingResult:
    reachable: bool
    rtt_ms: Optional[float] = None


def ping_host(host: str, timeout_seconds: int = 1) -> PingResult:
    """Run a single ICMP ping and return reachability + RTT in ms when available."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        reachable = proc.returncode == 0
    except FileNotFoundError:
        # Fallback for environments without `ping` binary
        return _tcp_reachability_fallback(host, timeout_seconds)

    rtt_ms = None
    match = re.search(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", output)
    if match:
        try:
            rtt_ms = float(match.group(1))
        except ValueError:
            rtt_ms = None

    return PingResult(reachable=reachable, rtt_ms=rtt_ms)


def _tcp_reachability_fallback(host: str, timeout_seconds: int) -> PingResult:
    """Best-effort fallback when ICMP ping is unavailable."""
    candidates = [80, 443, 22, 554, 8080]
    for port in candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_seconds)
        try:
            s_start = time.time()
            err = s.connect_ex((host, port))
            elapsed_ms = (time.time() - s_start) * 1000.0
            if err == 0:
                return PingResult(reachable=True, rtt_ms=elapsed_ms)
        except Exception:
            pass
        finally:
            s.close()
    return PingResult(reachable=False, rtt_ms=None)
