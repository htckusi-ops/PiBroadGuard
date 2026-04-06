import re
import subprocess
import sys
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

    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    reachable = proc.returncode == 0

    rtt_ms = None
    match = re.search(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", output)
    if match:
        try:
            rtt_ms = float(match.group(1))
        except ValueError:
            rtt_ms = None

    return PingResult(reachable=reachable, rtt_ms=rtt_ms)
