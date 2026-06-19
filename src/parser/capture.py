"""Live packet capture helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path


def capture_with_tcpdump(
    interface: str,
    output_pcap: str | Path,
    *,
    duration: int = 30,
    packet_count: int = 0,
) -> Path:
    output = Path(output_pcap)
    output.parent.mkdir(parents=True, exist_ok=True)

    command = ["tcpdump", "-i", interface, "-w", str(output)]
    if packet_count > 0:
        command.extend(["-c", str(packet_count)])

    try:
        subprocess.run(command, timeout=max(1, duration), check=False)
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError as exc:
        raise RuntimeError("tcpdump is required for live mode. Install with: sudo apt install -y tcpdump") from exc

    if not output.exists() or output.stat().st_size == 0:
        raise RuntimeError(f"No packets were captured on interface {interface}")
    return output

