"""Capture live traffic into rolling PCAP segments."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


BPF_PROFILES = {
    "http_dns": "(tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or udp port 53)",
    "balanced": "(tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 443 or udp port 53 or tcp port 22 or tcp port 25 or tcp port 110 or tcp port 143 or tcp port 993 or tcp port 995 or tcp port 3389 or tcp portrange 1-1024)",
    "wide": "(tcp or udp)",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FlowTragent live capture worker")
    parser.add_argument("--interface", required=True, help="Network interface, for example eth0")
    parser.add_argument("--output-dir", default="data/live/incoming", help="Directory for PCAP segments")
    parser.add_argument("--segment-seconds", type=int, default=60, help="Seconds per PCAP segment")
    parser.add_argument("--packet-count", type=int, default=0, help="Optional packet limit per segment")
    parser.add_argument("--profile", choices=sorted(BPF_PROFILES), default="balanced", help="BPF profile")
    parser.add_argument("--bpf", help="Override BPF filter")
    parser.add_argument("--once", action="store_true", help="Capture only one segment")
    parser.add_argument("--dry-run", action="store_true", help="Print tcpdump command without running it")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bpf = args.bpf or BPF_PROFILES[args.profile]
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise SystemExit("tcpdump not found. Install with: sudo apt install -y tcpdump")

    while True:
        target = output_dir / f"segment_{_stamp()}.pcap"
        cmd = [
            tcpdump,
            "-i",
            args.interface,
            "-nn",
            "-s",
            "0",
            "-w",
            str(target),
            "-G",
            str(args.segment_seconds),
            "-W",
            "1",
        ]
        if args.packet_count > 0:
            cmd.extend(["-c", str(args.packet_count)])
        cmd.append(bpf)

        if args.dry_run:
            print(json.dumps({"cmd": cmd, "output": str(target)}, ensure_ascii=False, indent=2))
            return

        completed = subprocess.run(cmd, check=False)
        if completed.returncode != 0:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "segment": str(target),
                        "profile": args.profile,
                        "bpf": bpf,
                        "returncode": completed.returncode,
                        "hint": "Run with sudo or grant tcpdump cap_net_raw,cap_net_admin.",
                    },
                    ensure_ascii=False,
                )
            )
            if target.exists() and target.stat().st_size == 0:
                target.unlink()
            if args.once:
                raise SystemExit(completed.returncode)
            time.sleep(3.0)
            continue
        print(json.dumps({"status": "captured", "segment": str(target), "profile": args.profile, "bpf": bpf}, ensure_ascii=False))
        if args.once:
            return
        time.sleep(0.2)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


if __name__ == "__main__":
    main()
