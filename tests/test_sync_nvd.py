from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    tmp = PROJECT_ROOT / "data" / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    fixture = tmp / "nvd_fixture.json"
    output = tmp / "nvd_output.jsonl"
    fixture.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-44228",
                            "published": "2021-12-10T00:00:00.000",
                            "lastModified": "2022-01-01T00:00:00.000",
                            "descriptions": [{"lang": "en", "value": "Log4Shell JNDI vulnerability."}],
                            "references": {"referenceData": [{"url": "https://example.com"}]},
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            sys.executable,
            "scripts/sync_nvd.py",
            "--input-json",
            str(fixture.relative_to(PROJECT_ROOT)),
            "--output",
            str(output.relative_to(PROJECT_ROOT)),
        ],
        cwd=PROJECT_ROOT,
        check=True,
    )
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["id"] == "CVE-2021-44228"
    assert rows[0]["cvss"] == 10.0


if __name__ == "__main__":
    main()
