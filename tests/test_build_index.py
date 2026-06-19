from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir) / "index"
        env = os.environ.copy()
        env["FLOWTRAGENT_OFFLINE"] = "1"
        subprocess.run(
            [
                sys.executable,
                "scripts/build_demo_index.py",
                "--input",
                "tests/fixtures/train_payloads.csv",
                "--output-dir",
                str(output_dir),
            ],
            cwd=PROJECT_ROOT,
            env=env,
            check=True,
        )
        assert (output_dir / "faiss.index").exists()
        assert (output_dir / "meta.json").exists()


if __name__ == "__main__":
    main()

