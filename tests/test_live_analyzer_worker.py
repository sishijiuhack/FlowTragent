from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.settings import load_config
from src.storage.alert_store import AlertStore


def _load_worker():
    path = PROJECT_ROOT / "scripts/live_analyzer_worker.py"
    spec = importlib.util.spec_from_file_location("live_analyzer_worker", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def main() -> None:
    subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)
    tmp = PROJECT_ROOT / "data/tmp/live_worker"
    if tmp.exists():
        shutil.rmtree(tmp)
    incoming = tmp / "incoming"
    reports = tmp / "reports"
    incoming.mkdir(parents=True)
    reports.mkdir(parents=True)
    segment = incoming / "segment_demo_attack.pcap"
    shutil.copy2(PROJECT_ROOT / "data/pcap/demo_attack.pcap", segment)

    store = AlertStore(tmp / "alerts.db")
    worker = _load_worker()
    output = worker.process_segment(
        segment,
        config=load_config(str(PROJECT_ROOT / "config/config.yaml")),
        store=store,
        output_dir=reports,
        min_risk_score=50,
        top_k=3,
        force_demo_index=True,
        enable_rag=False,
        enable_ollama=False,
    )
    assert output["status"] == "reported"
    assert Path(output["report"]).exists()
    assert Path(output["report"]).with_name(Path(output["report"]).stem + "_zh.md").exists()
    alert = store.get_by_segment(segment)
    assert alert is not None
    assert alert["status"] == "reported"
    assert alert["severity"] in {"critical", "high"}
    assert alert["report_path"] == output["report"]
    analysis = json.loads(Path(output["report"]).with_suffix(".json").read_text(encoding="utf-8"))
    assert analysis["impact_assessment"]["verdict"]


if __name__ == "__main__":
    main()
