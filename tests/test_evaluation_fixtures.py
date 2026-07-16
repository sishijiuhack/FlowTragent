from __future__ import annotations

import json
from pathlib import Path


def test_evaluation_samples_have_required_categories() -> None:
    path = Path("tests/fixtures/evaluation_samples.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert set(data) == {"successful", "failed", "uncertain"}
    for category, samples in data.items():
        assert len(samples) >= 10, category
        ids = {sample["id"] for sample in samples}
        assert len(ids) == len(samples)
        for sample in samples:
            assert sample["id"].startswith(category[:-3] if category == "successful" else category)
            assert sample["input_type"] in {"payload", "pcap", "log_bundle"}
            assert sample["payload"].strip()
            assert sample["expected_verdict"].strip()
            assert sample["expected_confidence"] in {"low", "medium", "high"}
            assert sample["evidence"]
