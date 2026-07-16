# Contributing to FlowTragent

Thanks for helping improve FlowTragent. This project handles security telemetry,
PCAPs, exploit indicators, and evaluation data, so contributions should be
small, reproducible, and careful with sensitive artifacts.

## Local Setup

```bash
python -m venv flowtragent_env
flowtragent_env\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

On Linux/WSL:

```bash
python3 -m venv flowtragent_env
source flowtragent_env/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## Verification

Run the default test suite before opening a change:

```bash
pytest tests/
python tests/test_web_app.py
python tests/test_agent_orchestrator.py
python tests/test_langgraph_runner.py
```

If scapy is available in a Linux/WSL environment, also run the PCAP-oriented
script tests:

```bash
python tests/test_pipeline.py
python tests/test_live_prefilter.py
python tests/test_live_analyzer_worker.py
```

## Development Guidelines

- Keep changes scoped to the task and follow existing module boundaries.
- Add or update tests for behavior changes.
- Prefer reproducible commands and record important assumptions in docs.
- Preserve the evidence hierarchy: retrieval hits and markers are candidate
  evidence, not standalone proof of successful exploitation.
- Keep holdout/evaluation data separate from index-building data.

## Data and Artifact Rules

Do not commit runtime or sensitive artifacts:

- `logs/`
- `reports/`
- `data/live/`
- `data/tmp/`
- `data/index/`
- real PCAP files
- raw DataCon datasets
- model weights or private embeddings

Use small synthetic fixtures under `tests/fixtures/` when tests need sample
data. Redact IPs, tokens, hostnames, usernames, and payloads when sharing logs.

## Pull Request Checklist

- The change has focused tests or a documented reason tests are not applicable.
- `pytest tests/` passes, or any failure is explained.
- Script-style tests affected by the change were run.
- Documentation is updated for user-facing behavior or deployment changes.
- No runtime artifacts, sensitive data, models, real PCAPs, or raw datasets are
  included.
