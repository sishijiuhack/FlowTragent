#!/usr/bin/env bash
set -euo pipefail

MODE="local"
NO_START=0
WEB_ONLY=0
WITH_SYSTEMD=0
HOST="${FLOWTRAGENT_HOST:-127.0.0.1}"
PORT="${FLOWTRAGENT_PORT:-5000}"
VENV_DIR="${FLOWTRAGENT_VENV:-.venv}"
PYTHON_BIN=""

usage() {
  cat <<'USAGE'
FlowTragent one-click installer

Usage:
  bash scripts/install.sh [--docker] [--web-only] [--with-systemd] [--no-start]

Options:
  --docker        Use Docker Compose instead of local Python venv.
  --web-only      Start only the Web service where supported.
  --with-systemd  Install systemd services after local dependency setup.
  --no-start      Install dependencies and build demo index without starting services.
USAGE
}

print_ready() {
  echo
  echo "FlowTragent is ready."
  echo "Web:     http://$HOST:$PORT"
  echo "Health:  curl http://$HOST:$PORT/health"
  echo "Metrics: curl http://$HOST:$PORT/metrics"
  echo "Token:   ${FLOWTRAGENT_TOKEN:-'(not set)'}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) MODE="docker" ;;
    --web-only) WEB_ONLY=1 ;;
    --with-systemd) WITH_SYSTEMD=1 ;;
    --no-start) NO_START=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

python_supported() {
  local candidate="$1"
  "$candidate" - <<'PY'
import sys
major, minor = sys.version_info[:2]
raise SystemExit(0 if (major == 3 and 10 <= minor < 13) else 1)
PY
}

python_version() {
  "$1" - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
PY
}

resolve_python() {
  local candidates=()
  if [[ -n "${FLOWTRAGENT_PYTHON:-}" ]]; then
    candidates+=("$FLOWTRAGENT_PYTHON")
  fi
  candidates+=(python3.12 python3.11 /usr/bin/python3.12 /usr/bin/python3.11 python3)

  local candidate
  for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1 && python_supported "$candidate"; then
      PYTHON_BIN="$(command -v "$candidate")"
      echo "Using Python: $PYTHON_BIN ($(python_version "$PYTHON_BIN"))"
      return
    fi
  done

  echo "FlowTragent requires Python >=3.10 and <3.13 for the pinned ML dependencies." >&2
  echo "Install Python 3.12/3.11, or run with FLOWTRAGENT_PYTHON=/path/to/python3.12 bash scripts/install.sh" >&2
  exit 1
}

ensure_compatible_venv() {
  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    return
  fi
  if "$VENV_DIR/bin/python" - <<'PY'
import sys
major, minor = sys.version_info[:2]
raise SystemExit(0 if (major == 3 and 10 <= minor < 13) else 1)
PY
  then
    return
  fi
  echo "Existing $VENV_DIR uses unsupported Python $("$VENV_DIR/bin/python" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))'). Recreating it."
  rm -rf "$VENV_DIR"
}

choose_port() {
  local candidate="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$candidate" <<'PY'
import socket, sys
port = int(sys.argv[1])
with socket.socket() as sock:
    raise SystemExit(0 if sock.connect_ex(("127.0.0.1", port)) != 0 else 1)
PY
  else
    return 0
  fi
}

if ! choose_port "$PORT"; then
  echo "Port $PORT is busy, trying 5050."
  PORT="5050"
fi

ensure_token() {
  if [[ -n "${FLOWTRAGENT_TOKEN:-}" ]]; then
    return
  fi
  FLOWTRAGENT_TOKEN="$("${PYTHON_BIN:-python3}" - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)"
  export FLOWTRAGENT_TOKEN
  umask 077
  cat > .env <<EOF
FLOWTRAGENT_HOST=$HOST
FLOWTRAGENT_PORT=$PORT
FLOWTRAGENT_TOKEN=$FLOWTRAGENT_TOKEN
EOF
  echo "Generated FLOWTRAGENT_TOKEN and wrote it to .env. Save it now: $FLOWTRAGENT_TOKEN"
}

install_system_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "Installing system packages with apt-get."
    sudo apt-get update
    sudo apt-get install -y python3.12-venv python3.12-dev python3-venv python3-pip tcpdump graphviz
  else
    echo "apt-get not found; skipping system package installation."
  fi
}

build_demo_index() {
  FLOWTRAGENT_OFFLINE=1 "$VENV_DIR/bin/python" scripts/build_demo_index.py \
    --input tests/fixtures/train_payloads.csv \
    --output-dir data/index
}

run_local() {
  install_system_packages
  resolve_python
  ensure_token
  ensure_compatible_venv
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
  "$VENV_DIR/bin/python" -m pip install -r requirements.txt
  "$VENV_DIR/bin/python" -m pip install gunicorn
  mkdir -p logs reports data/pcap data/csv data/index data/rag data/live/incoming data/tmp
  build_demo_index
  if [[ "$WITH_SYSTEMD" -eq 1 ]]; then
    sudo cp deploy/flowtragent-*.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now flowtragent-web
    if [[ "$WEB_ONLY" -eq 0 ]]; then
      sudo systemctl enable --now flowtragent-capture flowtragent-analyzer
    fi
  fi
  if [[ "$NO_START" -eq 0 && "$WITH_SYSTEMD" -eq 0 ]]; then
    export FLOWTRAGENT_HOST="$HOST" FLOWTRAGENT_PORT="$PORT" FLOWTRAGENT_PYTHON="$VENV_DIR/bin/python"
    print_ready
    exec scripts/run_web_prod.sh
  fi
}

run_docker() {
  command -v docker >/dev/null 2>&1 || { echo "docker is required for --docker." >&2; exit 1; }
  ensure_token
  export FLOWTRAGENT_PORT="$PORT" FLOWTRAGENT_TOKEN
  if [[ "$NO_START" -eq 1 ]]; then
    docker compose build
  elif [[ "$WEB_ONLY" -eq 1 ]]; then
    docker compose up --build -d web
  else
    docker compose up --build -d web analyzer capture
  fi
}

if [[ "$MODE" == "docker" ]]; then
  run_docker
else
  run_local
fi

print_ready
