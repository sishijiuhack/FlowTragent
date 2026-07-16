#!/usr/bin/env bash
set -euo pipefail

HOST="${FLOWTRAGENT_HOST:-127.0.0.1}"
PORT="${FLOWTRAGENT_PORT:-5000}"
WORKERS="${FLOWTRAGENT_WORKERS:-2}"
TIMEOUT="${FLOWTRAGENT_GUNICORN_TIMEOUT:-120}"
PYTHON_BIN="${FLOWTRAGENT_PYTHON:-python}"

if ! "$PYTHON_BIN" -m gunicorn --version >/dev/null 2>&1; then
  echo "gunicorn is required for production web serving." >&2
  echo "Install it in the deployment environment: python -m pip install gunicorn" >&2
  exit 1
fi

exec "$PYTHON_BIN" -m gunicorn \
  --workers "$WORKERS" \
  --bind "$HOST:$PORT" \
  --timeout "$TIMEOUT" \
  --access-logfile "-" \
  --error-logfile "-" \
  "web_app:app"
