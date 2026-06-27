#!/usr/bin/env bash
set -euo pipefail

HOST="${FLOWTRAGENT_HOST:-127.0.0.1}"
PORT="${FLOWTRAGENT_PORT:-5000}"
WORKERS="${FLOWTRAGENT_WORKERS:-2}"

if command -v gunicorn >/dev/null 2>&1; then
  exec gunicorn -w "$WORKERS" -b "$HOST:$PORT" "web_app:app"
fi

echo "gunicorn not found; falling back to Flask development server." >&2
echo "Install for production: python -m pip install gunicorn" >&2
exec python web_app.py
