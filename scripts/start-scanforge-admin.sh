#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'Этот сценарий нужно запускать с правами администратора.\n' >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT_DIR/.env"
  set +a
fi

STATE_DIR="${SCANFORGE_STATE_DIR:-/var/lib/scanforge}"
LOG_DIR="${SCANFORGE_LOG_DIR:-/var/log/scanforge}"
RUN_DIR="${SCANFORGE_RUN_DIR:-/var/run/scanforge}"
DATA_DIR="${QA_PORTAL_DATA_DIR:-$STATE_DIR/data}"

HOST="${QA_PORTAL_HOST:-127.0.0.1}"
PORT="${QA_PORTAL_PORT:-8000}"
URL="http://${HOST}:${PORT}"

WEB_PID_FILE="$RUN_DIR/web.pid"
WORKER_PID_FILE="$RUN_DIR/worker.pid"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$RUN_DIR" "$DATA_DIR"

healthcheck() {
  python3 - "$HOST" "$PORT" <<'PY'
import json
import sys
import urllib.request

host, port = sys.argv[1], sys.argv[2]
url = f"http://{host}:{port}/health"

try:
    with urllib.request.urlopen(url, timeout=2) as response:
        payload = json.loads(response.read().decode("utf-8"))
except Exception:
    raise SystemExit(1)

raise SystemExit(0 if payload.get("status") == "ok" else 1)
PY
}

pid_is_running() {
  local pid_file="$1"
  local pid
  if [[ ! -f "$pid_file" ]]; then
    return 1
  fi
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  kill -0 "$pid" 2>/dev/null
}

start_web() {
  if healthcheck; then
    return 0
  fi
  if pid_is_running "$WEB_PID_FILE"; then
    return 0
  fi

  (
    cd "$ROOT_DIR"
    export QA_PORTAL_DATA_DIR="$DATA_DIR"
    export QA_PORTAL_HOST="$HOST"
    export QA_PORTAL_PORT="$PORT"
    export QA_PORTAL_RELOAD=0
    export QA_PORTAL_AUTOSTART_WORKER=0
    nohup "$ROOT_DIR/run-server.sh" >>"$LOG_DIR/web.log" 2>&1 &
    echo "$!" >"$WEB_PID_FILE"
  )
}

start_worker() {
  if pid_is_running "$WORKER_PID_FILE"; then
    return 0
  fi

  (
    cd "$ROOT_DIR"
    export QA_PORTAL_DATA_DIR="$DATA_DIR"
    export QA_PORTAL_HOST="$HOST"
    export QA_PORTAL_PORT="$PORT"
    export QA_PORTAL_RELOAD=0
    export QA_PORTAL_AUTOSTART_WORKER=0
    nohup "$ROOT_DIR/run-worker.sh" >>"$LOG_DIR/worker.log" 2>&1 &
    echo "$!" >"$WORKER_PID_FILE"
  )
}

wait_for_health() {
  local attempt
  for attempt in $(seq 1 60); do
    if healthcheck; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_web
start_worker

if ! wait_for_health; then
  printf 'ScanForge не ответил по адресу %s за отведенное время.\n' "$URL" >&2
  exit 1
fi

printf '%s\n' "$URL"
