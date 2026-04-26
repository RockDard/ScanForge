#!/usr/bin/env bash
set -euo pipefail

print_help() {
  cat <<'EOF'
Usage: ./scripts/stop-scanforge-admin.sh

Stops ScanForge web and worker processes started by the administrator launcher.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  print_help
  exit 0
fi

if [[ $# -gt 0 ]]; then
  printf 'Unknown argument: %s\n' "$1" >&2
  print_help >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  printf 'Этот сценарий нужно запускать с правами администратора.\n' >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Подключаем helper, чтобы остановка и очистка state были согласованы с запуском.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

RUN_DIR="${SCANFORGE_RUN_DIR:-/var/run/scanforge}"
WEB_PID_FILE="$RUN_DIR/web.pid"
WORKER_PID_FILE="$RUN_DIR/worker.pid"
ENDPOINT_FILE="$RUN_DIR/endpoint.env"

stop_residual_scanforge_processes() {
  local pids pid pgid current_pgid seen_pgids remaining
  current_pgid="$(ps -o pgid= -p "$$" 2>/dev/null | tr -d '[:space:]' || true)"
  mapfile -t pids < <(pgrep -f "$ROOT_DIR/.venv/bin/python -m (qa_portal.worker|uvicorn qa_portal.app:app)" 2>/dev/null || true)
  seen_pgids=" "
  for pid in "${pids[@]}"; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" == "$$" ]] && continue
    kill -0 "$pid" 2>/dev/null || continue
    pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$pgid" =~ ^[0-9]+$ && "$pgid" != "$current_pgid" && "$seen_pgids" != *" $pgid "* ]]; then
      kill -- "-$pgid" 2>/dev/null || true
      seen_pgids+="$pgid "
    else
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  mapfile -t remaining < <(pgrep -f "$ROOT_DIR/.venv/bin/python -m (qa_portal.worker|uvicorn qa_portal.app:app)" 2>/dev/null || true)
  for pid in "${remaining[@]}"; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" == "$$" ]] && continue
    kill -9 "$pid" 2>/dev/null || true
  done
}

state_host=""
state_port=""
if scanforge_load_endpoint_state "$ENDPOINT_FILE"; then
  state_host="$QA_PORTAL_HOST"
  state_port="$QA_PORTAL_PORT"
fi

scanforge_stop_pid_file "$WORKER_PID_FILE"
scanforge_stop_pid_file "$WEB_PID_FILE"
stop_residual_scanforge_processes

if [[ -n "$state_host" && -n "$state_port" ]]; then
  if ! scanforge_healthcheck "$state_host" "$state_port"; then
    rm -f "$ENDPOINT_FILE"
  fi
else
  rm -f "$ENDPOINT_FILE"
fi

printf 'ScanForge остановлен.\n'
