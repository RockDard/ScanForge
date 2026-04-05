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

RUN_DIR="${SCANFORGE_RUN_DIR:-/var/run/scanforge}"
WEB_PID_FILE="$RUN_DIR/web.pid"
WORKER_PID_FILE="$RUN_DIR/worker.pid"

stop_pid_file() {
  local pid_file="$1"
  local pid
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi

  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pid_file"
}

stop_pid_file "$WORKER_PID_FILE"
stop_pid_file "$WEB_PID_FILE"

printf 'ScanForge остановлен.\n'
