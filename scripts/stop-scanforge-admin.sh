#!/usr/bin/env bash
set -euo pipefail

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

state_host=""
state_port=""
if scanforge_load_endpoint_state "$ENDPOINT_FILE"; then
  state_host="$QA_PORTAL_HOST"
  state_port="$QA_PORTAL_PORT"
fi

scanforge_stop_pid_file "$WORKER_PID_FILE"
scanforge_stop_pid_file "$WEB_PID_FILE"

if [[ -n "$state_host" && -n "$state_port" ]]; then
  if ! scanforge_healthcheck "$state_host" "$state_port"; then
    rm -f "$ENDPOINT_FILE"
  fi
else
  rm -f "$ENDPOINT_FILE"
fi

printf 'ScanForge остановлен.\n'
