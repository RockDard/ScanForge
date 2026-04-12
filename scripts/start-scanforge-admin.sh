#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'Этот сценарий нужно запускать с правами администратора.\n' >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Общий helper синхронизирует healthcheck, pid-контур и подбор порта.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

STATE_DIR="${SCANFORGE_STATE_DIR:-/var/lib/scanforge}"
LOG_DIR="${SCANFORGE_LOG_DIR:-/var/log/scanforge}"
RUN_DIR="${SCANFORGE_RUN_DIR:-/var/run/scanforge}"
DATA_DIR="${QA_PORTAL_DATA_DIR:-$STATE_DIR/data}"

HOST="${QA_PORTAL_HOST:-127.0.0.1}"
DESIRED_PORT="${QA_PORTAL_PORT:-8000}"

WEB_PID_FILE="$RUN_DIR/web.pid"
WORKER_PID_FILE="$RUN_DIR/worker.pid"
ENDPOINT_FILE="$RUN_DIR/endpoint.env"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$RUN_DIR" "$DATA_DIR"


# Если старый endpoint еще жив, переиспользуем его вместо нового запуска.
reuse_saved_endpoint_if_alive() {
  local saved_host saved_port saved_url
  if ! scanforge_load_endpoint_state "$ENDPOINT_FILE"; then
    return 1
  fi
  saved_host="$QA_PORTAL_HOST"
  saved_port="$QA_PORTAL_PORT"
  saved_url="$SCANFORGE_URL"
  if scanforge_healthcheck "$saved_host" "$saved_port"; then
    HOST="$saved_host"
    DESIRED_PORT="$saved_port"
    SCANFORGE_HOST="$saved_host"
    SCANFORGE_PORT="$saved_port"
    SCANFORGE_URL="$saved_url"
    export SCANFORGE_HOST SCANFORGE_PORT SCANFORGE_URL
    printf '%s\n' "$saved_url"
    return 0
  fi
  return 1
}


start_web() {
  if scanforge_healthcheck "$HOST" "$SCANFORGE_PORT"; then
    return 0
  fi
  if scanforge_pid_is_running "$WEB_PID_FILE"; then
    scanforge_stop_pid_file "$WEB_PID_FILE"
  fi

  (
    cd "$ROOT_DIR"
    export QA_PORTAL_DATA_DIR="$DATA_DIR"
    export QA_PORTAL_HOST="$HOST"
    export QA_PORTAL_PORT="$SCANFORGE_PORT"
    export QA_PORTAL_RELOAD=0
    export QA_PORTAL_AUTOSTART_WORKER=0
    nohup "$ROOT_DIR/run-server.sh" >>"$LOG_DIR/web.log" 2>&1 &
    echo "$!" >"$WEB_PID_FILE"
  )
}


start_worker() {
  if scanforge_pid_is_running "$WORKER_PID_FILE"; then
    return 0
  fi

  (
    cd "$ROOT_DIR"
    export QA_PORTAL_DATA_DIR="$DATA_DIR"
    export QA_PORTAL_HOST="$HOST"
    export QA_PORTAL_PORT="$SCANFORGE_PORT"
    export QA_PORTAL_RELOAD=0
    export QA_PORTAL_AUTOSTART_WORKER=0
    nohup "$ROOT_DIR/run-worker.sh" >>"$LOG_DIR/worker.log" 2>&1 &
    echo "$!" >"$WORKER_PID_FILE"
  )
}


wait_for_health() {
  local attempt
  for attempt in $(seq 1 60); do
    if scanforge_healthcheck "$HOST" "$SCANFORGE_PORT"; then
      return 0
    fi
    sleep 1
  done
  return 1
}


if reuse_saved_endpoint_if_alive; then
  start_worker
  scanforge_write_endpoint_state "$ENDPOINT_FILE" "$HOST" "$DESIRED_PORT"
  exit 0
fi

scanforge_pick_port "$HOST" "$DESIRED_PORT" 8000 8100
HOST="$SCANFORGE_HOST"

if [[ "$SCANFORGE_PICK_STATUS" == "preferred-occupied-foreign" ]]; then
  printf 'Порт %s занят сторонним сервисом. Используем %s.\n' "$DESIRED_PORT" "$SCANFORGE_URL" >&2
fi

if [[ "$SCANFORGE_PICK_STATUS" == "scanforge-running" || "$SCANFORGE_PICK_STATUS" == "fallback-running-scanforge" ]]; then
  start_worker
  scanforge_write_endpoint_state "$ENDPOINT_FILE" "$HOST" "$SCANFORGE_PORT"
  printf '%s\n' "$SCANFORGE_URL"
  exit 0
fi

start_web
start_worker

if ! wait_for_health; then
  rm -f "$ENDPOINT_FILE"
  printf 'ScanForge стартовал, но healthcheck не прошел по адресу %s.\n' "$SCANFORGE_URL" >&2
  exit 1
fi

scanforge_write_endpoint_state "$ENDPOINT_FILE" "$HOST" "$SCANFORGE_PORT"
printf '%s\n' "$SCANFORGE_URL"
