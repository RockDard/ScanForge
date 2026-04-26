#!/usr/bin/env bash
set -euo pipefail

print_help() {
  cat <<'EOF'
Usage: ./scripts/start-scanforge-admin.sh

Starts ScanForge web and worker processes as an administrator. By default the
web server listens on all interfaces, writes endpoint.env, and prints the
local browser URL.
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

# Общий helper синхронизирует healthcheck, pid-контур и подбор порта.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

STATE_DIR="${SCANFORGE_STATE_DIR:-/var/lib/scanforge}"
LOG_DIR="${SCANFORGE_LOG_DIR:-/var/log/scanforge}"
RUN_DIR="${SCANFORGE_RUN_DIR:-/var/run/scanforge}"
DATA_DIR="${QA_PORTAL_DATA_DIR:-$STATE_DIR/data}"

HOST="${QA_PORTAL_HOST:-0.0.0.0}"
DESIRED_PORT="${QA_PORTAL_PORT:-8000}"

WEB_PID_FILE="$RUN_DIR/web.pid"
WORKER_PID_FILE="$RUN_DIR/worker.pid"
ENDPOINT_FILE="$RUN_DIR/endpoint.env"

mkdir -p "$STATE_DIR" "$LOG_DIR" "$RUN_DIR" "$DATA_DIR"


# Если сохраненный runtime устарел относительно текущего кода, останавливаем его и запускаем заново.
stop_stale_runtime() {
  scanforge_stop_pid_file "$WORKER_PID_FILE"
  scanforge_stop_pid_file "$WEB_PID_FILE"
  rm -f "$ENDPOINT_FILE"
}


# Если старый endpoint еще жив, переиспользуем его вместо нового запуска.
reuse_saved_endpoint_if_alive() {
  local saved_host saved_port saved_url
  if ! scanforge_load_endpoint_state "$ENDPOINT_FILE"; then
    return 1
  fi
  saved_host="$QA_PORTAL_HOST"
  saved_port="$QA_PORTAL_PORT"
  saved_url="$SCANFORGE_URL"
  if [[ "$saved_host" != "$HOST" ]]; then
    printf 'Сохраненный endpoint %s слушает %s, а требуется %s. Выполняется перезапуск.\n' "$saved_url" "$saved_host" "$HOST" >&2
    stop_stale_runtime
    return 1
  fi
  if scanforge_healthcheck "$saved_host" "$saved_port"; then
    if ! scanforge_compatibilitycheck "$saved_host" "$saved_port"; then
      printf 'Сохраненный endpoint %s отвечает, но запущен на устаревшей версии ScanForge. Выполняется перезапуск.\n' "$saved_url" >&2
      stop_stale_runtime
      return 1
    fi
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
    nohup setsid "$ROOT_DIR/run-server.sh" >>"$LOG_DIR/web.log" 2>&1 &
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
    nohup setsid "$ROOT_DIR/run-worker.sh" >>"$LOG_DIR/worker.log" 2>&1 &
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

if [[ "$SCANFORGE_PICK_STATUS" == "preferred-occupied-incompatible" ]]; then
  printf 'Порт %s занят устаревшим экземпляром ScanForge. Используем %s.\n' "$DESIRED_PORT" "$SCANFORGE_URL" >&2
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
