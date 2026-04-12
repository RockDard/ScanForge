#!/usr/bin/env bash
set -euo pipefail

# Выбираем Python из локального .venv, если он уже подготовлен для проекта.
scanforge_init_python() {
  local root_dir="$1"
  PYTHON_BIN="python3"
  if [[ -x "$root_dir/.venv/bin/python" ]]; then
    PYTHON_BIN="$root_dir/.venv/bin/python"
  fi
  if [[ -n "${PYTHONPATH:-}" ]]; then
    export PYTHONPATH="$root_dir:$PYTHONPATH"
  else
    export PYTHONPATH="$root_dir"
  fi
  export PYTHON_BIN
}


# Подключаем пользовательский .env только если он существует в корне проекта.
scanforge_load_project_env() {
  local root_dir="$1"
  if [[ -f "$root_dir/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$root_dir/.env"
    set +a
  fi
}


# Проверка живого ScanForge идет через единый runtime helper.
scanforge_healthcheck() {
  local host="$1"
  local port="$2"
  "$PYTHON_BIN" -m qa_portal.runtime healthcheck --host "$host" --port "$port"
}


# Читаем сохраненный endpoint.env и экспортируем переменные только при валидном состоянии.
scanforge_load_endpoint_state() {
  local endpoint_file="$1"
  if [[ ! -f "$endpoint_file" ]]; then
    return 1
  fi
  # shellcheck source=/dev/null
  source "$endpoint_file"
  if [[ -z "${QA_PORTAL_HOST:-}" || -z "${QA_PORTAL_PORT:-}" || -z "${SCANFORGE_URL:-}" ]]; then
    return 1
  fi
  export QA_PORTAL_HOST QA_PORTAL_PORT SCANFORGE_URL
  return 0
}


# Запрашиваем у runtime helper лучший порт и сохраняем его в переменные shell.
scanforge_pick_port() {
  local host="$1"
  local desired_port="$2"
  local range_start="${3:-8000}"
  local range_end="${4:-8100}"
  local output
  if ! output="$("$PYTHON_BIN" -m qa_portal.runtime pick-port \
    --host "$host" \
    --desired-port "$desired_port" \
    --range-start "$range_start" \
    --range-end "$range_end" \
    --format shell)"; then
    return 1
  fi
  eval "$output"
  export SCANFORGE_HOST SCANFORGE_PORT SCANFORGE_URL SCANFORGE_PICK_STATUS SCANFORGE_PICK_MESSAGE
}


# Фиксируем актуальный адрес ScanForge в endpoint.env для повторного открытия.
scanforge_write_endpoint_state() {
  local endpoint_file="$1"
  local host="$2"
  local port="$3"
  "$PYTHON_BIN" -m qa_portal.runtime write-state --path "$endpoint_file" --host "$host" --port "$port"
}


scanforge_pid_is_running() {
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


# Останавливаем фоновые процессы ScanForge и чистим pid-файлы.
scanforge_stop_pid_file() {
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
