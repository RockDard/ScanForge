#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

print_help() {
  cat <<'EOF'
Usage: ./scripts/launch-scanforge-desktop.sh

Opens an existing ScanForge endpoint or starts ScanForge through pkexec on a
free port. The server listens on all interfaces by default; the desktop browser
opens the local URL.
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

# Общий helper обеспечивает одинаковую логику healthcheck и endpoint state.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

HOST="${QA_PORTAL_HOST:-0.0.0.0}"
PORT="${QA_PORTAL_PORT:-8000}"
RUN_DIR="${SCANFORGE_RUN_DIR:-/var/run/scanforge}"
ENDPOINT_FILE="$RUN_DIR/endpoint.env"
URL="http://127.0.0.1:${PORT}"
LAUNCH_LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/scanforge"
LAUNCH_LOG_FILE="$LAUNCH_LOG_DIR/desktop-launch.log"
HAD_ENDPOINT_STATE=0

mkdir -p "$LAUNCH_LOG_DIR"


log_launch() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LAUNCH_LOG_FILE"
}


log_launch "Старт launcher: cwd=$(pwd), DISPLAY=${DISPLAY:-unset}, WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-unset}, RUN_DIR=$RUN_DIR."


open_browser() {
  local target_url="$1"
  log_launch "Пробуем открыть браузер по адресу $target_url."
  if [[ "${SCANFORGE_SKIP_BROWSER:-0}" == "1" ]]; then
    log_launch "Открытие браузера пропущено по SCANFORGE_SKIP_BROWSER=1."
    return 0
  fi
  if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    log_launch "DISPLAY и WAYLAND_DISPLAY отсутствуют, браузер не будет открыт."
    return 0
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$target_url" >/dev/null 2>&1 &
    log_launch "Команда xdg-open отправлена."
  else
    log_launch "Команда xdg-open не найдена."
  fi
}


# Сначала пытаемся открыть уже живой сохраненный endpoint, если он существует.
if scanforge_load_endpoint_state "$ENDPOINT_FILE"; then
  HAD_ENDPOINT_STATE=1
  log_launch "Найден сохраненный endpoint $SCANFORGE_URL."
  if [[ "$QA_PORTAL_HOST" != "$HOST" ]]; then
    log_launch "Сохраненный endpoint слушает $QA_PORTAL_HOST, а требуется $HOST; нужен перезапуск."
  elif scanforge_healthcheck "$QA_PORTAL_HOST" "$QA_PORTAL_PORT"; then
    if scanforge_compatibilitycheck "$QA_PORTAL_HOST" "$QA_PORTAL_PORT"; then
      log_launch "Сохраненный endpoint отвечает и совместим с текущим кодом, новый старт не требуется."
      open_browser "$SCANFORGE_URL"
      exit 0
    fi
    log_launch "Сохраненный endpoint отвечает, но несовместим с текущим кодом. Потребуется новый старт."
  fi
  log_launch "Сохраненный endpoint не ответил, переходим к новому старту."
fi


# Если сохраненного endpoint не было, можно переиспользовать адрес из окружения
# или найти уже запущенный ScanForge в диапазоне портов.
if [[ "$HAD_ENDPOINT_STATE" != "1" ]]; then
  if scanforge_healthcheck "$HOST" "$PORT"; then
    if scanforge_compatibilitycheck "$HOST" "$PORT"; then
      URL="http://127.0.0.1:${PORT}"
      log_launch "Адрес из окружения уже отвечает и совместим: $URL."
      open_browser "$URL"
      exit 0
    fi
    log_launch "Адрес из окружения отвечает, но экземпляр несовместим с текущим кодом. Выполняем новый старт."
  fi

  if scanforge_pick_port "$HOST" "$PORT" 8000 8100; then
    if [[ "$SCANFORGE_PICK_STATUS" == "scanforge-running" || "$SCANFORGE_PICK_STATUS" == "fallback-running-scanforge" ]]; then
      log_launch "Найден уже запущенный ScanForge без state-файла: $SCANFORGE_URL."
      open_browser "$SCANFORGE_URL"
      exit 0
    fi
  fi
else
  log_launch "Сохраненный endpoint устарел; пропускаем поиск сторонних endpoints и запускаем новый экземпляр."
fi

if ! command -v pkexec >/dev/null 2>&1; then
  log_launch "Не найден pkexec."
  printf 'Не найден pkexec. Установите polkit или запустите ScanForge вручную.\n' >&2
  exit 1
fi

start_output=""
if ! start_output="$(pkexec "$ROOT_DIR/scripts/start-scanforge-admin.sh" 2>&1)"; then
  log_launch "pkexec завершился с ошибкой: $start_output"
  printf '%s\n' "$start_output" >&2
  exit 1
fi
log_launch "pkexec успешно завершился: $start_output"

if [[ "$start_output" =~ http://[^[:space:]]+ ]]; then
  URL="${BASH_REMATCH[0]}"
  log_launch "Из вывода старта извлечен URL $URL."
fi

for _ in $(seq 1 60); do
  if scanforge_load_endpoint_state "$ENDPOINT_FILE"; then
    if scanforge_healthcheck "$QA_PORTAL_HOST" "$QA_PORTAL_PORT" && scanforge_compatibilitycheck "$QA_PORTAL_HOST" "$QA_PORTAL_PORT"; then
      log_launch "Новый endpoint из state-файла отвечает: $SCANFORGE_URL."
      open_browser "$SCANFORGE_URL"
      exit 0
    fi
  fi
  if [[ "$URL" =~ ^http://([^:/]+):([0-9]+)$ ]]; then
    if scanforge_healthcheck "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" && scanforge_compatibilitycheck "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"; then
      log_launch "Новый endpoint из stdout отвечает: $URL."
      open_browser "$URL"
      exit 0
    fi
  fi
  sleep 1
done

log_launch "Старт завершился без рабочего endpoint."
printf 'ScanForge стартовал, но веб-интерфейс не ответил по сохраненному адресу или новому endpoint.\n' >&2
exit 1
