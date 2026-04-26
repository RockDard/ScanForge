#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DESKTOP_DIR="${DESKTOP_DIR:-}"
ICON_PATH="$ROOT_DIR/desktop/scanforge-icon.svg"
LAUNCHER_PATH="$ROOT_DIR/scripts/launch-scanforge-desktop.sh"

print_help() {
  cat <<'EOF'
Usage: ./scripts/install-desktop-shortcut.sh [--desktop-dir /path/to/Desktop]

Creates or updates the ScanForge desktop launcher.
The DESKTOP_DIR environment variable can also be used.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      print_help
      exit 0
      ;;
    --desktop-dir)
      if [[ $# -lt 2 ]]; then
        printf 'Missing value for --desktop-dir.\n' >&2
        exit 1
      fi
      DESKTOP_DIR="$2"
      shift 2
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      print_help >&2
      exit 1
      ;;
  esac
done

if [[ -z "$DESKTOP_DIR" ]]; then
  if command -v xdg-user-dir >/dev/null 2>&1; then
    DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
  fi
  DESKTOP_DIR="${DESKTOP_DIR:-$HOME/Desktop}"
fi

SHORTCUT_PATH="$DESKTOP_DIR/ScanForge.desktop"

mkdir -p "$DESKTOP_DIR"

cat >"$SHORTCUT_PATH" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=ScanForge
Comment=Запуск ScanForge с правами администратора
Exec="${LAUNCHER_PATH}"
Path=${ROOT_DIR}
Icon=${ICON_PATH}
Terminal=false
Categories=Development;Security;Utility;
StartupNotify=true
EOF

chmod +x "$SHORTCUT_PATH"

if command -v gio >/dev/null 2>&1; then
  gio set "$SHORTCUT_PATH" metadata::trusted true >/dev/null 2>&1 || true
fi

printf '%s\n' "$SHORTCUT_PATH"
