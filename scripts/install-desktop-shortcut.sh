#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DESKTOP_DIR="${DESKTOP_DIR:-$HOME/Desktop}"
SHORTCUT_PATH="$DESKTOP_DIR/ScanForge.desktop"
ICON_PATH="$ROOT_DIR/desktop/scanforge-icon.svg"
LAUNCHER_PATH="$ROOT_DIR/scripts/launch-scanforge-desktop.sh"

mkdir -p "$DESKTOP_DIR"

cat >"$SHORTCUT_PATH" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=ScanForge
Comment=Запуск ScanForge с правами администратора
Exec=${LAUNCHER_PATH}
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
