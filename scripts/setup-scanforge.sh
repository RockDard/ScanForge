#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
BOOTSTRAP_PYTHON="${SCANFORGE_BOOTSTRAP_PYTHON:-python3}"
RECREATE=0
SKIP_PIP_UPGRADE=0
INSTALL_SYSTEM_PACKAGES="${SCANFORGE_INSTALL_SYSTEM_PACKAGES:-auto}"
INSTALL_DESKTOP_SHORTCUT="${SCANFORGE_INSTALL_DESKTOP_SHORTCUT:-1}"
DESKTOP_DIR_OVERRIDE="${DESKTOP_DIR:-}"

APT_PACKAGES=(
  python3
  python3-venv
  python3-pip
  ca-certificates
  build-essential
  cmake
  ninja-build
  clang
  clang-tidy
  cppcheck
  valgrind
  afl++
  qt6-base-dev
  qt6-base-dev-tools
  qt6-declarative-dev
  qt6-tools-dev
  qt6-tools-dev-tools
  qmake6
)

DNF_PACKAGES=(
  python3
  python3-pip
  python3-virtualenv
  ca-certificates
  gcc
  gcc-c++
  make
  cmake
  ninja-build
  clang
  clang-tools-extra
  cppcheck
  valgrind
  afl++
  qt6-qtbase-devel
  qt6-qtdeclarative-devel
  qt6-qttools-devel
)

PACMAN_PACKAGES=(
  python
  python-pip
  ca-certificates
  base-devel
  cmake
  ninja
  clang
  cppcheck
  valgrind
  aflplusplus
  qt6-base
  qt6-declarative
  qt6-tools
)

print_help() {
  cat <<'EOF'
Usage: ./scripts/setup-scanforge.sh [--recreate] [--python /path/to/python3] [--skip-pip-upgrade]
                                  [--skip-system-packages] [--skip-desktop-shortcut]
                                  [--desktop-dir /path/to/Desktop]

Installs host packages through apt, dnf, or pacman when possible, creates the project .venv, installs
Python dependencies from requirements.txt, creates the desktop shortcut, and
runs ScanForge preflight diagnostics.
EOF
}

run_privileged() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    if [[ -n "${SCANFORGE_SUDO_PASSWORD:-}" ]]; then
      printf '%s\n' "$SCANFORGE_SUDO_PASSWORD" | env -u SCANFORGE_SUDO_PASSWORD sudo -S -p '' "$@"
      return
    fi
    sudo "$@"
    return
  fi
  if command -v pkexec >/dev/null 2>&1; then
    pkexec "$@"
    return
  fi
  printf 'Administrator privileges are required to run: %s\n' "$*" >&2
  return 1
}

install_apt_packages() {
  local -a missing_packages=()
  local package

  if ! command -v dpkg-query >/dev/null 2>&1; then
    missing_packages=("${APT_PACKAGES[@]}")
  else
    for package in "${APT_PACKAGES[@]}"; do
      if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q '^install ok installed$'; then
        missing_packages+=("$package")
      fi
    done
  fi

  if [[ "${#missing_packages[@]}" -eq 0 ]]; then
    printf 'System packages are already installed.\n'
    return 0
  fi

  printf 'Installing missing system packages: %s\n' "${missing_packages[*]}"
  run_privileged apt-get update
  run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing_packages[@]}"
}

install_dnf_packages() {
  local -a missing_packages=()
  local package

  if ! command -v rpm >/dev/null 2>&1; then
    missing_packages=("${DNF_PACKAGES[@]}")
  else
    for package in "${DNF_PACKAGES[@]}"; do
      if ! rpm -q "$package" >/dev/null 2>&1; then
        missing_packages+=("$package")
      fi
    done
  fi

  if [[ "${#missing_packages[@]}" -eq 0 ]]; then
    printf 'System packages are already installed.\n'
    return 0
  fi

  printf 'Installing missing system packages: %s\n' "${missing_packages[*]}"
  run_privileged dnf install -y "${missing_packages[@]}"
}

install_pacman_packages() {
  local -a missing_packages=()
  local package

  for package in "${PACMAN_PACKAGES[@]}"; do
    if ! pacman -Q "$package" >/dev/null 2>&1; then
      missing_packages+=("$package")
    fi
  done

  if [[ "${#missing_packages[@]}" -eq 0 ]]; then
    printf 'System packages are already installed.\n'
    return 0
  fi

  printf 'Installing missing system packages: %s\n' "${missing_packages[*]}"
  run_privileged pacman -Sy --noconfirm "${missing_packages[@]}"
}

install_system_packages() {
  case "$INSTALL_SYSTEM_PACKAGES" in
    0|false|no|off|skip)
      printf 'System package installation skipped.\n'
      return 0
      ;;
    1|true|yes|on|auto)
      ;;
    *)
      printf 'Invalid SCANFORGE_INSTALL_SYSTEM_PACKAGES value: %s\n' "$INSTALL_SYSTEM_PACKAGES" >&2
      exit 1
      ;;
  esac

  if command -v apt-get >/dev/null 2>&1; then
    install_apt_packages
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    install_dnf_packages
    return
  fi

  if command -v pacman >/dev/null 2>&1; then
    install_pacman_packages
    return
  fi

  if [[ "$INSTALL_SYSTEM_PACKAGES" == "auto" ]]; then
    printf 'Supported package manager was not detected; skipping system package installation.\n' >&2
    return 0
  fi

  printf 'Automatic system package installation requires apt, dnf, or pacman.\n' >&2
  exit 1
}

ensure_project_venv() {
  local temp_venv
  if [[ "$RECREATE" == "1" && -d "$VENV_DIR" ]]; then
    printf 'Recreating virtual environment: %s\n' "$VENV_DIR"
    rm -rf "$VENV_DIR"
  fi

  if [[ -d "$VENV_DIR" && ! -x "$VENV_DIR/bin/python" ]]; then
    printf 'Found incomplete virtual environment at %s; rebuilding it safely.\n' "$VENV_DIR" >&2
    temp_venv="$VENV_DIR.rebuild.$$"
    rm -rf "$temp_venv"
    if ! "$BOOTSTRAP_PYTHON" -m venv "$temp_venv"; then
      rm -rf "$temp_venv"
      return 1
    fi
    rm -rf "$VENV_DIR"
    mv "$temp_venv" "$VENV_DIR"
    return
  fi

  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    if ! "$BOOTSTRAP_PYTHON" -m venv "$VENV_DIR"; then
      rm -rf "$VENV_DIR"
      return 1
    fi
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      print_help
      exit 0
      ;;
    --recreate)
      RECREATE=1
      shift
      ;;
    --skip-pip-upgrade)
      SKIP_PIP_UPGRADE=1
      shift
      ;;
    --skip-system-packages)
      INSTALL_SYSTEM_PACKAGES=0
      shift
      ;;
    --install-system-packages)
      INSTALL_SYSTEM_PACKAGES=1
      shift
      ;;
    --skip-desktop-shortcut)
      INSTALL_DESKTOP_SHORTCUT=0
      shift
      ;;
    --desktop-dir)
      if [[ $# -lt 2 ]]; then
        printf 'Missing value for --desktop-dir.\n' >&2
        exit 1
      fi
      DESKTOP_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --python)
      if [[ $# -lt 2 ]]; then
        printf 'Missing value for --python.\n' >&2
        exit 1
      fi
      BOOTSTRAP_PYTHON="$2"
      shift 2
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      print_help >&2
      exit 1
      ;;
  esac
done

if ! command -v "$BOOTSTRAP_PYTHON" >/dev/null 2>&1; then
  printf 'Python interpreter not found: %s\n' "$BOOTSTRAP_PYTHON" >&2
  exit 1
fi

install_system_packages
ensure_project_venv

export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$SKIP_PIP_UPGRADE" != "1" ]]; then
  "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
fi

"$VENV_DIR/bin/python" -m pip install -r "$ROOT_DIR/requirements.txt"

if [[ "$INSTALL_DESKTOP_SHORTCUT" == "1" ]]; then
  if [[ -n "$DESKTOP_DIR_OVERRIDE" ]]; then
    DESKTOP_DIR="$DESKTOP_DIR_OVERRIDE" "$ROOT_DIR/scripts/install-desktop-shortcut.sh"
  else
    "$ROOT_DIR/scripts/install-desktop-shortcut.sh"
  fi
else
  printf 'Desktop shortcut creation skipped.\n'
fi

"$VENV_DIR/bin/python" -m qa_portal.environment preflight --root "$ROOT_DIR" --format text
