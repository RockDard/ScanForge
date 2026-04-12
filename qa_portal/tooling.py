from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ToolSpec:
    key: str
    label: str
    binaries: tuple[str, ...]
    packages: dict[str, tuple[str, ...]]
    description: str


# Каталог хостовых инструментов, с которыми работает ScanForge.
TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        key="cmake",
        label="CMake",
        binaries=("cmake",),
        packages={
            "apt": ("cmake",),
            "dnf": ("cmake",),
            "pacman": ("cmake",),
        },
        description="Конфигурация и сборка C/C++-проектов.",
    ),
    ToolSpec(
        key="ctest",
        label="CTest",
        binaries=("ctest",),
        packages={
            "apt": ("cmake",),
            "dnf": ("cmake",),
            "pacman": ("cmake",),
        },
        description="Запуск тестов CMake/CTest.",
    ),
    ToolSpec(
        key="ninja",
        label="Ninja",
        binaries=("ninja",),
        packages={
            "apt": ("ninja-build",),
            "dnf": ("ninja-build",),
            "pacman": ("ninja",),
        },
        description="Быстрая backend-сборка для CMake.",
    ),
    ToolSpec(
        key="make",
        label="GNU Make",
        binaries=("make",),
        packages={
            "apt": ("build-essential",),
            "dnf": ("make", "gcc-c++"),
            "pacman": ("base-devel",),
        },
        description="Базовый инструмент сборки для Unix.",
    ),
    ToolSpec(
        key="clang",
        label="Clang",
        binaries=("clang",),
        packages={
            "apt": ("clang",),
            "dnf": ("clang",),
            "pacman": ("clang",),
        },
        description="Компилятор C/C++ для анализа и сборки.",
    ),
    ToolSpec(
        key="clangxx",
        label="Clang++",
        binaries=("clang++",),
        packages={
            "apt": ("clang",),
            "dnf": ("clang",),
            "pacman": ("clang",),
        },
        description="Компилятор C++ для CMake и fuzzing-контура.",
    ),
    ToolSpec(
        key="clang_tidy",
        label="clang-tidy",
        binaries=("clang-tidy",),
        packages={
            "apt": ("clang-tidy",),
            "dnf": ("clang-tools-extra",),
            "pacman": ("clang",),
        },
        description="Статический анализ и style-диагностика.",
    ),
    ToolSpec(
        key="cppcheck",
        label="Cppcheck",
        binaries=("cppcheck",),
        packages={
            "apt": ("cppcheck",),
            "dnf": ("cppcheck",),
            "pacman": ("cppcheck",),
        },
        description="Проверка качества и поддерживаемости кода.",
    ),
    ToolSpec(
        key="afl_fuzz",
        label="AFL++",
        binaries=("afl-fuzz",),
        packages={
            "apt": ("afl++",),
            "dnf": ("afl++",),
            "pacman": ("aflplusplus",),
        },
        description="Фаззинг и crash-driven исследование входных данных.",
    ),
    ToolSpec(
        key="qmake",
        label="qmake",
        binaries=("qmake", "qmake6"),
        packages={
            "apt": ("qt6-base-dev", "qt6-base-dev-tools"),
            "dnf": ("qt6-qtbase-devel",),
            "pacman": ("qt6-base",),
        },
        description="Сборка и обнаружение Qt-проектов.",
    ),
    ToolSpec(
        key="nvidia_smi",
        label="nvidia-smi",
        binaries=("nvidia-smi",),
        packages={},
        description="Диагностика NVIDIA GPU и проброса видеокарт.",
    ),
)

TOOL_SPEC_BY_KEY = {spec.key: spec for spec in TOOL_SPECS}


# Пытаемся определить менеджер пакетов на текущем хосте.
def detect_package_manager() -> str | None:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("pacman"):
        return "pacman"
    return None


def _tool_path(spec: ToolSpec) -> str | None:
    for binary in spec.binaries:
        candidate = shutil.which(binary)
        if candidate:
            return candidate
    return None


def detect_toolchain() -> dict[str, str | None]:
    return {spec.key: _tool_path(spec) for spec in TOOL_SPECS}


# Для UI отдаём расширенное описание: можно ли поставить инструмент и каким пакетом.
def describe_toolchain() -> list[dict[str, Any]]:
    package_manager = detect_package_manager()
    inventory: list[dict[str, Any]] = []
    for spec in TOOL_SPECS:
        path = _tool_path(spec)
        packages = list(spec.packages.get(package_manager or "", ()))
        inventory.append(
            {
                "key": spec.key,
                "label": spec.label,
                "path": path,
                "installed": bool(path),
                "package_manager": package_manager,
                "packages": packages,
                "installable": bool(not path and package_manager and packages),
                "description": spec.description,
            }
        )
    return inventory


def run_command(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> CommandResult:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged_env,
        check=False,
    )
    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _install_commands(package_manager: str, packages: list[str]) -> list[list[str]]:
    if package_manager == "apt":
        return [
            ["apt-get", "update"],
            ["apt-get", "install", "-y", *packages],
        ]
    if package_manager == "dnf":
        return [["dnf", "install", "-y", *packages]]
    if package_manager == "pacman":
        return [["pacman", "-Sy", "--noconfirm", *packages]]
    return []


# Установка выполняется только от имени администратора, чтобы не зависнуть на веб-запросе.
def install_host_tool(tool_key: str) -> dict[str, Any]:
    spec = TOOL_SPEC_BY_KEY.get(tool_key)
    if spec is None:
        return {"ok": False, "status": "unknown-tool", "message": f"Unknown tool: {tool_key}"}

    existing_path = _tool_path(spec)
    if existing_path:
        return {
            "ok": True,
            "status": "already-installed",
            "path": existing_path,
            "message": f"{spec.label} is already installed.",
        }

    package_manager = detect_package_manager()
    packages = list(spec.packages.get(package_manager or "", ()))
    if not package_manager or not packages:
        return {
            "ok": False,
            "status": "unsupported",
            "message": f"{spec.label} cannot be installed automatically on this host.",
        }

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return {
            "ok": False,
            "status": "requires-admin",
            "message": f"{spec.label} installation requires administrator rights.",
        }

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    logs: list[str] = []
    for command in _install_commands(package_manager, packages):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        logs.append(f"$ {' '.join(command)}")
        if result.stdout.strip():
            logs.append(result.stdout.strip())
        if result.stderr.strip():
            logs.append(result.stderr.strip())
        if result.returncode != 0:
            return {
                "ok": False,
                "status": "install-failed",
                "logs": logs,
                "message": f"Automatic installation of {spec.label} failed.",
            }

    refreshed_path = _tool_path(spec)
    return {
        "ok": bool(refreshed_path),
        "status": "installed" if refreshed_path else "installed-but-not-detected",
        "path": refreshed_path,
        "logs": logs,
        "message": f"{spec.label} installation finished.",
    }
