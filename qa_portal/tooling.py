from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import STALE_RUNNING_SECONDS, TOOL_INSTALL_JOBS_DIR


if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 1000  # type: ignore[attr-defined]


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
        key="valgrind",
        label="Valgrind",
        binaries=("valgrind",),
        packages={
            "apt": ("valgrind",),
            "dnf": ("valgrind",),
            "pacman": ("valgrind",),
        },
        description="Инструментированный runtime-анализ памяти и утечек.",
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
        key="python3",
        label="Python 3",
        binaries=("python3",),
        packages={
            "apt": ("python3",),
            "dnf": ("python3",),
            "pacman": ("python",),
        },
        description="Интерпретатор Python для compileall и тестов.",
    ),
    ToolSpec(
        key="pytest",
        label="pytest",
        binaries=("pytest", "pytest-3"),
        packages={
            "apt": ("python3-pytest",),
            "dnf": ("python3-pytest",),
            "pacman": ("python-pytest",),
        },
        description="Запуск автотестов Python-проектов.",
    ),
    ToolSpec(
        key="go",
        label="Go",
        binaries=("go",),
        packages={
            "apt": ("golang-go",),
            "dnf": ("golang",),
            "pacman": ("go",),
        },
        description="Сборка и тестирование Go-проектов.",
    ),
    ToolSpec(
        key="node",
        label="Node.js",
        binaries=("node",),
        packages={
            "apt": ("nodejs",),
            "dnf": ("nodejs",),
            "pacman": ("nodejs",),
        },
        description="Проверка JavaScript/TypeScript проектов и runtime-сервисов.",
    ),
    ToolSpec(
        key="npm",
        label="npm",
        binaries=("npm",),
        packages={
            "apt": ("npm",),
            "dnf": ("npm",),
            "pacman": ("npm",),
        },
        description="Менеджер пакетов Node.js для вспомогательных сценариев.",
    ),
    ToolSpec(
        key="tsc",
        label="TypeScript",
        binaries=("tsc",),
        packages={
            "apt": ("node-typescript",),
            "dnf": ("typescript",),
            "pacman": ("typescript",),
        },
        description="Статическая проверка TypeScript без генерации артефактов.",
    ),
    ToolSpec(
        key="strace",
        label="strace",
        binaries=("strace",),
        packages={
            "apt": ("strace",),
            "dnf": ("strace",),
            "pacman": ("strace",),
        },
        description="Трассировка системных вызовов для runtime и replay-профилей.",
    ),
    ToolSpec(
        key="gdb",
        label="gdb",
        binaries=("gdb",),
        packages={
            "apt": ("gdb",),
            "dnf": ("gdb",),
            "pacman": ("gdb",),
        },
        description="Отладчик для crash replay и глубокой диагностики.",
    ),
    ToolSpec(
        key="docker",
        label="Docker",
        binaries=("docker",),
        packages={
            "apt": ("docker.io",),
            "dnf": ("docker",),
            "pacman": ("docker",),
        },
        description="Контейнерный runtime для full-system и sandbox-сценариев.",
    ),
    ToolSpec(
        key="qemu_system",
        label="QEMU",
        binaries=("qemu-system-x86_64",),
        packages={
            "apt": ("qemu-system-x86",),
            "dnf": ("qemu-system-x86",),
            "pacman": ("qemu-system-x86",),
        },
        description="Полноценный full-system runtime и VM-профилирование.",
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
INSTALL_LOCK = threading.Lock()
INSTALL_JOB_LOCK = threading.RLock()

InstallLogCallback = Callable[[str], None]
InstallProgressCallback = Callable[[int, str], None]


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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _install_job_path(job_id: str) -> Path:
    return TOOL_INSTALL_JOBS_DIR / f"{job_id}.json"


def _write_install_job(job: dict[str, Any]) -> dict[str, Any]:
    TOOL_INSTALL_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job["updated_at"] = _utc_now()
    destination = _install_job_path(str(job["id"]))
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(TOOL_INSTALL_JOBS_DIR),
    ) as handle:
        json.dump(job, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(destination)
    return job


def _read_install_job(job_id: str) -> dict[str, Any]:
    return json.loads(_install_job_path(job_id).read_text(encoding="utf-8"))


def _mutate_install_job(job_id: str, mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with INSTALL_JOB_LOCK:
        job = _read_install_job(job_id)
        mutator(job)
        return _write_install_job(job)


def _append_install_log(job_id: str, line: str) -> None:
    def mutate(job: dict[str, Any]) -> None:
        job.setdefault("logs", []).append(line)

    _mutate_install_job(job_id, mutate)


def _update_install_progress(job_id: str, progress: int, message: str) -> None:
    def mutate(job: dict[str, Any]) -> None:
        job["progress"] = max(0, min(int(progress), 100))
        job["message"] = message

    _mutate_install_job(job_id, mutate)


def recover_stale_tool_install_jobs(stale_seconds: int = STALE_RUNNING_SECONDS) -> list[dict[str, Any]]:
    if not TOOL_INSTALL_JOBS_DIR.exists():
        return []
    recovered: list[dict[str, Any]] = []
    cutoff = datetime.now(timezone.utc).timestamp() - max(60, stale_seconds)
    with INSTALL_JOB_LOCK:
        for path in sorted(TOOL_INSTALL_JOBS_DIR.glob("*.json")):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(job, dict) or job.get("status") not in {"queued", "running"}:
                continue
            updated_at = _parse_timestamp(job.get("updated_at") or job.get("started_at") or job.get("created_at"))
            if updated_at is not None and updated_at.timestamp() > cutoff:
                continue
            job["status"] = "failed"
            job["progress"] = 100
            job["message"] = "Tool installation was interrupted before completion."
            job["finished_at"] = _utc_now()
            job.setdefault("logs", []).append("Recovered stale install job after process restart.")
            recovered.append(_write_install_job(job))
    return recovered


def list_tool_install_jobs(limit: int = 20) -> list[dict[str, Any]]:
    recover_stale_tool_install_jobs()
    if not TOOL_INSTALL_JOBS_DIR.exists():
        return []
    jobs: list[dict[str, Any]] = []
    with INSTALL_JOB_LOCK:
        for path in sorted(TOOL_INSTALL_JOBS_DIR.glob("*.json"), reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(payload, dict):
                jobs.append(payload)
    jobs.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return jobs[: max(1, limit)]


def tool_install_job_status(job_id: str) -> dict[str, Any]:
    recover_stale_tool_install_jobs()
    try:
        return _read_install_job(job_id)
    except (OSError, ValueError) as exc:
        raise FileNotFoundError(job_id) from exc


def latest_tool_install_job_for_tool(tool_key: str) -> dict[str, Any] | None:
    for job in list_tool_install_jobs(limit=100):
        if job.get("tool_key") == tool_key:
            return job
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
        install_job = latest_tool_install_job_for_tool(spec.key)
        install_running = bool(install_job and install_job.get("status") in {"queued", "running"})
        inventory.append(
            {
                "key": spec.key,
                "label": spec.label,
                "path": path,
                "installed": bool(path),
                "package_manager": package_manager,
                "packages": packages,
                "installable": bool(not path and package_manager and packages and not install_running),
                "install_job": install_job,
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
            ["apt-get", "install", "-y", "--no-install-recommends", *packages],
        ]
    if package_manager == "dnf":
        return [["dnf", "install", "-y", *packages]]
    if package_manager == "pacman":
        return [["pacman", "-Sy", "--noconfirm", *packages]]
    return []


def _dry_run_commands(package_manager: str, packages: list[str]) -> list[list[str]]:
    if package_manager == "apt":
        return [["apt-get", "install", "-s", "--no-install-recommends", *packages]]
    if package_manager == "dnf":
        return [["dnf", "install", "--assumeno", *packages]]
    if package_manager == "pacman":
        return [["pacman", "-Sp", "--print-format", "%n %v", *packages]]
    return []


def _privilege_status() -> dict[str, Any]:
    if os.geteuid() == 0:  # type: ignore[attr-defined]
        return {"mode": "root", "available": True, "message": "Current process has administrator rights."}

    sudo_path = shutil.which("sudo")
    sudo_password = os.environ.get("SCANFORGE_SUDO_PASSWORD", "")
    if sudo_path and sudo_password:
        return {"mode": "sudo-password", "available": True, "message": "sudo will use SCANFORGE_SUDO_PASSWORD."}

    if sudo_path:
        check = subprocess.run([sudo_path, "-n", "true"], capture_output=True, text=True, check=False)
        if check.returncode == 0:
            return {"mode": "sudo-passwordless", "available": True, "message": "passwordless sudo is available."}

    pkexec_path = shutil.which("pkexec")
    if pkexec_path:
        return {"mode": "pkexec", "available": True, "message": "pkexec is available for interactive elevation."}

    return {
        "mode": "none",
        "available": False,
        "message": "Administrator rights are required and no sudo/pkexec runner was detected.",
    }


def _apt_source_lines() -> list[tuple[Path, int, str]]:
    paths = [Path("/etc/apt/sources.list")]
    source_dir = Path("/etc/apt/sources.list.d")
    if source_dir.exists():
        paths.extend(sorted(source_dir.glob("*.list")))
    lines: list[tuple[Path, int, str]] = []
    for path in paths:
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            stripped = raw_line.strip()
            if stripped.startswith("deb "):
                lines.append((path, line_number, stripped))
    return lines


def _normalize_apt_source_line(line: str) -> str:
    parts = line.split()
    if len(parts) >= 2 and parts[1].startswith("["):
        while len(parts) > 1 and not parts[1].endswith("]"):
            parts.pop(1)
        if len(parts) > 1:
            parts.pop(1)
    return " ".join(parts[:4]).casefold()


def _apt_preflight() -> dict[str, Any]:
    warnings: list[str] = []
    source_lines = _apt_source_lines()
    seen: dict[str, tuple[Path, int]] = {}
    duplicates: list[dict[str, Any]] = []
    for path, line_number, line in source_lines:
        normalized = _normalize_apt_source_line(line)
        if normalized in seen:
            first_path, first_line = seen[normalized]
            duplicates.append(
                {
                    "source": normalized,
                    "first": f"{first_path}:{first_line}",
                    "duplicate": f"{path}:{line_number}",
                }
            )
        else:
            seen[normalized] = (path, line_number)
    if duplicates:
        warnings.append(f"Duplicate apt source entries detected: {len(duplicates)}.")

    legacy_keyring = Path("/etc/apt/trusted.gpg")
    try:
        legacy_keyring_present = legacy_keyring.exists() and legacy_keyring.stat().st_size > 0
    except OSError:
        legacy_keyring_present = False
    if legacy_keyring_present:
        warnings.append("Legacy apt keyring /etc/apt/trusted.gpg is present; prefer signed-by keyrings.")

    return {
        "source_entries": len(source_lines),
        "duplicate_sources": duplicates[:20],
        "legacy_keyring_present": legacy_keyring_present,
        "warnings": warnings,
    }


def tool_install_preflight(tool_key: str | None = None) -> dict[str, Any]:
    package_manager = detect_package_manager()
    privilege = _privilege_status()
    warnings: list[str] = []
    issues: list[str] = []
    apt = _apt_preflight() if package_manager == "apt" else {}
    warnings.extend(apt.get("warnings", []))

    tool_payload: dict[str, Any] = {}
    if tool_key:
        spec = TOOL_SPEC_BY_KEY.get(tool_key)
        if spec is None:
            issues.append(f"Unknown tool: {tool_key}")
        else:
            packages = list(spec.packages.get(package_manager or "", ()))
            installed_path = _tool_path(spec)
            tool_payload = {
                "key": spec.key,
                "label": spec.label,
                "installed": bool(installed_path),
                "path": installed_path,
                "packages": packages,
                "installable": bool(not installed_path and package_manager and packages),
            }
            if not installed_path and not packages:
                issues.append(f"{spec.label} cannot be installed automatically on this host.")

    if not package_manager:
        issues.append("Supported package manager was not detected.")
    if package_manager and not privilege["available"]:
        issues.append(privilege["message"])

    return {
        "package_manager": package_manager,
        "privilege": privilege,
        "apt": apt,
        "tool": tool_payload,
        "warnings": warnings,
        "issues": issues,
        "ok": not issues,
    }


def _install_plan(tool_key: str) -> dict[str, Any]:
    spec = TOOL_SPEC_BY_KEY.get(tool_key)
    if spec is None:
        return {"ok": False, "status": "unknown-tool", "message": f"Unknown tool: {tool_key}"}
    existing_path = _tool_path(spec)
    package_manager = detect_package_manager()
    packages = list(spec.packages.get(package_manager or "", ()))
    commands = _install_commands(package_manager or "", packages)
    dry_commands = _dry_run_commands(package_manager or "", packages)
    return {
        "ok": bool(existing_path or (package_manager and packages and commands)),
        "status": "already-installed" if existing_path else ("ready" if package_manager and packages and commands else "unsupported"),
        "tool_key": spec.key,
        "label": spec.label,
        "path": existing_path,
        "package_manager": package_manager,
        "packages": packages,
        "commands": [_display_command(command) for command in commands],
        "dry_run_commands": [_display_command(command) for command in dry_commands],
        "message": (
            f"{spec.label} is already installed."
            if existing_path
            else (
                f"{spec.label} can be installed with {package_manager}."
                if package_manager and packages and commands
                else f"{spec.label} cannot be installed automatically on this host."
            )
        ),
    }


def dry_run_host_tool(tool_key: str) -> dict[str, Any]:
    plan = _install_plan(tool_key)
    preflight = tool_install_preflight(tool_key)
    payload = {
        **plan,
        "preflight": preflight,
        "confirmation_required": plan.get("status") == "ready",
        "logs": [],
    }
    if plan.get("status") != "ready":
        return payload

    dry_commands = _dry_run_commands(str(plan.get("package_manager") or ""), list(plan.get("packages") or []))
    logs: list[str] = []
    ok = True
    for command in dry_commands:
        logs.append(f"$ {_display_command(command)}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            logs.append(str(exc))
            ok = False
            break
        if result.stdout.strip():
            logs.append(result.stdout.strip())
        if result.stderr.strip():
            logs.append(result.stderr.strip())
        if result.returncode not in {0, 1}:
            ok = False
    payload["logs"] = logs
    payload["dry_run_ok"] = ok
    if not ok:
        payload["ok"] = False
        payload["status"] = "dry-run-failed"
        payload["message"] = f"Dry-run for {plan.get('label')} failed."
    return payload


def _privileged_runner(command: list[str]) -> tuple[list[str], str | None, str | None]:
    if os.geteuid() == 0:  # type: ignore[attr-defined]
        return command, None, None

    sudo_path = shutil.which("sudo")
    sudo_password = os.environ.get("SCANFORGE_SUDO_PASSWORD", "")
    if sudo_path and sudo_password:
        return [sudo_path, "-S", "-p", "", "env", "DEBIAN_FRONTEND=noninteractive", *command], sudo_password + "\n", "sudo"

    if sudo_path:
        check = subprocess.run([sudo_path, "-n", "true"], capture_output=True, text=True, check=False)
        if check.returncode == 0:
            return [sudo_path, "-n", "env", "DEBIAN_FRONTEND=noninteractive", *command], None, "sudo"

    pkexec_path = shutil.which("pkexec")
    if pkexec_path:
        return [pkexec_path, "env", "DEBIAN_FRONTEND=noninteractive", *command], None, "pkexec"

    return [], None, None


def _display_command(command: list[str]) -> str:
    if command and Path(command[0]).name in {"sudo", "pkexec"}:
        try:
            env_index = command.index("env")
            return " ".join(command[env_index + 2 :])
        except ValueError:
            return " ".join(command[1:])
    return " ".join(command)


# Установка идет через системный пакетный менеджер; для apt ставятся реальные deb-пакеты.
def install_host_tool(
    tool_key: str,
    *,
    confirmed_packages: list[str] | None = None,
    log_callback: InstallLogCallback | None = None,
    progress_callback: InstallProgressCallback | None = None,
) -> dict[str, Any]:
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
    if confirmed_packages is not None and sorted(confirmed_packages) != sorted(packages):
        return {
            "ok": False,
            "status": "package-confirmation-mismatch",
            "packages": packages,
            "message": f"{spec.label} package confirmation no longer matches the current package plan.",
        }
    if not package_manager or not packages:
        return {
            "ok": False,
            "status": "unsupported",
            "message": f"{spec.label} cannot be installed automatically on this host.",
        }

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    logs: list[str] = []
    with INSTALL_LOCK:
        commands = _install_commands(package_manager, packages)
        for index, command in enumerate(commands, start=1):
            privileged_command, stdin, runner = _privileged_runner(command)
            if not privileged_command:
                return {
                    "ok": False,
                    "status": "requires-admin",
                    "packages": packages,
                    "message": f"{spec.label} installation requires administrator rights.",
                }
            if progress_callback:
                progress_callback(
                    20 + int((index - 1) / max(len(commands), 1) * 70),
                    f"Running {_display_command(privileged_command)}",
                )
            result = subprocess.run(
                privileged_command,
                input=stdin,
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=900,
            )
            logs.append(f"$ {_display_command(privileged_command)}")
            if log_callback:
                log_callback(f"$ {_display_command(privileged_command)}")
            if runner:
                logs.append(f"privilege_runner={runner}")
                if log_callback:
                    log_callback(f"privilege_runner={runner}")
            if result.stdout.strip():
                logs.append(result.stdout.strip())
                if log_callback:
                    log_callback(result.stdout.strip())
            if result.stderr.strip():
                logs.append(result.stderr.strip())
                if log_callback:
                    log_callback(result.stderr.strip())
            if result.returncode != 0:
                return {
                    "ok": False,
                    "status": "install-failed",
                    "packages": packages,
                    "logs": logs,
                    "message": f"Automatic installation of {spec.label} failed.",
                }

        refreshed_path = _tool_path(spec)
        if not refreshed_path:
            return {
                "ok": False,
                "status": "installed-but-not-detected",
                "packages": packages,
                "logs": logs,
                "message": f"{spec.label} packages were installed, but the binary was not detected yet.",
            }

    if progress_callback:
        progress_callback(100, f"{spec.label} installation finished.")
    return {
        "ok": True,
        "status": "installed",
        "path": refreshed_path,
        "packages": packages,
        "logs": logs,
        "message": f"{spec.label} installation finished.",
    }


def _tool_install_worker(job_id: str) -> None:
    def set_failed(message: str, result: dict[str, Any] | None = None) -> None:
        def mutate(job: dict[str, Any]) -> None:
            job["status"] = "failed"
            job["progress"] = 100
            job["message"] = message
            job["finished_at"] = _utc_now()
            if result is not None:
                job["result"] = result

        _mutate_install_job(job_id, mutate)

    try:
        job = _mutate_install_job(
            job_id,
            lambda item: item.update(
                {
                    "status": "running",
                    "progress": 5,
                    "message": "Preparing package dry-run.",
                    "started_at": _utc_now(),
                }
            ),
        )
        tool_key = str(job.get("tool_key") or "")
        dry_run = dry_run_host_tool(tool_key)

        def save_dry_run(item: dict[str, Any]) -> None:
            item["dry_run"] = dry_run
            item["packages"] = dry_run.get("packages", [])
            item["progress"] = 20
            item["message"] = "Package dry-run complete."
            item.setdefault("logs", []).extend(dry_run.get("logs", [])[-30:])

        _mutate_install_job(job_id, save_dry_run)
        if dry_run.get("ok") is False:
            set_failed(str(dry_run.get("message") or "Tool install dry-run failed."), dry_run)
            return

        result = install_host_tool(
            tool_key,
            confirmed_packages=list(job.get("confirmed_packages") or dry_run.get("packages") or []),
            log_callback=lambda line: _append_install_log(job_id, line),
            progress_callback=lambda progress, message: _update_install_progress(job_id, progress, message),
        )
        if not result.get("ok"):
            set_failed(str(result.get("message") or "Tool installation failed."), result)
            return

        def set_completed(item: dict[str, Any]) -> None:
            item["status"] = "completed"
            item["progress"] = 100
            item["message"] = str(result.get("message") or "Tool installation finished.")
            item["finished_at"] = _utc_now()
            item["result"] = result

        _mutate_install_job(job_id, set_completed)
    except Exception as exc:  # pragma: no cover - defensive background failure path
        set_failed(f"Tool installation failed: {exc}")


def start_tool_install_job(tool_key: str, *, confirmed_packages: list[str] | None = None) -> dict[str, Any]:
    plan = _install_plan(tool_key)
    if plan.get("status") == "unknown-tool":
        return {**plan, "status": "unknown-tool"}
    if plan.get("status") == "already-installed":
        return {**plan, "ok": True}
    if not plan.get("ok"):
        return plan
    if confirmed_packages is None:
        return {
            **plan,
            "ok": False,
            "status": "confirmation-required",
            "message": "Confirm the package list before installing.",
        }
    if sorted(confirmed_packages) != sorted(list(plan.get("packages") or [])):
        return {
            **plan,
            "ok": False,
            "status": "package-confirmation-mismatch",
            "message": "Confirmed package list no longer matches the current install plan.",
        }

    running = latest_tool_install_job_for_tool(tool_key)
    if running and running.get("status") in {"queued", "running"}:
        return running

    job = {
        "id": uuid.uuid4().hex[:12],
        "tool_key": tool_key,
        "label": plan.get("label", tool_key),
        "status": "queued",
        "progress": 0,
        "message": "Queued for installation.",
        "package_manager": plan.get("package_manager"),
        "packages": list(plan.get("packages") or []),
        "confirmed_packages": confirmed_packages or list(plan.get("packages") or []),
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "started_at": None,
        "finished_at": None,
        "logs": [],
        "dry_run": {},
        "result": {},
    }
    with INSTALL_JOB_LOCK:
        _write_install_job(job)

    thread = threading.Thread(target=_tool_install_worker, args=(str(job["id"]),), daemon=True)
    thread.start()
    return job


def wait_for_tool_install_job(job_id: str, timeout_seconds: float = 10.0) -> dict[str, Any]:
    deadline = datetime.now(timezone.utc).timestamp() + timeout_seconds
    while datetime.now(timezone.utc).timestamp() < deadline:
        job = tool_install_job_status(job_id)
        if job.get("status") in {"completed", "failed"}:
            return job
        threading.Event().wait(0.05)
    return tool_install_job_status(job_id)
