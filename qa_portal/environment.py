from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


# Базовый список Python-зависимостей читается из requirements.txt в корне проекта.
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def requirements_path(root: Path | None = None) -> Path:
    return (root or project_root()) / "requirements.txt"


def _python_version_text() -> str:
    return ".".join(str(part) for part in sys.version_info[:3])


def _project_venv_dir(root: Path) -> Path:
    return root / ".venv"


def _project_venv_python(root: Path) -> Path:
    return _project_venv_dir(root) / "bin" / "python"


def _is_project_venv_active(root: Path) -> bool:
    try:
        return Path(sys.prefix).resolve().is_relative_to(_project_venv_dir(root).resolve())
    except AttributeError:  # pragma: no cover
        prefix = str(Path(sys.prefix).resolve())
        return prefix.startswith(str(_project_venv_dir(root).resolve()))


def _parse_requirements(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    items: list[dict[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        requirement = stripped.split("#", 1)[0].strip()
        if not requirement:
            continue
        name = requirement
        spec = ""
        for marker in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if marker in requirement:
                name, tail = requirement.split(marker, 1)
                spec = marker + tail.strip()
                break
        items.append(
            {
                "name": name.strip(),
                "spec": spec.strip(),
                "raw": requirement,
            }
        )
    return items


def _installed_distribution_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _pip_available(python_bin: str) -> bool:
    result = subprocess.run(
        [python_bin, "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def _venv_available(python_bin: str) -> bool:
    result = subprocess.run(
        [python_bin, "-m", "venv", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False
    with tempfile.TemporaryDirectory(prefix="scanforge-venv-check-") as temp_dir:
        candidate = Path(temp_dir) / "venv"
        create_result = subprocess.run(
            [python_bin, "-m", "venv", str(candidate)],
            capture_output=True,
            text=True,
            check=False,
        )
        return create_result.returncode == 0 and (candidate / "bin" / "python").exists()


def build_environment_status(root: Path | None = None) -> dict[str, Any]:
    base = root or project_root()
    requirements_file = requirements_path(base)
    project_venv_python = _project_venv_python(base)
    requirements = _parse_requirements(requirements_file)

    installed_requirements: list[dict[str, str]] = []
    missing_requirements: list[dict[str, str]] = []
    version_mismatches: list[dict[str, str]] = []

    for item in requirements:
        version = _installed_distribution_version(item["name"])
        record = {
            "name": item["name"],
            "spec": item["spec"],
            "installed_version": version or "",
        }
        if version is None:
            missing_requirements.append(record)
            continue
        if item["spec"].startswith("==") and version != item["spec"][2:].strip():
            version_mismatches.append(record)
            continue
        installed_requirements.append(record)

    # Менеджер пакетов определяем через существующий toolchain-слой, чтобы UI и preflight не расходились.
    from .tooling import detect_package_manager

    package_manager = detect_package_manager()
    current_runtime_ready = (
        _pip_available(sys.executable)
        and _venv_available(sys.executable)
        and not missing_requirements
        and not version_mismatches
    )
    project_venv_ready = project_venv_python.exists()
    project_writable = os.access(base, os.W_OK)
    is_admin = bool(getattr(os, "geteuid", lambda: 1)() == 0)

    issues: list[str] = []
    if not project_venv_ready:
        issues.append("Project virtual environment is missing.")
    if not _pip_available(sys.executable):
        issues.append("pip is not available in the current interpreter.")
    if not _venv_available(sys.executable):
        issues.append("The current interpreter does not provide the venv module.")
    if missing_requirements:
        issues.append(f"Missing Python requirements: {', '.join(item['name'] for item in missing_requirements[:8])}.")
    if version_mismatches:
        issues.append(
            "Pinned Python requirements have version mismatches: "
            + ", ".join(f"{item['name']} ({item['installed_version']})" for item in version_mismatches[:8])
            + "."
        )
    if not project_writable:
        issues.append("The project directory is not writable for the current user.")

    bootstrap_recommended = not _is_project_venv_active(base) or not project_venv_ready
    summary = "ready" if current_runtime_ready else "needs-bootstrap"
    if current_runtime_ready and bootstrap_recommended:
        summary = "ready-with-warning"

    return {
        "summary": summary,
        "current_runtime_ready": current_runtime_ready,
        "bootstrap_recommended": bootstrap_recommended,
        "python_executable": sys.executable,
        "python_version": _python_version_text(),
        "pip_available": _pip_available(sys.executable),
        "venv_available": _venv_available(sys.executable),
        "project_root": str(base),
        "project_writable": project_writable,
        "requirements_path": str(requirements_file),
        "requirements_present": requirements_file.exists(),
        "requirements_total": len(requirements),
        "requirements_satisfied": len(installed_requirements),
        "missing_requirements": missing_requirements,
        "version_mismatches": version_mismatches,
        "package_manager": package_manager or "",
        "project_venv": {
            "path": str(_project_venv_dir(base)),
            "python_path": str(project_venv_python),
            "exists": project_venv_ready,
            "active": _is_project_venv_active(base),
        },
        "current_user_is_admin": is_admin,
        "bootstrap_command": "./scripts/setup-scanforge.sh",
        "preflight_command": "./scripts/scanforge-preflight.sh",
        "issues": issues,
    }


def preflight_ok(root: Path | None = None) -> bool:
    return bool(build_environment_status(root).get("current_runtime_ready"))


def render_preflight_text(status: dict[str, Any]) -> str:
    lines = [
        "ScanForge preflight",
        f"Python: {status['python_executable']} ({status['python_version']})",
        f"Project root: {status['project_root']}",
        f"Project venv: {'active' if status['project_venv']['active'] else 'inactive'}"
        f" · {'present' if status['project_venv']['exists'] else 'missing'}",
        f"pip: {'ready' if status['pip_available'] else 'missing'}",
        f"venv module: {'ready' if status['venv_available'] else 'missing'}",
        f"Requirements: {status['requirements_satisfied']}/{status['requirements_total']}",
        f"Package manager: {status['package_manager'] or 'unknown'}",
        f"Writable project dir: {'yes' if status['project_writable'] else 'no'}",
        f"Current runtime ready: {'yes' if status['current_runtime_ready'] else 'no'}",
    ]
    if status["missing_requirements"]:
        lines.append(
            "Missing requirements: "
            + ", ".join(item["name"] for item in status["missing_requirements"][:12])
        )
    if status["version_mismatches"]:
        lines.append(
            "Version mismatches: "
            + ", ".join(
                f"{item['name']}={item['installed_version']} expected {item['spec']}"
                for item in status["version_mismatches"][:12]
            )
        )
    if status["issues"]:
        lines.append("Issues:")
        lines.extend(f"- {item}" for item in status["issues"])
    lines.append(f"Bootstrap command: {status['bootstrap_command']}")
    lines.append(f"Preflight command: {status['preflight_command']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ScanForge environment diagnostics.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Check whether the current Python runtime is ready.",
        description="ScanForge environment diagnostics.",
    )
    preflight_parser.add_argument("--format", choices=("text", "json"), default="text")
    preflight_parser.add_argument("--root", default="")

    args = parser.parse_args(argv)

    if args.command == "preflight":
        root = Path(args.root).resolve() if args.root else None
        status = build_environment_status(root)
        if args.format == "json":
            print(json.dumps(status, ensure_ascii=False))
        else:
            print(render_preflight_text(status))
        return 0 if status["current_runtime_ready"] else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
