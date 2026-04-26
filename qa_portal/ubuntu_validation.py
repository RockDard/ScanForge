from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX_PATH = REPO_ROOT / "tests" / "fixtures" / "ubuntu_2204_test_matrix.json"
DEFAULT_REPORT_PATH = REPO_ROOT / "data" / "validation" / "ubuntu_2204_validation_report.json"
DEFAULT_LOG_DIR = REPO_ROOT / "data" / "validation" / "logs"

TARGET_OS = "ubuntu-22.04"
TARGET_PACKAGE_MANAGER = "apt"
DEFAULT_CHECK_TIMEOUT_SECONDS = 1800
VALID_RESULT_STATUSES = {"not-run", "passed", "failed", "skipped", "blocked"}
RUNTIME_RESULT_STATUSES = {"passed", "failed"}
REQUIRED_SCENARIOS = {
    "ubuntu-22.04-root-apt",
    "ubuntu-22.04-sudo-passwordless-apt",
    "ubuntu-22.04-sudo-password-apt",
    "ubuntu-22.04-pkexec-apt",
    "ubuntu-22.04-no-privilege-apt",
}
REQUIRED_PRIVILEGE_MODES = {
    "root",
    "sudo-passwordless",
    "sudo-password",
    "pkexec",
    "no-privilege",
}
INSTALL_CAPABLE_PRIVILEGES = {
    "root",
    "sudo-passwordless",
    "sudo-password",
    "pkexec",
}
INSTALL_CAPABLE_CHECKS = {
    "setup-scanforge",
    "run-tests",
    "web-smoke",
    "tool-install-unit-tests",
    "systemd-unit-render",
    "auth-bootstrap-status",
}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def read_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_file(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load_matrix(path: Path = DEFAULT_MATRIX_PATH) -> dict[str, Any]:
    return read_json_file(path)


def validate_matrix(matrix: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if matrix.get("schema_version") != 1:
        errors.append("matrix.schema_version must be 1")
    if matrix.get("target_os") != TARGET_OS:
        errors.append(f"matrix.target_os must be {TARGET_OS}")
    if matrix.get("package_manager") != TARGET_PACKAGE_MANAGER:
        errors.append(f"matrix.package_manager must be {TARGET_PACKAGE_MANAGER}")

    unsupported_targets = {str(item).casefold() for item in _as_list(matrix.get("unsupported_direct_targets"))}
    for target in ("windows", "wsl", "docker-desktop-windows"):
        if target not in unsupported_targets:
            errors.append(f"matrix.unsupported_direct_targets must include {target}")

    check_catalog = _as_list(matrix.get("check_catalog"))
    check_ids = [str(item.get("id") or "") for item in check_catalog if isinstance(item, dict)]
    if len(check_ids) != len(set(check_ids)):
        errors.append("matrix.check_catalog contains duplicate check ids")
    check_lookup = {str(item.get("id")): item for item in check_catalog if isinstance(item, dict) and item.get("id")}
    if not check_lookup:
        errors.append("matrix.check_catalog must not be empty")

    for check_id, check in check_lookup.items():
        command = str(check.get("command") or "").strip()
        command_lower = command.casefold()
        if not command:
            errors.append(f"check {check_id} command must not be empty")
        if check.get("requires_linux_runtime") is not True:
            errors.append(f"check {check_id} must require Linux runtime")
        if "wsl" in command_lower or "docker" in command_lower or command_lower.endswith(".ps1"):
            errors.append(f"check {check_id} must not use WSL, Docker, or PowerShell")
        if command_lower.startswith("python "):
            errors.append(f"check {check_id} must use python3 or ./.venv/bin/python, not bare python")
        timeout = check.get("timeout_seconds", DEFAULT_CHECK_TIMEOUT_SECONDS)
        if not isinstance(timeout, int) or timeout <= 0:
            errors.append(f"check {check_id} timeout_seconds must be a positive integer")

    scenarios = _as_list(matrix.get("scenarios"))
    scenario_ids = [str(item.get("id") or "") for item in scenarios if isinstance(item, dict)]
    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("matrix.scenarios contains duplicate scenario ids")
    if not scenarios:
        errors.append("matrix.scenarios must not be empty")

    scenario_id_set = set(scenario_ids)
    missing_scenarios = sorted(REQUIRED_SCENARIOS - scenario_id_set)
    if missing_scenarios:
        errors.append(f"matrix.scenarios missing required scenarios: {', '.join(missing_scenarios)}")

    privilege_modes = {
        str(item.get("privilege_mode") or "")
        for item in scenarios
        if isinstance(item, dict)
    }
    missing_privileges = sorted(REQUIRED_PRIVILEGE_MODES - privilege_modes)
    if missing_privileges:
        errors.append(f"matrix.scenarios missing privilege modes: {', '.join(missing_privileges)}")

    for scenario in scenarios:
        if not isinstance(scenario, dict):
            errors.append("matrix.scenarios entries must be objects")
            continue
        scenario_id = str(scenario.get("id") or "")
        privilege_mode = str(scenario.get("privilege_mode") or "")
        env = _as_dict(scenario.get("env"))
        check_ids_for_scenario = [str(item) for item in _as_list(scenario.get("check_ids"))]
        if scenario.get("os") != TARGET_OS:
            errors.append(f"scenario {scenario_id} os must be {TARGET_OS}")
        if scenario.get("package_manager") != TARGET_PACKAGE_MANAGER:
            errors.append(f"scenario {scenario_id} package_manager must be {TARGET_PACKAGE_MANAGER}")
        if not check_ids_for_scenario:
            errors.append(f"scenario {scenario_id} must reference at least one check")
        unknown_checks = sorted(set(check_ids_for_scenario) - set(check_lookup))
        if unknown_checks:
            errors.append(f"scenario {scenario_id} references unknown checks: {', '.join(unknown_checks)}")
        if "QA_PORTAL_SUDO_PASSWORD" in env:
            errors.append(f"scenario {scenario_id} must use SCANFORGE_SUDO_PASSWORD, not QA_PORTAL_SUDO_PASSWORD")
        if privilege_mode == "sudo-password" and not env.get("SCANFORGE_SUDO_PASSWORD"):
            errors.append(f"scenario {scenario_id} must define SCANFORGE_SUDO_PASSWORD marker")
        if privilege_mode in INSTALL_CAPABLE_PRIVILEGES:
            missing_checks = sorted(INSTALL_CAPABLE_CHECKS - set(check_ids_for_scenario))
            if missing_checks:
                errors.append(f"scenario {scenario_id} missing install-capable checks: {', '.join(missing_checks)}")
            if env.get("QA_PORTAL_AUTH_AUTO_SETUP") != "1":
                errors.append(f"scenario {scenario_id} must enable QA_PORTAL_AUTH_AUTO_SETUP")
        if privilege_mode == "no-privilege":
            if scenario.get("expected_install_result") != "blocked-by-preflight":
                errors.append(f"scenario {scenario_id} must expect blocked-by-preflight")
            if "setup-scanforge" in check_ids_for_scenario:
                errors.append(f"scenario {scenario_id} must not run setup-scanforge")
            if "tool-install-preflight" not in check_ids_for_scenario:
                errors.append(f"scenario {scenario_id} must include tool-install-preflight")

    return errors


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def collect_host_facts(*, privilege_mode: str = "not-run") -> dict[str, Any]:
    os_release = _read_os_release()
    os_id = os_release.get("ID", "")
    version_id = os_release.get("VERSION_ID", "")
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "package_manager": "apt" if shutil.which("apt-get") else "unknown",
        "privilege_mode": privilege_mode,
        "os_release_id": os_id or "unknown",
        "os_release_version_id": version_id or "unknown",
        "is_target_ubuntu_2204": os_id == "ubuntu" and version_id == "22.04",
    }


def build_validation_report_template(
    matrix: dict[str, Any],
    *,
    host: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    check_lookup = {
        str(item["id"]): item
        for item in _as_list(matrix.get("check_catalog"))
        if isinstance(item, dict) and item.get("id")
    }
    generated_at = generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    host = host or collect_host_facts()
    scenarios: list[dict[str, Any]] = []
    check_count = 0

    for scenario in _as_list(matrix.get("scenarios")):
        if not isinstance(scenario, dict):
            continue
        checks = []
        for check_id in [str(item) for item in _as_list(scenario.get("check_ids"))]:
            check = check_lookup.get(check_id, {})
            checks.append(
                {
                    "id": check_id,
                    "command": str(check.get("command") or ""),
                    "status": "not-run",
                    "exit_code": None,
                    "duration_seconds": None,
                    "log_path": "",
                    "artifacts": [],
                    "message": "",
                }
            )
            check_count += 1
        scenarios.append(
            {
                "id": str(scenario.get("id") or ""),
                "privilege_mode": str(scenario.get("privilege_mode") or ""),
                "expected_install_result": str(scenario.get("expected_install_result") or ""),
                "status": "not-run",
                "checks": checks,
            }
        )

    return {
        "schema_version": 1,
        "matrix_schema_version": matrix.get("schema_version"),
        "target_os": matrix.get("target_os"),
        "generated_at": generated_at,
        "host": host,
        "summary": {
            "scenario_count": len(scenarios),
            "check_count": check_count,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "blocked": 0,
            "not_run": check_count,
        },
        "scenarios": scenarios,
    }


def _report_has_runtime_results(report: dict[str, Any]) -> bool:
    return any(
        isinstance(check, dict) and str(check.get("status") or "") in RUNTIME_RESULT_STATUSES
        for scenario in _as_list(report.get("scenarios"))
        if isinstance(scenario, dict)
        for check in _as_list(scenario.get("checks"))
    )


def _scenario_status_from_checks(checks: list[dict[str, Any]]) -> str:
    statuses = [str(check.get("status") or "not-run") for check in checks]
    if not statuses:
        return "not-run"
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if all(status == "passed" for status in statuses):
        return "passed"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    if all(status == "not-run" for status in statuses):
        return "not-run"
    if any(status == "passed" for status in statuses):
        return "passed"
    return statuses[0]


def _update_report_summary(report: dict[str, Any]) -> None:
    status_counts = {status: 0 for status in VALID_RESULT_STATUSES}
    check_count = 0
    scenarios = _as_list(report.get("scenarios"))
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        checks = [check for check in _as_list(scenario.get("checks")) if isinstance(check, dict)]
        scenario["status"] = _scenario_status_from_checks(checks)
        for check in checks:
            status = str(check.get("status") or "not-run")
            if status in status_counts:
                status_counts[status] += 1
            check_count += 1
    report["summary"] = {
        "scenario_count": len([item for item in scenarios if isinstance(item, dict)]),
        "check_count": check_count,
        "passed": status_counts["passed"],
        "failed": status_counts["failed"],
        "skipped": status_counts["skipped"],
        "blocked": status_counts["blocked"],
        "not_run": status_counts["not-run"],
    }


def validate_validation_report(
    report: dict[str, Any],
    matrix: dict[str, Any],
    *,
    require_completed: bool = False,
) -> list[str]:
    errors: list[str] = []
    matrix_errors = validate_matrix(matrix)
    if matrix_errors:
        errors.extend(f"matrix: {item}" for item in matrix_errors)
        return errors

    if report.get("schema_version") != 1:
        errors.append("report.schema_version must be 1")
    if report.get("matrix_schema_version") != matrix.get("schema_version"):
        errors.append("report.matrix_schema_version must match matrix.schema_version")
    if report.get("target_os") != matrix.get("target_os"):
        errors.append("report.target_os must match matrix.target_os")
    if not str(report.get("generated_at") or "").strip():
        errors.append("report.generated_at must not be empty")

    host = _as_dict(report.get("host"))
    for key in ("hostname", "kernel", "python", "package_manager", "privilege_mode"):
        if not str(host.get(key) or "").strip():
            errors.append(f"report.host.{key} must not be empty")
    if _report_has_runtime_results(report):
        if host.get("is_target_ubuntu_2204") is not True:
            errors.append("report.host.is_target_ubuntu_2204 must be true for executed checks")
        if host.get("package_manager") != TARGET_PACKAGE_MANAGER:
            errors.append(f"report.host.package_manager must be {TARGET_PACKAGE_MANAGER} for executed checks")

    scenario_lookup = {
        str(item["id"]): item
        for item in _as_list(matrix.get("scenarios"))
        if isinstance(item, dict) and item.get("id")
    }
    check_lookup = {
        str(item["id"]): item
        for item in _as_list(matrix.get("check_catalog"))
        if isinstance(item, dict) and item.get("id")
    }
    report_scenarios = _as_list(report.get("scenarios"))
    report_scenario_ids = {
        str(item.get("id") or "")
        for item in report_scenarios
        if isinstance(item, dict)
    }
    if report_scenario_ids != set(scenario_lookup):
        missing = sorted(set(scenario_lookup) - report_scenario_ids)
        extra = sorted(report_scenario_ids - set(scenario_lookup))
        if missing:
            errors.append(f"report.scenarios missing scenarios: {', '.join(missing)}")
        if extra:
            errors.append(f"report.scenarios has unknown scenarios: {', '.join(extra)}")

    status_counts = {status: 0 for status in VALID_RESULT_STATUSES}
    check_count = 0
    for scenario_report in report_scenarios:
        if not isinstance(scenario_report, dict):
            errors.append("report.scenarios entries must be objects")
            continue
        scenario_id = str(scenario_report.get("id") or "")
        matrix_scenario = scenario_lookup.get(scenario_id)
        if not matrix_scenario:
            continue
        scenario_status = str(scenario_report.get("status") or "")
        if scenario_status not in VALID_RESULT_STATUSES:
            errors.append(f"scenario {scenario_id} has invalid status {scenario_status!r}")
        expected_check_ids = [str(item) for item in _as_list(matrix_scenario.get("check_ids"))]
        checks = _as_list(scenario_report.get("checks"))
        check_objects = [item for item in checks if isinstance(item, dict)]
        expected_scenario_status = _scenario_status_from_checks(check_objects)
        if scenario_status != expected_scenario_status:
            errors.append(f"scenario {scenario_id} status must be {expected_scenario_status}")
        actual_check_ids = [
            str(item.get("id") or "")
            for item in check_objects
        ]
        if actual_check_ids != expected_check_ids:
            errors.append(f"scenario {scenario_id} checks must match matrix order")
        for check_report in checks:
            if not isinstance(check_report, dict):
                errors.append(f"scenario {scenario_id} check entries must be objects")
                continue
            check_id = str(check_report.get("id") or "")
            matrix_check = check_lookup.get(check_id, {})
            if str(check_report.get("command") or "") != str(matrix_check.get("command") or ""):
                errors.append(f"scenario {scenario_id} check {check_id} command must match matrix")
            check_status = str(check_report.get("status") or "")
            if check_status not in VALID_RESULT_STATUSES:
                errors.append(f"scenario {scenario_id} check {check_id} has invalid status {check_status!r}")
            else:
                status_counts[check_status] += 1
            exit_code = check_report.get("exit_code")
            if exit_code is not None and not isinstance(exit_code, int):
                errors.append(f"scenario {scenario_id} check {check_id} exit_code must be integer or null")
            if check_status == "passed" and exit_code != 0:
                errors.append(f"scenario {scenario_id} check {check_id} passed checks must have exit_code 0")
            if check_status == "failed" and (exit_code is None or exit_code == 0):
                errors.append(f"scenario {scenario_id} check {check_id} failed checks must have non-zero exit_code")
            if check_status == "not-run" and exit_code is not None:
                errors.append(f"scenario {scenario_id} check {check_id} not-run checks must have null exit_code")
            if check_status in {"blocked", "skipped"} and exit_code is not None:
                errors.append(f"scenario {scenario_id} check {check_id} {check_status} checks must have null exit_code")
            duration = check_report.get("duration_seconds")
            if duration is not None and (
                not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0
            ):
                errors.append(f"scenario {scenario_id} check {check_id} duration_seconds must be non-negative or null")
            log_path = check_report.get("log_path", "")
            if not isinstance(log_path, str):
                errors.append(f"scenario {scenario_id} check {check_id} log_path must be a string")
            if check_status in RUNTIME_RESULT_STATUSES and not str(log_path).strip():
                errors.append(f"scenario {scenario_id} check {check_id} executed checks must include log_path")
            artifacts = check_report.get("artifacts", [])
            if not isinstance(artifacts, list) or any(not isinstance(item, str) for item in artifacts):
                errors.append(f"scenario {scenario_id} check {check_id} artifacts must be a list of strings")
            message = check_report.get("message", "")
            if not isinstance(message, str):
                errors.append(f"scenario {scenario_id} check {check_id} message must be a string")
            if check_status in {"failed", "blocked"} and not str(message).strip():
                errors.append(f"scenario {scenario_id} check {check_id} {check_status} checks must include message")
            check_count += 1

    summary = _as_dict(report.get("summary"))
    expected_summary = {
        "scenario_count": len(scenario_lookup),
        "check_count": check_count,
        "passed": status_counts["passed"],
        "failed": status_counts["failed"],
        "skipped": status_counts["skipped"],
        "blocked": status_counts["blocked"],
        "not_run": status_counts["not-run"],
    }
    for key, expected_value in expected_summary.items():
        if summary.get(key) != expected_value:
            errors.append(f"report.summary.{key} must be {expected_value}")
    if require_completed and expected_summary["not_run"] > 0:
        errors.append("report must not contain not-run checks when require_completed is enabled")

    return errors


def release_validation_status(
    *,
    report_path: Path = DEFAULT_REPORT_PATH,
    matrix_path: Path = DEFAULT_MATRIX_PATH,
) -> dict[str, Any]:
    matrix = load_matrix(matrix_path)
    if not report_path.exists():
        return {
            "ready": False,
            "report_path": str(report_path),
            "exists": False,
            "errors": ["validation report is missing"],
        }
    report = read_json_file(report_path)
    errors = validate_validation_report(report, matrix, require_completed=True)
    summary = _as_dict(report.get("summary"))
    for key in ("failed", "blocked", "skipped", "not_run"):
        if int(summary.get(key, 0) or 0) > 0:
            errors.append(f"report.summary.{key} must be 0 for release readiness")
    return {
        "ready": not errors,
        "report_path": str(report_path),
        "exists": True,
        "errors": errors,
        "summary": summary,
        "target_os": report.get("target_os"),
        "generated_at": report.get("generated_at"),
    }


def _safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value.strip())
    return cleaned.strip("-") or "item"


def _resolve_scenario_env(scenario: dict[str, Any], base_env: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    env = dict(base_env)
    missing: list[str] = []
    for key, value in _as_dict(scenario.get("env")).items():
        env_key = str(key)
        env_value = str(value)
        if env_value == "provided-by-operator":
            provided = base_env.get(env_key, "")
            if not provided:
                missing.append(env_key)
                continue
            env[env_key] = provided
        else:
            env[env_key] = env_value
    return env, missing


def _blocked_check(check_id: str, command: str, message: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "command": command,
        "status": "blocked",
        "exit_code": None,
        "duration_seconds": 0.0,
        "log_path": "",
        "artifacts": [],
        "message": message,
    }


def _skipped_check(check_id: str, command: str, message: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "command": command,
        "status": "skipped",
        "exit_code": None,
        "duration_seconds": 0.0,
        "log_path": "",
        "artifacts": [],
        "message": message,
    }


def _write_check_log(
    log_dir: Path,
    *,
    scenario_id: str,
    check_id: str,
    command: str,
    completed: subprocess.CompletedProcess[str] | None,
    error: str = "",
) -> str:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{_safe_name(scenario_id)}__{_safe_name(check_id)}.log"
    lines = [f"$ {command}", ""]
    if completed is not None:
        lines.extend(
            [
                f"exit_code={completed.returncode}",
                "",
                "[stdout]",
                completed.stdout or "",
                "",
                "[stderr]",
                completed.stderr or "",
            ]
        )
    if error:
        lines.extend(["", "[error]", error])
    log_path.write_text("\n".join(lines), encoding="utf-8")
    try:
        return log_path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return log_path.as_posix()


def _run_shell_command(
    command: str,
    *,
    env: dict[str, str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def run_validation_matrix(
    matrix: dict[str, Any],
    *,
    output_path: Path = DEFAULT_REPORT_PATH,
    log_dir: Path = DEFAULT_LOG_DIR,
    scenario_ids: set[str] | None = None,
    stop_on_failure: bool = False,
    host: dict[str, Any] | None = None,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = _run_shell_command,
) -> dict[str, Any]:
    errors = validate_matrix(matrix)
    if errors:
        raise ValueError("; ".join(errors))

    host = host or collect_host_facts()
    report = build_validation_report_template(matrix, host=host)
    check_lookup = {
        str(item["id"]): item
        for item in _as_list(matrix.get("check_catalog"))
        if isinstance(item, dict) and item.get("id")
    }
    scenario_lookup = {
        str(item["id"]): item
        for item in _as_list(matrix.get("scenarios"))
        if isinstance(item, dict) and item.get("id")
    }
    if scenario_ids is not None:
        unknown_scenarios = sorted(scenario_ids - set(scenario_lookup))
        if unknown_scenarios:
            raise ValueError("Unknown scenario ids: " + ", ".join(unknown_scenarios))

    block_message = ""
    if host.get("is_target_ubuntu_2204") is not True:
        block_message = "Blocked: validation runner must be executed on Ubuntu 22.04."
    elif host.get("package_manager") != TARGET_PACKAGE_MANAGER:
        block_message = "Blocked: validation runner requires apt package manager."

    should_stop = False
    base_env = {str(key): str(value) for key, value in os.environ.items()}
    for scenario_report in _as_list(report.get("scenarios")):
        if not isinstance(scenario_report, dict):
            continue
        scenario_id = str(scenario_report.get("id") or "")
        matrix_scenario = scenario_lookup.get(scenario_id, {})
        if scenario_ids is not None and scenario_id not in scenario_ids:
            scenario_report["checks"] = [
                _skipped_check(
                    str(check.get("id") or ""),
                    str(check.get("command") or ""),
                    "Skipped by scenario filter.",
                )
                for check in _as_list(scenario_report.get("checks"))
                if isinstance(check, dict)
            ]
            continue

        scenario_env, missing_env = _resolve_scenario_env(matrix_scenario, base_env)
        scenario_block_message = block_message
        if missing_env:
            scenario_block_message = "Blocked: missing required operator-provided environment variables: " + ", ".join(
                sorted(missing_env)
            )

        if scenario_block_message:
            scenario_report["checks"] = [
                _blocked_check(
                    str(check.get("id") or ""),
                    str(check.get("command") or ""),
                    scenario_block_message,
                )
                for check in _as_list(scenario_report.get("checks"))
                if isinstance(check, dict)
            ]
            continue

        updated_checks: list[dict[str, Any]] = []
        for check_report in _as_list(scenario_report.get("checks")):
            if not isinstance(check_report, dict):
                continue
            check_id = str(check_report.get("id") or "")
            matrix_check = check_lookup.get(check_id, {})
            command = str(matrix_check.get("command") or check_report.get("command") or "")
            timeout_seconds = int(matrix_check.get("timeout_seconds") or DEFAULT_CHECK_TIMEOUT_SECONDS)
            if should_stop:
                updated_checks.append(_blocked_check(check_id, command, "Blocked: stop-on-failure already triggered."))
                continue
            started = time.monotonic()
            try:
                completed = command_runner(command, env=scenario_env, timeout_seconds=timeout_seconds)
                duration = round(time.monotonic() - started, 3)
                status = "passed" if completed.returncode == 0 else "failed"
                log_path = _write_check_log(
                    log_dir,
                    scenario_id=scenario_id,
                    check_id=check_id,
                    command=command,
                    completed=completed,
                )
                check_result = {
                    "id": check_id,
                    "command": command,
                    "status": status,
                    "exit_code": completed.returncode,
                    "duration_seconds": duration,
                    "log_path": log_path,
                    "artifacts": [],
                    "message": "Command completed." if status == "passed" else "Command failed.",
                }
                if status == "failed" and stop_on_failure:
                    should_stop = True
            except subprocess.TimeoutExpired as exc:
                duration = round(time.monotonic() - started, 3)
                log_path = _write_check_log(
                    log_dir,
                    scenario_id=scenario_id,
                    check_id=check_id,
                    command=command,
                    completed=None,
                    error=f"Timed out after {timeout_seconds} seconds: {exc}",
                )
                check_result = {
                    "id": check_id,
                    "command": command,
                    "status": "failed",
                    "exit_code": 124,
                    "duration_seconds": duration,
                    "log_path": log_path,
                    "artifacts": [],
                    "message": f"Timed out after {timeout_seconds} seconds.",
                }
                if stop_on_failure:
                    should_stop = True
            updated_checks.append(check_result)
        scenario_report["checks"] = updated_checks

    _update_report_summary(report)
    write_json_file(output_path, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate ScanForge Ubuntu 22.04 release matrix artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_matrix_parser = subparsers.add_parser("validate-matrix", help="Validate the Ubuntu 22.04 matrix JSON.")
    validate_matrix_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH)

    template_parser = subparsers.add_parser("write-report-template", help="Write a not-run validation report template.")
    template_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH)
    template_parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH)

    validate_report_parser = subparsers.add_parser("validate-report", help="Validate a completed validation report JSON.")
    validate_report_parser.add_argument("report", type=Path)
    validate_report_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH)
    validate_report_parser.add_argument("--require-completed", action="store_true")

    run_parser = subparsers.add_parser("run-matrix", help="Run the Ubuntu 22.04 matrix on the current host.")
    run_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH)
    run_parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH)
    run_parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    run_parser.add_argument("--scenario", action="append", default=[])
    run_parser.add_argument("--stop-on-failure", action="store_true")

    release_parser = subparsers.add_parser("check-release", help="Check that the Ubuntu validation report is release-ready.")
    release_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH)
    release_parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)

    args = parser.parse_args(argv)
    matrix = load_matrix(args.matrix)

    if args.command == "validate-matrix":
        errors = validate_matrix(matrix)
        if errors:
            for error in errors:
                print(error)
            return 1
        print("Ubuntu 22.04 validation matrix OK")
        return 0

    if args.command == "write-report-template":
        errors = validate_matrix(matrix)
        if errors:
            for error in errors:
                print(error)
            return 1
        report = build_validation_report_template(matrix)
        write_json_file(args.output, report)
        print(args.output)
        return 0

    if args.command == "validate-report":
        report = read_json_file(args.report)
        errors = validate_validation_report(report, matrix, require_completed=args.require_completed)
        if errors:
            for error in errors:
                print(error)
            return 1
        print("Ubuntu 22.04 validation report OK")
        return 0

    if args.command == "run-matrix":
        errors = validate_matrix(matrix)
        if errors:
            for error in errors:
                print(error)
            return 1
        try:
            report = run_validation_matrix(
                matrix,
                output_path=args.output,
                log_dir=args.log_dir,
                scenario_ids=set(args.scenario) if args.scenario else None,
                stop_on_failure=args.stop_on_failure,
            )
        except ValueError as exc:
            print(exc)
            return 1
        report_errors = validate_validation_report(report, matrix, require_completed=True)
        if report_errors:
            for error in report_errors:
                print(error)
            return 1
        print(args.output)
        return 1 if report["summary"]["failed"] or report["summary"]["blocked"] else 0

    if args.command == "check-release":
        status = release_validation_status(report_path=args.report, matrix_path=args.matrix)
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return 0 if status["ready"] else 1

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
