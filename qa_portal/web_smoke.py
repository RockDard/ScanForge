from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx


# Корень проекта нужен для запуска uvicorn и worker в одном временном data-dir.
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def _python_bin(root: Path) -> str:
    candidate = root / ".venv" / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    return sys.executable


def _base_env(root: Path, data_dir: Path, port: int) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{root}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else str(root)
    env["QA_PORTAL_DATA_DIR"] = str(data_dir)
    env["QA_PORTAL_HOST"] = "127.0.0.1"
    env["QA_PORTAL_PORT"] = str(port)
    env["QA_PORTAL_RELOAD"] = "0"
    env["QA_PORTAL_AUTOSTART_WORKER"] = "0"
    return env


def _wait_for_health(base_url: str, timeout_seconds: float = 30.0) -> None:
    deadline = time.time() + timeout_seconds
    with httpx.Client(timeout=3.0) as client:
        while time.time() < deadline:
            try:
                response = client.get(f"{base_url}/health")
                if response.status_code == 200 and response.json().get("status") == "ok":
                    return
            except Exception:
                pass
            time.sleep(0.5)
    raise RuntimeError(f"Smoke server did not become healthy at {base_url}.")


def _run_worker_once(root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_python_bin(root), "-m", "qa_portal.worker", "once"],
        cwd=str(root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _extract_job_id(location: str) -> str:
    match = re.search(r"/jobs/([A-Za-z0-9_-]+)", location)
    if not match:
        raise RuntimeError(f"Could not extract job id from redirect location: {location}")
    return match.group(1)


def _poll_job_completion(base_url: str, job_id: str, timeout_seconds: float = 40.0) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    with httpx.Client(timeout=5.0) as client:
        while time.time() < deadline:
            response = client.get(f"{base_url}/api/jobs/{job_id}")
            response.raise_for_status()
            payload = response.json()
            if payload.get("status") in {"completed", "failed", "cancelled"}:
                return payload
            time.sleep(0.5)
    raise RuntimeError(f"Job {job_id} did not finish within {timeout_seconds} seconds.")


# Smoke-путь специально покрывает реальные HTTP-маршруты, upload, worker и report redirect.
def run_web_smoke(existing_url: str | None = None) -> list[str]:
    root = project_root()
    logs: list[str] = []
    temp_dir_cm = tempfile.TemporaryDirectory(prefix="scanforge-web-smoke-")
    temp_dir = Path(temp_dir_cm.name)
    data_dir = temp_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    base_url = existing_url.rstrip("/") if existing_url else f"http://127.0.0.1:{port}"
    env = _base_env(root, data_dir, port)
    server_process: subprocess.Popen[str] | None = None

    try:
        if not existing_url:
            command = [
                _python_bin(root),
                "-m",
                "uvicorn",
                "qa_portal.app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ]
            server_process = subprocess.Popen(
                command,
                cwd=str(root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            logs.append(f"Started smoke server on {base_url}.")
            _wait_for_health(base_url)

        with httpx.Client(base_url=base_url, follow_redirects=False, timeout=10.0) as client:
            response = client.get("/")
            response.raise_for_status()
            if "ScanForge" not in response.text:
                raise RuntimeError("Dashboard smoke check did not render ScanForge branding.")
            logs.append("Dashboard rendered successfully.")

            response = client.get("/settings")
            response.raise_for_status()
            if "Environment diagnostics" not in response.text:
                raise RuntimeError("Settings smoke check did not render environment diagnostics.")
            logs.append("Settings page rendered successfully.")

            response = client.get("/?lang=ru")
            response.raise_for_status()
            if "Создать задачу" not in response.text:
                raise RuntimeError("Russian localization smoke check failed.")
            logs.append("Russian localization rendered successfully.")

            upload_response = client.post(
                "/jobs",
                data={
                    "name": "Smoke run",
                    "mode": "full_scan",
                    "preset": "balanced",
                },
                files={"upload": ("widget.cpp", b"int main() { return 0; }\n", "text/plain")},
            )
            if upload_response.status_code != 303:
                raise RuntimeError(f"Upload smoke check failed with status {upload_response.status_code}.")
            job_location = upload_response.headers.get("location", "")
            job_id = _extract_job_id(job_location)
            logs.append(f"Created smoke job {job_id}.")

        worker_result = _run_worker_once(root, env)
        if worker_result.returncode != 0:
            raise RuntimeError(
                "Worker smoke step failed.\n"
                + worker_result.stdout
                + "\n"
                + worker_result.stderr
            )
        logs.append("Worker processed the queued smoke job.")

        payload = _poll_job_completion(base_url, job_id)
        if payload.get("status") != "completed":
            raise RuntimeError(f"Smoke job finished with unexpected status: {payload.get('status')}")
        logs.append("Smoke job completed successfully.")

        with httpx.Client(base_url=base_url, follow_redirects=False, timeout=10.0) as client:
            response = client.get(f"/jobs/{job_id}")
            response.raise_for_status()
            if "Smoke run" not in response.text:
                raise RuntimeError("Job detail page did not render the smoke job.")
            logs.append("Job detail page rendered successfully.")

            response = client.get(f"/jobs/{job_id}/report")
            if response.status_code != 303:
                raise RuntimeError(f"Report redirect smoke check failed with status {response.status_code}.")
            artifact_url = response.headers.get("location", "")
            if not artifact_url:
                raise RuntimeError("Report redirect did not provide an artifact location.")

            report_response = client.get(artifact_url)
            report_response.raise_for_status()
            if "ScanForge Report" not in report_response.text and "Smoke run" not in report_response.text:
                raise RuntimeError("HTML report smoke check did not render expected content.")
            logs.append("HTML report rendered successfully.")

        return logs
    finally:
        if server_process is not None:
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
        temp_dir_cm.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the optional ScanForge web smoke stage.")
    parser.add_argument("--existing-url", default="", help="Reuse an already running ScanForge instance instead of spawning a temp server.")
    args = parser.parse_args(argv)

    try:
        logs = run_web_smoke(args.existing_url or None)
    except Exception as exc:
        print(f"Web smoke failed: {exc}")
        return 1

    for line in logs:
        print(line)
    print("Web smoke passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
