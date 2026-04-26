from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPException
import json
import socket
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


RUNTIME_SIGNATURE_SUFFIXES = {".py", ".html", ".css", ".js", ".svg"}


# Корень проекта нужен helper-утилите для расчета текущей сигнатуры веб-рантайма.
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


# В сигнатуру рантайма включаем только файлы, которые влияют на веб-интерфейс и API.
def iter_runtime_signature_files(root: Path | None = None) -> list[Path]:
    base = root or project_root()
    app_root = base / "qa_portal"
    files = [
        path
        for path in app_root.rglob("*")
        if path.is_file() and path.suffix.lower() in RUNTIME_SIGNATURE_SUFFIXES
    ]
    return sorted(files)


# Сигнатура позволяет понять, совместим ли уже работающий экземпляр с кодом на диске.
def compute_runtime_signature(root: Path | None = None) -> str:
    base = root or project_root()
    digest = hashlib.sha256()
    for path in iter_runtime_signature_files(base):
        relative = path.relative_to(base).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
        digest.update(b"\0")
    return digest.hexdigest()[:16]


CURRENT_RUNTIME_SIGNATURE = compute_runtime_signature()


# Приводим адрес к локально проверяемому виду для healthcheck и проверки занятости порта.
def probe_host(host: str) -> str:
    normalized = (host or "").strip()
    if normalized in {"", "0.0.0.0", "::", "::0", "[::]"}:
        return "127.0.0.1"
    if normalized == "localhost":
        return "127.0.0.1"
    return normalized


def endpoint_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def browser_host(host: str) -> str:
    normalized = (host or "").strip()
    if normalized in {"", "0.0.0.0", "::", "::0", "[::]"}:
        return "127.0.0.1"
    return normalized


def browser_url(host: str, port: int) -> str:
    return endpoint_url(browser_host(host), port)


def healthcheck(host: str, port: int, timeout: float = 2.0) -> bool:
    url = endpoint_url(probe_host(host), port) + "/health"
    try:
        with urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, HTTPError, URLError, HTTPException):
        return False
    return payload.get("status") == "ok"


def port_in_use(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((probe_host(host), port), timeout=timeout):
            return True
    except OSError:
        return False


def runtime_metadata(host: str, port: int, timeout: float = 2.0) -> dict[str, Any] | None:
    url = endpoint_url(probe_host(host), port) + "/api/runtime"
    try:
        with urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, HTTPError, URLError, HTTPException):
        return None
    return payload if isinstance(payload, dict) else None


# Совместимым считаем только экземпляр с такой же сигнатурой рантайма, как у текущего кода.
def compatibilitycheck(host: str, port: int, timeout: float = 2.0) -> bool:
    payload = runtime_metadata(host, port, timeout=timeout)
    if not payload:
        return False
    return (
        str(payload.get("name", "")) == "ScanForge"
        and str(payload.get("runtime_signature", "")) == CURRENT_RUNTIME_SIGNATURE
    )


def _candidate_ports(desired_port: str, range_start: int, range_end: int) -> tuple[int | None, list[int]]:
    preferred: int | None = None
    if desired_port.strip().isdigit():
        preferred = int(desired_port.strip())
    fallback_ports = list(range(range_start, range_end + 1))
    if preferred is None:
        return None, fallback_ports
    ordered = [preferred]
    ordered.extend(port for port in fallback_ports if port != preferred)
    return preferred, ordered


# Выбираем рабочий endpoint: либо уже живой ScanForge, либо свободный порт для нового запуска.
def choose_endpoint(
    host: str,
    desired_port: str,
    *,
    range_start: int = 8000,
    range_end: int = 8100,
) -> dict[str, Any]:
    preferred, candidates = _candidate_ports(desired_port, range_start, range_end)
    preferred_occupied_by_foreign = False
    preferred_occupied_by_incompatible = False

    for candidate in candidates:
        if healthcheck(host, candidate):
            if not compatibilitycheck(host, candidate):
                if preferred is not None and candidate == preferred:
                    preferred_occupied_by_incompatible = True
                continue
            status = "scanforge-running"
            url = browser_url(host, candidate)
            message = f"ScanForge is already responding on {url}."
            if preferred is not None and candidate != preferred:
                status = "fallback-running-scanforge"
            return {
                "host": host,
                "port": candidate,
                "url": url,
                "status": status,
                "message": message,
            }
        if preferred is not None and candidate == preferred and port_in_use(host, candidate):
            preferred_occupied_by_foreign = True

    for candidate in candidates:
        if not port_in_use(host, candidate):
            status = "preferred-free" if preferred is not None and candidate == preferred else "fallback-free"
            url = browser_url(host, candidate)
            message = f"Selected free port {candidate}."
            if preferred is not None and preferred_occupied_by_foreign and candidate != preferred:
                status = "preferred-occupied-foreign"
                message = f"Preferred port {preferred} is occupied by a foreign service; falling back to {candidate}."
            if preferred is not None and preferred_occupied_by_incompatible and candidate != preferred:
                status = "preferred-occupied-incompatible"
                message = (
                    f"Preferred port {preferred} is occupied by an incompatible ScanForge instance; "
                    f"falling back to {candidate}."
                )
            return {
                "host": host,
                "port": candidate,
                "url": url,
                "status": status,
                "message": message,
            }

    raise RuntimeError(
        f"No free ScanForge port found in range {range_start}-{range_end} for host {host}."
    )


def load_endpoint_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        payload[key.strip()] = value.strip()
    host = payload.get("QA_PORTAL_HOST")
    port = payload.get("QA_PORTAL_PORT")
    url = payload.get("SCANFORGE_URL")
    if not host or not port or not port.isdigit():
        return None
    return {
        "host": host,
        "port": int(port),
        "url": url or endpoint_url(host, int(port)),
    }


def save_endpoint_state(path: Path, host: str, port: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    url = browser_url(host, port)
    path.write_text(
        "\n".join(
            [
                f"QA_PORTAL_HOST={host}",
                f"QA_PORTAL_PORT={port}",
                f"SCANFORGE_URL={url}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o644)
    return path


def _shell_quote(value: Any) -> str:
    text = str(value)
    return "'" + text.replace("'", "'\"'\"'") + "'"


def _print_shell(payload: dict[str, Any]) -> None:
    mapping = {
        "SCANFORGE_HOST": payload["host"],
        "SCANFORGE_PORT": payload["port"],
        "SCANFORGE_URL": payload["url"],
        "SCANFORGE_PICK_STATUS": payload.get("status", ""),
        "SCANFORGE_PICK_MESSAGE": payload.get("message", ""),
    }
    for key, value in mapping.items():
        print(f"{key}={_shell_quote(value)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ScanForge runtime helper.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    health_parser = subparsers.add_parser("healthcheck", help="Probe a ScanForge /health endpoint.")
    health_parser.add_argument("--host", required=True)
    health_parser.add_argument("--port", type=int, required=True)

    compat_parser = subparsers.add_parser("compatibilitycheck", help="Verify that a running ScanForge matches the current code.")
    compat_parser.add_argument("--host", required=True)
    compat_parser.add_argument("--port", type=int, required=True)

    pick_parser = subparsers.add_parser("pick-port", help="Select a usable port for ScanForge.")
    pick_parser.add_argument("--host", required=True)
    pick_parser.add_argument("--desired-port", required=True)
    pick_parser.add_argument("--range-start", type=int, default=8000)
    pick_parser.add_argument("--range-end", type=int, default=8100)
    pick_parser.add_argument("--format", choices=("json", "shell"), default="shell")

    state_show = subparsers.add_parser("read-state", help="Read endpoint.env and print its content.")
    state_show.add_argument("--path", required=True)
    state_show.add_argument("--format", choices=("json", "shell"), default="json")

    state_write = subparsers.add_parser("write-state", help="Write endpoint.env.")
    state_write.add_argument("--path", required=True)
    state_write.add_argument("--host", required=True)
    state_write.add_argument("--port", type=int, required=True)

    args = parser.parse_args(argv)

    if args.command == "healthcheck":
        return 0 if healthcheck(args.host, args.port) else 1

    if args.command == "compatibilitycheck":
        return 0 if compatibilitycheck(args.host, args.port) else 1

    if args.command == "pick-port":
        payload = choose_endpoint(
            args.host,
            args.desired_port,
            range_start=args.range_start,
            range_end=args.range_end,
        )
        if args.format == "json":
            print(json.dumps(payload, ensure_ascii=False))
        else:
            _print_shell(payload)
        return 0

    if args.command == "read-state":
        payload = load_endpoint_state(Path(args.path))
        if payload is None:
            return 1
        if args.format == "json":
            print(json.dumps(payload, ensure_ascii=False))
        else:
            _print_shell(payload)
        return 0

    if args.command == "write-state":
        save_endpoint_state(Path(args.path), args.host, args.port)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
