from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import Request

try:
    from fastapi.responses import Response
except ModuleNotFoundError:  # pragma: no cover - allows bootstrap CLI before web deps are installed
    class Response:  # type: ignore[no-redef]
        def __init__(self, body: str = "", status_code: int = 200, headers: dict[str, str] | None = None) -> None:
            self.body = body
            self.status_code = status_code
            self.headers = headers or {}

from .config import SETTINGS_DIR


PUBLIC_PREFIXES = ("/static/",)
PUBLIC_PATHS = {"/health", "/api/runtime"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_BOOTSTRAP_PATH = SETTINGS_DIR / "auth_bootstrap.json"
NETWORK_BIND_HOSTS = {"0.0.0.0", "::", "::0", "[::]"}


@dataclass(frozen=True)
class AuthContext:
    enabled: bool
    username: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _network_bind_requested() -> bool:
    raw_host = os.environ.get("QA_PORTAL_HOST")
    if raw_host is None:
        return False
    host = raw_host.strip().casefold()
    if not host:
        return False
    if host in NETWORK_BIND_HOSTS:
        return True
    if host in {"localhost", "127.0.0.1", "::1", "[::1]"}:
        return False
    return not host.startswith("127.")


def _auto_setup_enabled() -> bool:
    return _env_bool("QA_PORTAL_AUTH_AUTO_SETUP", True)


def _bootstrap_allowed() -> bool:
    return _env_bool("QA_PORTAL_AUTH_BOOTSTRAP", False) or (_auto_setup_enabled() and _network_bind_requested())


def auth_enabled() -> bool:
    if "QA_PORTAL_AUTH_ENABLED" in os.environ:
        return _env_bool("QA_PORTAL_AUTH_ENABLED", False)
    return _auto_setup_enabled() and _network_bind_requested()


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, dir=str(path.parent)) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _read_bootstrap_credentials() -> dict[str, str] | None:
    try:
        payload = json.loads(AUTH_BOOTSTRAP_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    username = str(payload.get("admin_user", "")).strip() or "admin"
    password = str(payload.get("admin_password", "")).strip()
    if not password:
        return None
    return {"admin_user": username, "admin_password": password}


def ensure_bootstrap_credentials() -> dict[str, str]:
    existing = _read_bootstrap_credentials()
    if existing:
        return existing
    username = os.environ.get("QA_PORTAL_ADMIN_USER", "admin").strip() or "admin"
    payload: dict[str, object] = {
        "admin_user": username,
        "admin_password": secrets.token_urlsafe(24),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "bootstrap-file",
    }
    _atomic_write_json(AUTH_BOOTSTRAP_PATH, payload)
    return {"admin_user": str(payload["admin_user"]), "admin_password": str(payload["admin_password"])}


def _admin_user() -> str:
    configured = os.environ.get("QA_PORTAL_ADMIN_USER")
    if configured is not None and configured.strip():
        return configured.strip()
    if os.environ.get("QA_PORTAL_ADMIN_PASSWORD", ""):
        return "admin"
    bootstrap_credentials = _read_bootstrap_credentials()
    if bootstrap_credentials:
        return bootstrap_credentials["admin_user"]
    return "admin"


def _admin_password() -> str:
    password = os.environ.get("QA_PORTAL_ADMIN_PASSWORD", "")
    if password:
        return password
    if auth_enabled() and _bootstrap_allowed():
        return ensure_bootstrap_credentials()["admin_password"]
    return ""


def _auth_source() -> str:
    if not auth_enabled():
        return "disabled"
    if os.environ.get("QA_PORTAL_ADMIN_PASSWORD", ""):
        return "environment"
    if _read_bootstrap_credentials():
        return "bootstrap-file"
    if _bootstrap_allowed():
        return "bootstrap-pending"
    return "missing"


def auth_status() -> dict[str, object]:
    return {
        "enabled": auth_enabled(),
        "admin_user": _admin_user(),
        "viewer_configured": bool(os.environ.get("QA_PORTAL_VIEWER_PASSWORD", "").strip()),
        "mode": "basic",
        "source": _auth_source(),
        "auto_setup_enabled": _auto_setup_enabled(),
        "bootstrap_allowed": _bootstrap_allowed(),
        "bootstrap_path": str(AUTH_BOOTSTRAP_PATH),
        "bootstrap_configured": _read_bootstrap_credentials() is not None,
        "network_bind_requested": _network_bind_requested(),
    }


def _unauthorized() -> Response:
    return Response(
        "Authentication required.",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="ScanForge"'},
    )


def _forbidden() -> Response:
    return Response("Administrator role required.", status_code=403)


def _misconfigured() -> Response:
    return Response("ScanForge authentication is enabled, but no admin password is configured.", status_code=503)


def _public_request(request: Request) -> bool:
    path = request.url.path
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


def _read_basic_credentials(header_value: str) -> tuple[str, str] | None:
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "basic" or not token.strip():
        return None
    try:
        decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    username, separator, password = decoded.partition(":")
    if not separator:
        return None
    return username, password


def _credentials_match(username: str, password: str, *, expected_user: str, expected_password: str) -> bool:
    if not expected_password:
        return False
    return secrets.compare_digest(username, expected_user) and secrets.compare_digest(password, expected_password)


def authenticate_request(request: Request) -> AuthContext | Response:
    if not auth_enabled():
        return AuthContext(enabled=False, username="local", role="admin")
    if _public_request(request):
        return AuthContext(enabled=True, username="anonymous", role="public")

    admin_user = _admin_user()
    admin_password = _admin_password()
    if not admin_password:
        return _misconfigured()

    credentials = _read_basic_credentials(request.headers.get("authorization", ""))
    if credentials is None:
        return _unauthorized()
    username, password = credentials

    if _credentials_match(username, password, expected_user=admin_user, expected_password=admin_password):
        return AuthContext(enabled=True, username=username, role="admin")

    viewer_user = os.environ.get("QA_PORTAL_VIEWER_USER", "viewer").strip() or "viewer"
    viewer_password = os.environ.get("QA_PORTAL_VIEWER_PASSWORD", "")
    if _credentials_match(username, password, expected_user=viewer_user, expected_password=viewer_password):
        if request.method.upper() in WRITE_METHODS:
            return _forbidden()
        return AuthContext(enabled=True, username=username, role="viewer")

    return _unauthorized()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Manage ScanForge authentication bootstrap credentials.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("bootstrap", help="Create or print the initial admin credentials file.")
    subparsers.add_parser("status", help="Print authentication bootstrap status as JSON.")
    args = parser.parse_args()

    if args.command == "bootstrap":
        credentials = ensure_bootstrap_credentials()
        print("ScanForge auth bootstrap")
        print(f"admin_user={credentials['admin_user']}")
        print(f"admin_password={credentials['admin_password']}")
        print(f"bootstrap_path={AUTH_BOOTSTRAP_PATH}")
        return 0
    if args.command == "status":
        print(json.dumps(auth_status(), ensure_ascii=False, indent=2))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
