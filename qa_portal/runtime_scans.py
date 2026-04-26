from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

from .config import MAX_TEXT_FILE_SIZE
from .models import Artifact, Finding
from .tooling import run_command


# Паттерны строят inventory маршрутов с методом, файлом и строкой, чтобы DAST можно было связать с исходниками.
ROUTE_PATTERN_SPECS: tuple[dict[str, Any], ...] = (
    {
        "pattern": re.compile(
            r"@(?:app|bp|router)\.(?P<method>get|post|put|delete|patch|options|head)\(\s*[\"'](?P<path>[^\"']+)[\"']",
            re.IGNORECASE,
        ),
        "framework": "",
    },
    {
        "pattern": re.compile(
            r"\b(?:app|router|server)\.(?P<method>get|post|put|delete|patch|options|head)\(\s*[\"'](?P<path>[^\"']+)[\"']",
            re.IGNORECASE,
        ),
        "framework": "",
    },
    {
        "pattern": re.compile(r"(?:HandleFunc|Handle)\(\s*[\"'](?P<path>[^\"']+)[\"']", re.IGNORECASE),
        "framework": "go-http",
        "method": "ANY",
    },
    {
        "pattern": re.compile(r"\bpath\(\s*[\"'](?P<path>[^\"']+)[\"']", re.IGNORECASE),
        "framework": "django",
        "method": "ANY",
    },
    {
        "pattern": re.compile(r"\broute\(\s*[\"'](?P<path>[^\"']+)[\"']", re.IGNORECASE),
        "framework": "",
        "method": "ANY",
    },
    {
        "pattern": re.compile(r"\bserver\.route\(\s*[\"'](?P<path>[^\"']+)[\"']", re.IGNORECASE),
        "framework": "",
        "method": "ANY",
    },
    {
        "pattern": re.compile(r"\bQHttpServerRoute\(\s*[\"'](?P<path>[^\"']+)[\"']", re.IGNORECASE),
        "framework": "qt-network",
        "method": "ANY",
    },
)
FRAMEWORK_HINTS = {
    "fastapi": re.compile(r"\bFastAPI\b|from\s+fastapi\s+import", re.IGNORECASE),
    "flask": re.compile(r"\bFlask\b|from\s+flask\s+import", re.IGNORECASE),
    "django": re.compile(r"\bdjango\b|from\s+django", re.IGNORECASE),
    "express": re.compile(r"\bexpress\s*\(", re.IGNORECASE),
    "koa": re.compile(r"\bkoa\b", re.IGNORECASE),
    "nest": re.compile(r"@Controller\(|@Get\(|@Post\(", re.IGNORECASE),
    "go-http": re.compile(r"\bnet/http\b|HandleFunc\(", re.IGNORECASE),
    "qt-network": re.compile(r"\bQHttpServer\b|\bQTcpServer\b|\bQWebSocketServer\b", re.IGNORECASE),
}
OPENAPI_FILENAMES = {"openapi.json", "swagger.json", "openapi.yaml", "openapi.yml"}
OPENAPI_DOC_CANDIDATES = ("/openapi.json", "/swagger.json", "/swagger", "/docs", "/api-docs")
SAFE_VERIFICATION_METHODS = {"GET", "HEAD", "OPTIONS"}
SAFE_ACTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ROUTE_PARAMETER_PATTERNS = (
    re.compile(r"{([^}/]+)}"),
    re.compile(r"<(?:[^:>]+:)?([^>]+)>"),
    re.compile(r":([A-Za-z_][A-Za-z0-9_]*)"),
)
HTTP_METHOD_NAMES = {"get", "post", "put", "delete", "patch", "options", "head"}


def _safe_read_text(path: Path) -> str:
    if not path.exists() or path.stat().st_size > MAX_TEXT_FILE_SIZE:
        return ""
    for encoding in ("utf-8", "cp1251", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return ""


def _line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _normalize_route_path(value: str) -> str:
    path = str(value or "").strip()
    if not path:
        return "/"
    if path.startswith("http://") or path.startswith("https://"):
        parsed = urlparse(path)
        path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    path = re.sub(r"/{2,}", "/", path)
    if path != "/":
        path = path.rstrip("/")
    return path or "/"


def _route_parameter_names(path: str) -> list[str]:
    values: list[str] = []
    for pattern in ROUTE_PARAMETER_PATTERNS:
        values.extend(match.group(1) for match in pattern.finditer(path))
    seen: set[str] = set()
    ordered: list[str] = []
    for item in values:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _parameter_specs(raw_parameters: list[Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for raw in raw_parameters:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        location = str(raw.get("in", "")).strip().lower()
        if not name or not location:
            continue
        schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else {}
        items.append(
            {
                "name": name,
                "in": location,
                "required": bool(raw.get("required")),
                "type": str(schema.get("type", "")).strip().lower(),
            }
        )
    return items


def _merge_parameter_specs(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for item in group:
            key = (str(item.get("name", "")), str(item.get("in", "")))
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return merged


def _parameter_value(name: str, type_hint: str = "") -> str:
    normalized_name = name.casefold()
    normalized_type = type_hint.casefold()
    if normalized_type in {"integer", "number"} or any(marker in normalized_name for marker in ("id", "count", "limit", "page", "offset")):
        return "1"
    if normalized_type == "boolean" or any(marker in normalized_name for marker in ("enabled", "flag", "debug", "verbose")):
        return "true"
    if any(marker in normalized_name for marker in ("email", "mail")):
        return "scanforge@example.test"
    if any(marker in normalized_name for marker in ("token", "secret", "password")):
        return "scanforge-probe"
    return "scanforge"


def _apply_path_parameter_examples(path: str, parameter_names: list[str]) -> str:
    resolved = path
    for name in parameter_names:
        value = _parameter_value(name)
        resolved = resolved.replace(f"{{{name}}}", value)
        resolved = re.sub(rf"<(?:[^:>]+:)?{re.escape(name)}>", value, resolved)
        resolved = re.sub(rf":{re.escape(name)}\b", value, resolved)
    return _normalize_route_path(resolved)


def _example_request_path(route: dict[str, Any]) -> str:
    path = _apply_path_parameter_examples(
        str(route.get("path", "/")),
        [
            str(item.get("name", ""))
            for item in route.get("parameters", [])
            if str(item.get("in", "")) == "path"
        ]
        or _route_parameter_names(str(route.get("path", "/"))),
    )
    query_pairs: list[tuple[str, str]] = []
    for item in route.get("parameters", []):
        if str(item.get("in", "")) != "query":
            continue
        if not (bool(item.get("required")) or len(query_pairs) < 2):
            continue
        query_pairs.append((str(item.get("name", "")), _parameter_value(str(item.get("name", "")), str(item.get("type", "")))))
    if not query_pairs:
        return path
    return f"{path}?{urlencode(query_pairs)}"


def _http_probe(
    url: str,
    method: str = "GET",
    timeout: float = 3.0,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> dict[str, Any]:
    merged_headers = {"User-Agent": "ScanForge/0.2"}
    if headers:
        merged_headers.update(headers)
    request = Request(url, method=method, headers=merged_headers, data=data)
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(1024)
            return {
                "url": url,
                "method": method,
                "status": int(response.status),
                "content_type": response.headers.get("Content-Type", ""),
                "ok": True,
                "preview": body.decode("utf-8", errors="ignore"),
            }
    except HTTPError as exc:
        return {
            "url": url,
            "method": method,
            "status": int(exc.code),
            "content_type": exc.headers.get("Content-Type", ""),
            "ok": False,
            "preview": exc.read(512).decode("utf-8", errors="ignore"),
        }
    except (OSError, URLError) as exc:
        return {
            "url": url,
            "method": method,
            "status": 0,
            "content_type": "",
            "ok": False,
            "preview": str(exc),
        }


    # Из OpenAPI извлекаем только пути и методы, не исполняя произвольные сценарии.
def _load_openapi_paths(root: Path, path: Path) -> list[dict[str, Any]]:
    text = _safe_read_text(path)
    if not text:
        return []
    source_path = str(path.relative_to(root))
    entries: list[dict[str, Any]] = []
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except ValueError:
            return []
        global_security = payload.get("security") or []
        for route_path, methods in (payload.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            shared_parameters = _parameter_specs(list(methods.get("parameters") or []))
            for method, operation in methods.items():
                if str(method).casefold() not in HTTP_METHOD_NAMES:
                    continue
                operation_payload = operation if isinstance(operation, dict) else {}
                request_content = operation_payload.get("requestBody", {}) if isinstance(operation_payload.get("requestBody"), dict) else {}
                content_map = request_content.get("content", {}) if isinstance(request_content.get("content"), dict) else {}
                entries.append(
                    {
                        "path": _normalize_route_path(str(route_path)),
                        "method": str(method).upper(),
                        "parameters": _merge_parameter_specs(
                            shared_parameters,
                            _parameter_specs(list(operation_payload.get("parameters") or [])),
                        ),
                        "request_content_types": [str(item) for item in content_map.keys()][:4],
                        "security_declared": bool(operation_payload.get("security") or global_security),
                        "operation_id": str(operation_payload.get("operationId", "")).strip(),
                        "tags": [str(item).strip() for item in (operation_payload.get("tags") or []) if str(item).strip()][:4],
                        "source_path": source_path,
                        "line": None,
                        "framework": "openapi",
                        "source_kind": "openapi",
                    }
                )
        return entries

    current_path = ""
    for line in text.splitlines():
        if re.match(r"^\s{2}/", line):
            current_path = _normalize_route_path(line.strip().rstrip(":"))
            continue
        method_match = re.match(r"^\s{4}(get|post|put|delete|patch|options|head):", line, flags=re.IGNORECASE)
        if current_path and method_match:
            entries.append(
                {
                    "path": current_path,
                    "method": method_match.group(1).upper(),
                    "parameters": [],
                    "request_content_types": [],
                    "security_declared": False,
                    "operation_id": "",
                    "tags": [],
                    "source_path": source_path,
                    "line": None,
                    "framework": "openapi",
                    "source_kind": "openapi",
                }
            )
    return entries


# Определяем API-поверхность по исходникам и служебным спецификациям.
def discover_service_surface(root: Path) -> dict[str, Any]:
    frameworks: set[str] = set()
    routes: set[str] = set()
    openapi_specs: list[str] = []
    openapi_requests: list[dict[str, Any]] = []
    route_inventory: list[dict[str, Any]] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = str(path.relative_to(root))
        if path.name.casefold() in OPENAPI_FILENAMES:
            openapi_specs.append(relative)
            for item in _load_openapi_paths(root, path):
                openapi_requests.append(item)
                route_inventory.append(item)
                routes.add(str(item.get("path", "/")))
            continue
        if path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".go", ".java", ".cpp", ".cc", ".cxx", ".h", ".hpp"}:
            continue
        text = _safe_read_text(path)
        if not text:
            continue
        matched_frameworks: list[str] = []
        for framework, pattern in FRAMEWORK_HINTS.items():
            if pattern.search(text):
                frameworks.add(framework)
                matched_frameworks.append(framework)
        default_framework = matched_frameworks[0] if matched_frameworks else ""
        for spec in ROUTE_PATTERN_SPECS:
            for match in spec["pattern"].finditer(text):
                raw_path = str(match.groupdict().get("path", "")).strip()
                if not raw_path:
                    continue
                normalized_path = _normalize_route_path(raw_path)
                routes.add(normalized_path)
                method = str(match.groupdict().get("method") or spec.get("method") or "ANY").upper()
                route_inventory.append(
                    {
                        "path": normalized_path,
                        "method": method,
                        "parameters": [
                            {"name": item, "in": "path", "required": True, "type": ""}
                            for item in _route_parameter_names(normalized_path)
                        ],
                        "request_content_types": [],
                        "security_declared": False,
                        "operation_id": "",
                        "tags": [],
                        "source_path": relative,
                        "line": _line_number_for_offset(text, match.start()),
                        "framework": str(spec.get("framework") or default_framework),
                        "source_kind": "source",
                    }
                )

    deduped_inventory: list[dict[str, Any]] = []
    seen_inventory: set[tuple[str, str, str, str, str]] = set()
    for item in sorted(
        route_inventory,
        key=lambda entry: (
            str(entry.get("path", "")),
            str(entry.get("method", "")),
            str(entry.get("source_path", "")),
            int(entry.get("line") or 0),
            str(entry.get("source_kind", "")),
        ),
    ):
        key = (
            str(item.get("path", "")),
            str(item.get("method", "")),
            str(item.get("source_path", "")),
            str(item.get("line") or ""),
            str(item.get("source_kind", "")),
        )
        if key in seen_inventory:
            continue
        seen_inventory.add(key)
        deduped_inventory.append(item)
    ordered_routes = sorted(routes)
    ordered_openapi = sorted(openapi_specs)
    return {
        "frameworks": sorted(frameworks),
        "route_count": len(ordered_routes),
        "routes": ordered_routes[:50],
        "openapi_specs": ordered_openapi,
        "openapi_requests": openapi_requests[:30],
        "route_inventory": deduped_inventory[:80],
        "route_inventory_count": len(deduped_inventory),
        "route_source_file_count": len({str(item.get("source_path", "")) for item in deduped_inventory if str(item.get("source_path", ""))}),
        "service_detected": bool(frameworks or ordered_routes or ordered_openapi),
    }


def _discover_target_url(ci_context: dict[str, Any] | None = None) -> str:
    context = ci_context or {}
    for key in ("target_url", "service_url", "preview_url"):
        value = str(context.get(key, "")).strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value
    return ""


def _discover_runtime_profile(ci_context: dict[str, Any] | None = None) -> str:
    context = ci_context or {}
    value = str(
        context.get("service_runtime_profile")
        or context.get("dast_profile")
        or context.get("runtime_profile")
        or "passive"
    ).strip().casefold()
    return "safe-active" if value == "safe-active" else "passive"


def _discover_request_timeout(ci_context: dict[str, Any] | None = None) -> float:
    context = ci_context or {}
    raw = context.get("request_timeout_seconds") or context.get("service_timeout_seconds") or 3
    try:
        timeout = float(raw)
    except (TypeError, ValueError):
        return 3.0
    return max(1.0, min(timeout, 30.0))


def _discover_request_headers(ci_context: dict[str, Any] | None = None) -> dict[str, str]:
    context = ci_context or {}
    raw_headers = context.get("request_headers") or context.get("service_headers") or {}
    if isinstance(raw_headers, dict):
        return {
            str(key).strip(): str(value).strip()
            for key, value in raw_headers.items()
            if str(key).strip() and str(value).strip()
        }
    if isinstance(raw_headers, str):
        try:
            parsed = json.loads(raw_headers)
        except ValueError:
            return {}
        if isinstance(parsed, dict):
            return {
                str(key).strip(): str(value).strip()
                for key, value in parsed.items()
                if str(key).strip() and str(value).strip()
            }
    return {}


def _discover_auth_config(ci_context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = ci_context or {}
    headers = _discover_request_headers(context)

    username = str(context.get("basic_auth_username", "")).strip()
    password = str(context.get("basic_auth_password", "")).strip()
    if username and password:
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
        return {"mode": "basic", "headers": headers}

    token = str(context.get("auth_token", "")).strip()
    if token:
        header_name = str(context.get("auth_header_name", "Authorization")).strip() or "Authorization"
        token_prefix = str(context.get("auth_token_prefix", "Bearer")).strip()
        headers[header_name] = f"{token_prefix} {token}".strip() if token_prefix else token
        mode = "bearer" if header_name.lower() == "authorization" and token_prefix.casefold() == "bearer" else "header"
        return {"mode": mode, "headers": headers}

    cookie_name = str(context.get("auth_cookie_name", "")).strip()
    cookie_value = str(context.get("auth_cookie", "")).strip()
    if cookie_name and cookie_value:
        headers["Cookie"] = f"{cookie_name}={cookie_value}"
        return {"mode": "cookie", "headers": headers}

    return {"mode": "none", "headers": headers}


def _build_probe_payload(method: str, path: str, request_spec: dict[str, Any] | None = None) -> tuple[bytes | None, str, str]:
    normalized_method = method.upper()
    if normalized_method not in SAFE_ACTIVE_METHODS:
        return None, "", ""
    if normalized_method == "DELETE":
        return None, "", ""
    request_content_types = [str(item).strip() for item in (request_spec or {}).get("request_content_types", []) if str(item).strip()]
    probe_payload = {
        "scanforge_probe": True,
        "method": normalized_method,
        "path": path,
        "mode": "safe-active",
        "operation_id": str((request_spec or {}).get("operation_id", "")),
    }
    if any("application/json" in item for item in request_content_types) or not request_content_types:
        content_type = next((item for item in request_content_types if "application/json" in item), "application/json")
        return json.dumps(probe_payload, ensure_ascii=False).encode("utf-8"), content_type, ""
    if any("application/x-www-form-urlencoded" in item for item in request_content_types):
        return urlencode({"scanforge_probe": "true", "path": path}).encode("utf-8"), "application/x-www-form-urlencoded", ""
    if any(item.startswith("text/plain") for item in request_content_types):
        return f"scanforge_probe:{normalized_method}:{path}".encode("utf-8"), "text/plain", ""
    return None, request_content_types[0], "unsupported-active-content-type"


def _request_headers_for_probe(auth_config: dict[str, Any], profile: str, content_type: str, request_spec: dict[str, Any] | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "X-ScanForge-Verification": profile,
    }
    headers.update(auth_config.get("headers", {}))
    for item in (request_spec or {}).get("parameters", []):
        if str(item.get("in", "")) != "header":
            continue
        header_name = str(item.get("name", "")).strip()
        if not header_name or header_name.lower() in {"authorization", "cookie"}:
            continue
        headers.setdefault(header_name, _parameter_value(header_name, str(item.get("type", ""))))
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _verification_request_lines(target_url: str, requests: list[dict[str, Any]], *, auth_mode: str, profile: str) -> str:
    lines = ["# Controlled verification requests", ""]
    if not target_url:
        lines.append("# No target URL was provided. Add service_url / target_url in CI metadata to enable live verification.")
        return "\n".join(lines) + "\n"
    for item in requests[:20]:
        method = item.get("method", "GET")
        original_path = item.get("path", "/")
        resolved_path = item.get("resolved_path") or original_path
        payload_bytes, content_type, _skip_reason = _build_probe_payload(method, str(original_path), item)
        lines.extend(
            [
                f"# route: {original_path}",
                *( [f"# source: {item.get('source_path')}:{item.get('line')}" ] if item.get("source_path") else [] ),
                f"{method} {urljoin(target_url.rstrip('/') + '/', str(resolved_path).lstrip('/'))}",
                "Accept: application/json",
                f"X-ScanForge-Verification: {profile}",
                f"# auth: {auth_mode}",
                *( [f"Content-Type: {content_type}"] if content_type else [] ),
                *(["", payload_bytes.decode("utf-8", errors="ignore")] if payload_bytes else []),
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def _replay_script_lines(target_url: str, requests: list[dict[str, Any]], *, auth_mode: str, profile: str) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f'BASE_URL="${{SCANFORGE_TARGET_URL:-{target_url or "http://127.0.0.1:8000"}}}"',
        f'VERIFICATION_PROFILE="${{SCANFORGE_VERIFICATION_PROFILE:-{profile}}}"',
        'AUTH_HEADER_NAME="${SCANFORGE_AUTH_HEADER_NAME:-Authorization}"',
        'AUTH_HEADER_VALUE="${SCANFORGE_AUTH_HEADER_VALUE:-}"',
        "",
        "# Для безопасного replay секреты передаются только через переменные окружения.",
        f"# Ожидаемый auth-режим: {auth_mode}",
        "",
        "run_probe() {",
        '  local method="$1"',
        '  local path="$2"',
        '  local content_type="${3:-}"',
        '  local body="${4:-}"',
        '  local -a args=(curl -sS -X "$method" "$BASE_URL$path" -H "Accept: application/json" -H "X-ScanForge-Verification: $VERIFICATION_PROFILE")',
        '  if [[ -n "$AUTH_HEADER_VALUE" ]]; then',
        '    args+=(-H "$AUTH_HEADER_NAME: $AUTH_HEADER_VALUE")',
        "  fi",
        '  if [[ -n "$content_type" ]]; then',
        '    args+=(-H "Content-Type: $content_type")',
        "  fi",
        '  if [[ -n "$body" ]]; then',
        '    args+=(--data "$body")',
        "  fi",
        '  printf \'\\n==> %s %s\\n\' \"$method\" \"$path\"',
        '  "${args[@]}"',
        "  printf '\\n'",
        "}",
        "",
    ]
    for item in requests[:20]:
        body_bytes, content_type, _skip_reason = _build_probe_payload(str(item.get("method", "GET")), str(item.get("path", "/")), item)
        body = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
        lines.append(
            f'run_probe "{item.get("method", "GET")}" "{item.get("resolved_path") or item.get("path", "/")}" "{content_type}" {json.dumps(body)}'
        )
    return "\n".join(lines).strip() + "\n"


def _documentation_surface_key(path: str) -> str:
    normalized = _normalize_route_path(path).casefold()
    if normalized in {"/openapi.json", "/swagger.json"}:
        return "machine-readable-spec"
    if normalized in {"/swagger", "/docs", "/api-docs"}:
        return "interactive-docs"
    return normalized


def _merge_request_entry(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    merged["parameters"] = _merge_parameter_specs(
        list(base.get("parameters") or []),
        list(extra.get("parameters") or []),
    )

    content_types: list[str] = []
    for group in (base.get("request_content_types") or [], extra.get("request_content_types") or []):
        for item in group:
            normalized = str(item).strip()
            if normalized and normalized not in content_types:
                content_types.append(normalized)
    merged["request_content_types"] = content_types

    tags: list[str] = []
    for group in (base.get("tags") or [], extra.get("tags") or []):
        for item in group:
            normalized = str(item).strip()
            if normalized and normalized not in tags:
                tags.append(normalized)
    merged["tags"] = tags

    merged["security_declared"] = bool(base.get("security_declared") or extra.get("security_declared"))
    merged["operation_id"] = str(base.get("operation_id") or extra.get("operation_id") or "").strip()

    if str(base.get("source_kind", "")) != "source" and str(extra.get("source_kind", "")) == "source":
        merged["source_kind"] = "source"
        merged["source_path"] = extra.get("source_path", "")
        merged["line"] = extra.get("line")
        merged["framework"] = extra.get("framework", "")
    else:
        merged["source_kind"] = str(base.get("source_kind") or extra.get("source_kind") or "")
        merged["source_path"] = base.get("source_path") or extra.get("source_path") or ""
        merged["line"] = base.get("line") if base.get("line") is not None else extra.get("line")
        merged["framework"] = base.get("framework") or extra.get("framework") or ""

    merged["request_kind"] = str(base.get("request_kind") or extra.get("request_kind") or "route")
    merged["resolved_path"] = str(base.get("resolved_path") or extra.get("resolved_path") or _example_request_path(merged))
    return merged


def _candidate_verification_requests(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = [
        {
            "method": "GET",
            "path": "/",
            "resolved_path": "/",
            "parameters": [],
            "request_content_types": [],
            "security_declared": False,
            "operation_id": "",
            "tags": [],
            "source_path": "",
            "line": None,
            "framework": "",
            "source_kind": "root",
            "request_kind": "health-probe",
        }
    ]
    for item in sorted(
        metadata.get("route_inventory", []),
        key=lambda entry: (
            0 if str(entry.get("source_kind", "")) == "source" else 1,
            str(entry.get("path", "")),
            str(entry.get("method", "")),
            str(entry.get("source_path", "")),
        ),
    ):
        request = dict(item)
        request["method"] = str(request.get("method") or "GET").upper()
        if request["method"] == "ANY":
            request["method"] = "GET"
        request["resolved_path"] = _example_request_path(request)
        request["request_kind"] = "route"
        requests.append(request)
    if metadata.get("openapi_specs"):
        for item in OPENAPI_DOC_CANDIDATES:
            requests.append(
                {
                    "method": "GET",
                    "path": item,
                    "resolved_path": item,
                    "parameters": [],
                    "request_content_types": [],
                    "security_declared": False,
                    "operation_id": "",
                    "tags": ["documentation"],
                    "source_path": metadata.get("openapi_specs", [""])[0],
                    "line": None,
                    "framework": "openapi",
                    "source_kind": "documentation",
                    "request_kind": "documentation",
                }
            )
    deduped: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], int] = {}
    for item in requests:
        key = (str(item.get("method", "GET")).upper(), str(item.get("resolved_path") or item.get("path", "/")))
        if key in seen:
            deduped[seen[key]] = _merge_request_entry(deduped[seen[key]], item)
            continue
        seen[key] = len(deduped)
        deduped.append(item)
    return deduped[:24]


# DAST/IAST-подобная стадия выполняет безопасные HTTP-проверки и коррелирует их с исходными маршрутами.
def analyze_service_runtime(
    root: Path,
    output_dir: Path,
    *,
    ci_context: dict[str, Any] | None = None,
) -> tuple[list[Finding], list[Artifact], list[str], dict[str, Any]]:
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    logs: list[str] = []
    metadata = discover_service_surface(root)
    metadata["target_url"] = _discover_target_url(ci_context)
    metadata["verification_profile"] = _discover_runtime_profile(ci_context)
    metadata["request_timeout_seconds"] = _discover_request_timeout(ci_context)
    metadata["auth_mode"] = "none"
    metadata["verification_requests"] = []
    metadata["verification_results"] = []
    metadata["skipped_requests"] = []
    metadata["source_correlated_paths"] = 0
    metadata["openapi_exposed"] = False
    metadata["mutating_route_count"] = 0
    metadata["verification_request_count"] = 0
    metadata["verified_route_count"] = 0
    metadata["server_error_count"] = 0
    metadata["documentation_exposure_count"] = 0
    metadata["documentation_exposure_paths"] = []
    metadata["unauthenticated_write_count"] = 0
    metadata["security_declared_bypass_count"] = 0
    metadata["replay_script"] = ""
    metadata["surface_inventory_artifact"] = ""
    metadata["iast_hints_artifact"] = ""

    if not metadata["service_detected"]:
        findings.append(
            Finding(
                category="service-runtime",
                severity="info",
                title="No runnable service surface detected",
                description="В проекте не обнаружены явные API-маршруты, OpenAPI-спецификации или сетевые фреймворки.",
                source="service-runtime",
                recommendation="Для DAST/IAST-проверок добавьте API-описание или runtime URL сервиса.",
            )
        )
    else:
        findings.append(
            Finding(
                category="service-runtime",
                severity="info",
                title="Service/API surface detected",
                description=(
                    f"Обнаружено фреймворков: {len(metadata['frameworks'])}, "
                    f"маршрутов: {metadata['route_count']}, OpenAPI-спецификаций: {len(metadata['openapi_specs'])}."
                ),
                source="service-runtime",
                recommendation="Проверьте runtime URL сервиса и выполните controlled verification requests.",
            )
        )
        if metadata.get("route_inventory_count", 0):
            findings.append(
                Finding(
                    category="service-runtime",
                    severity="info",
                    title="Route inventory prepared for runtime correlation",
                    description=(
                        f"Подготовлен inventory из {metadata.get('route_inventory_count', 0)} API-маршрутов "
                        f"в {metadata.get('route_source_file_count', 0)} исходных файлах."
                    ),
                    source="service-runtime",
                    recommendation="Используйте inventory для точечного replay, IAST-корреляции и контроля измененных API.",
                )
            )

    metadata["verification_requests"] = _candidate_verification_requests(metadata)
    metadata["verification_request_count"] = len(metadata["verification_requests"])
    metadata["mutating_route_count"] = sum(1 for item in metadata["verification_requests"] if item["method"] in SAFE_ACTIVE_METHODS)
    auth_config = _discover_auth_config(ci_context)
    metadata["auth_mode"] = auth_config["mode"]

    surface_path = output_dir / "service_surface.json"
    surface_path.write_text(
        json.dumps(
            {
                "frameworks": metadata.get("frameworks", []),
                "route_count": metadata.get("route_count", 0),
                "route_inventory_count": metadata.get("route_inventory_count", 0),
                "route_inventory": metadata.get("route_inventory", []),
                "openapi_specs": metadata.get("openapi_specs", []),
                "verification_requests": metadata.get("verification_requests", []),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    metadata["surface_inventory_artifact"] = surface_path.name
    artifacts.append(Artifact(label="Service surface", filename=surface_path.name, kind="json"))

    verification_path = output_dir / "verification_requests.http"
    verification_path.write_text(
        _verification_request_lines(
            metadata["target_url"],
            metadata["verification_requests"],
            auth_mode=metadata["auth_mode"],
            profile=metadata["verification_profile"],
        ),
        encoding="utf-8",
    )
    artifacts.append(Artifact(label="Verification requests", filename=verification_path.name, kind="text"))

    replay_path = output_dir / "verification_replay.sh"
    replay_path.write_text(
        _replay_script_lines(
            metadata["target_url"],
            metadata["verification_requests"],
            auth_mode=metadata["auth_mode"],
            profile=metadata["verification_profile"],
        ),
        encoding="utf-8",
    )
    replay_path.chmod(0o755)
    metadata["replay_script"] = replay_path.name
    artifacts.append(Artifact(label="Verification replay", filename=replay_path.name, kind="text"))

    if metadata["target_url"]:
        parsed = urlparse(metadata["target_url"])
        if parsed.scheme in {"http", "https"}:
            verified_sources: set[tuple[str, int, str]] = set()
            verified_routes: set[tuple[str, str]] = set()
            server_errors: list[dict[str, Any]] = []
            documentation_exposures: dict[str, dict[str, Any]] = {}
            unauthenticated_writes: list[dict[str, Any]] = []
            security_declared_bypasses: list[dict[str, Any]] = []
            for item in metadata["verification_requests"][:10]:
                if metadata["verification_profile"] != "safe-active" and item["method"] in SAFE_ACTIVE_METHODS:
                    metadata["skipped_requests"].append(
                        {
                            "method": item["method"],
                            "path": item["path"],
                            "resolved_path": item.get("resolved_path") or item["path"],
                            "reason": "mutating-route-deferred-by-passive-profile",
                        }
                    )
                    continue
                payload_bytes, content_type, skip_reason = _build_probe_payload(item["method"], str(item["path"]), item)
                if skip_reason:
                    metadata["skipped_requests"].append(
                        {
                            "method": item["method"],
                            "path": item["path"],
                            "resolved_path": item.get("resolved_path") or item["path"],
                            "reason": skip_reason,
                        }
                    )
                    continue
                request_url = urljoin(
                    metadata["target_url"].rstrip("/") + "/",
                    str(item.get("resolved_path") or item["path"]).lstrip("/"),
                )
                headers = _request_headers_for_probe(auth_config, metadata["verification_profile"], content_type, item)
                result = _http_probe(
                    request_url,
                    method=item["method"],
                    timeout=metadata["request_timeout_seconds"],
                    headers=headers,
                    data=payload_bytes,
                )
                result["path"] = item["path"]
                result["resolved_path"] = item.get("resolved_path") or item["path"]
                result["auth_used"] = metadata["auth_mode"]
                result["profile"] = metadata["verification_profile"]
                result["content_type_sent"] = content_type
                result["source_path"] = item.get("source_path", "")
                result["line"] = item.get("line")
                result["framework"] = item.get("framework", "")
                result["request_kind"] = item.get("request_kind", "route")
                result["security_declared"] = bool(item.get("security_declared"))
                result["operation_id"] = item.get("operation_id", "")
                result["tags"] = item.get("tags", [])
                result["accepted"] = 200 <= int(result.get("status", 0) or 0) < 400
                metadata["verification_results"].append(result)
                if result["accepted"]:
                    verified_routes.add((str(item["method"]), str(item["path"])))
                    if item.get("source_path"):
                        verified_sources.add((str(item.get("source_path", "")), int(item.get("line") or 0), str(item["path"])))
                    logs.append(f"Verified route {item['method']} {request_url} -> HTTP {result['status']}")
                    if result["request_kind"] == "documentation":
                        metadata["openapi_exposed"] = True
                        if metadata["auth_mode"] == "none":
                            documentation_exposures.setdefault(
                                _documentation_surface_key(str(result.get("resolved_path") or result.get("path") or "/")),
                                result,
                            )
                    if item["method"] in SAFE_ACTIVE_METHODS and metadata["auth_mode"] == "none":
                        unauthenticated_writes.append(result)
                    if item.get("security_declared") and metadata["auth_mode"] == "none":
                        security_declared_bypasses.append(result)
                if int(result.get("status", 0) or 0) >= 500:
                    server_errors.append(result)
            metadata["source_correlated_paths"] = len(verified_sources)
            metadata["verified_route_count"] = len(verified_routes)
            metadata["server_error_count"] = len(server_errors)
            metadata["documentation_exposure_count"] = len(documentation_exposures)
            metadata["documentation_exposure_paths"] = sorted(
                str(item.get("resolved_path") or item.get("path") or "/")
                for item in documentation_exposures.values()
            )
            metadata["unauthenticated_write_count"] = len(unauthenticated_writes)
            metadata["security_declared_bypass_count"] = len(security_declared_bypasses)
            if metadata["verification_results"] and metadata["verified_route_count"] > 0:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="medium" if metadata["documentation_exposure_count"] else "info",
                        title="Controlled TLS input verification completed" if parsed.scheme == "https" else "Controlled service verification completed",
                        description=(
                            f"Успешно подтверждено {metadata['verified_route_count']} HTTP-маршрутов "
                            f"по адресу {metadata['target_url']}."
                        ),
                        source="service-runtime",
                        recommendation="Используйте эти маршруты как baseline для DAST-повтора и replay-проверок.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="low",
                        title="Runtime target did not expose verified routes",
                        description="Runtime URL задан, но controlled verification requests не подтвердили доступные маршруты.",
                        source="service-runtime",
                        recommendation="Проверьте, что сервис поднят и совпадает с загруженным проектом.",
                    )
                )
            if metadata["source_correlated_paths"] > 0:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="info",
                        title="IAST-style source correlation produced verified route evidence",
                        description=(
                            f"Для {metadata['source_correlated_paths']} маршрутов подготовлена связка runtime-ответов "
                            "с исходными файлами и строками."
                        ),
                        source="service-runtime",
                        recommendation="Используйте iast_hints.json для replay по измененным endpoint-ам и для root-cause triage.",
                    )
                )
            if server_errors:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="high",
                        title="Runtime verification surfaced server errors",
                        description=(
                            f"Controlled verification получила HTTP 5xx на {len(server_errors)} endpoint-ах, "
                            f"например {server_errors[0].get('method', 'GET')} {server_errors[0].get('path', '/')}."
                        ),
                        source="service-runtime",
                        recommendation="Проверьте server-side обработчики, логи и трассировку вокруг упавших маршрутов.",
                    )
                )
            if documentation_exposures:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="medium",
                        title="OpenAPI or Swagger endpoint exposed without authentication",
                        description=(
                            f"Подтвержден доступ без аутентификации к {len(documentation_exposures)} уникальным поверхностям документации."
                        ),
                        source="service-runtime",
                        recommendation="Ограничьте доступ к OpenAPI/Swagger в тестовом и production-профиле или вынесите его за auth-gateway.",
                    )
                )
            if unauthenticated_writes:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="high",
                        title="Mutating endpoints accepted unauthenticated requests",
                        description=(
                            f"Safe-active проверка подтвердила {len(unauthenticated_writes)} mutating-маршрутов "
                            "без предоставления auth-данных."
                        ),
                        source="service-runtime",
                        recommendation="Проверьте auth middlewares, ACL и CSRF/permission boundary для write-endpoint-ов.",
                    )
                )
            if security_declared_bypasses:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="high",
                        title="Security-declared API routes responded without supplied authentication",
                        description=(
                            f"OpenAPI security metadata была объявлена для {len(security_declared_bypasses)} endpoint-ов, "
                            "но они ответили без auth-заголовков."
                        ),
                        source="service-runtime",
                        recommendation="Проверьте, не расходится ли OpenAPI security contract с фактической конфигурацией runtime.",
                    )
                )
            if metadata["verification_profile"] == "safe-active":
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="info",
                        title="Safe active verification profile enabled",
                        description="Разрешены безопасные replay-проверки для mutating HTTP-методов с синтетическими payload-шаблонами.",
                        source="service-runtime",
                        recommendation="Используйте safe-active профиль только на тестовом окружении с контролируемыми данными.",
                    )
                )
            elif metadata["mutating_route_count"]:
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="info",
                        title="Mutating routes deferred by passive verification profile",
                        description=(
                            f"Обнаружено mutating-маршрутов: {metadata['mutating_route_count']}. "
                            "Они не выполнялись в live-режиме, потому что активирован passive-профиль."
                        ),
                        source="service-runtime",
                        recommendation="Для контролируемого replay включите service_runtime_profile=safe-active.",
                    )
                )
            if metadata["auth_mode"] != "none":
                findings.append(
                    Finding(
                        category="service-runtime",
                        severity="info",
                        title="Authenticated runtime verification enabled",
                        description=f"Для runtime-верификации использован auth-режим: {metadata['auth_mode']}.",
                        source="service-runtime",
                        recommendation="Проверьте, что auth-секреты передаются только через защищенный CI context.",
                    )
                )
        else:
            findings.append(
                Finding(
                    category="service-runtime",
                    severity="low",
                    title="Unsupported runtime target scheme",
                    description="Для DAST/IAST поддерживаются только HTTP и HTTPS адреса.",
                    source="service-runtime",
                    recommendation="Передайте runtime URL вида http://host:port или https://host.",
                )
            )
    elif metadata["service_detected"]:
        findings.append(
            Finding(
                category="service-runtime",
                severity="medium",
                title="Service surface detected but no runtime target provided",
                description="Маршруты и API обнаружены, но live-верификация не выполнена, потому что не задан target URL.",
                source="service-runtime",
                recommendation="Передавайте `service_url`, `target_url` или `preview_url` через CI metadata.",
            )
        )

    if metadata["openapi_specs"]:
        findings.append(
            Finding(
                category="service-runtime",
                severity="info",
                title="OpenAPI description available",
                description="Проект содержит OpenAPI/Swagger-спецификацию, пригодную для безопасного replay и DAST-планирования.",
                source="service-runtime",
                recommendation="Используйте спецификацию как источник маршрутов для regression verification.",
            )
        )

    metadata["verification_results"] = metadata["verification_results"][:20]
    iast_hints_path = output_dir / "iast_hints.json"
    iast_hints_path.write_text(
        json.dumps(
            {
                "route_inventory": metadata.get("route_inventory", []),
                "verified_routes": [
                    {
                        "method": item.get("method", "GET"),
                        "path": item.get("path", "/"),
                        "resolved_path": item.get("resolved_path", item.get("path", "/")),
                        "status": item.get("status", 0),
                        "source_path": item.get("source_path", ""),
                        "line": item.get("line"),
                        "framework": item.get("framework", ""),
                    }
                    for item in metadata.get("verification_results", [])
                    if item.get("accepted")
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    metadata["iast_hints_artifact"] = iast_hints_path.name
    artifacts.append(Artifact(label="IAST hints", filename=iast_hints_path.name, kind="json"))
    results_path = output_dir / "verification_results.json"
    results_path.write_text(
        json.dumps(
            {
                "profile": metadata["verification_profile"],
                "timeout_seconds": metadata["request_timeout_seconds"],
                "auth_mode": metadata["auth_mode"],
                "verified_route_count": metadata["verified_route_count"],
                "server_error_count": metadata["server_error_count"],
                "documentation_exposure_count": metadata["documentation_exposure_count"],
                "documentation_exposure_paths": metadata["documentation_exposure_paths"],
                "unauthenticated_write_count": metadata["unauthenticated_write_count"],
                "security_declared_bypass_count": metadata["security_declared_bypass_count"],
                "results": metadata["verification_results"],
                "skipped": metadata["skipped_requests"],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    artifacts.append(Artifact(label="Verification results", filename=results_path.name, kind="json"))
    return findings, artifacts, logs, metadata


def _discover_executables(build_dir: Path) -> list[str]:
    items: list[str] = []
    if not build_dir.exists():
        return items
    for path in build_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.stat().st_mode & 0o111:
                items.append(str(path.relative_to(build_dir)))
        except OSError:
            continue
    return sorted(items)[:40]


# VM/full-system режим начинает с реальных runtime-артефактов: trace, inventory и replay-команд.
def analyze_vm_runtime(
    root: Path,
    build_dir: Path,
    output_dir: Path,
    *,
    functionality_meta: dict[str, Any] | None = None,
) -> tuple[list[Finding], list[Artifact], list[str], dict[str, Any]]:
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    logs: list[str] = []
    metadata = {
        "eligible": False,
        "strace_available": bool(shutil.which("strace")),
        "docker_available": bool(shutil.which("docker")),
        "qemu_available": bool(shutil.which("qemu-system-x86_64")),
        "gdb_available": bool(shutil.which("gdb")),
        "taint_tracking_available": False,
        "process_trace_collected": False,
        "binary_inventory": _discover_executables(build_dir),
        "crash_replay_script": "",
    }
    metadata["taint_tracking_available"] = metadata["qemu_available"] and metadata["gdb_available"]

    inventory_path = output_dir / "binary_inventory.json"
    inventory_path.write_text(json.dumps(metadata["binary_inventory"], indent=2, ensure_ascii=False), encoding="utf-8")
    artifacts.append(Artifact(label="Binary inventory", filename=inventory_path.name, kind="json"))

    replay_path = output_dir / "crash_replay.sh"
    replay_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f"BUILD_DIR={str(build_dir)!r}",
        "",
        "# Повторный прогон тестов и инструментированного рантайма для воспроизведения проблем.",
        "if [[ -f \"$BUILD_DIR/CTestTestfile.cmake\" ]]; then",
        "  ctest --test-dir \"$BUILD_DIR\" --output-on-failure --parallel 1",
        "fi",
    ]
    replay_path.write_text("\n".join(replay_lines).strip() + "\n", encoding="utf-8")
    replay_path.chmod(0o755)
    metadata["crash_replay_script"] = replay_path.name
    artifacts.append(Artifact(label="Crash replay", filename=replay_path.name, kind="text"))

    if not functionality_meta or not functionality_meta.get("built"):
        findings.append(
            Finding(
                category="vm-runtime",
                severity="info",
                title="VM/full-system runtime skipped",
                description="Полноценный runtime-анализ требует хотя бы одной успешной сборки бинарных артефактов.",
                source="vm-runtime",
                recommendation="Сначала добейтесь успешной сборки и повторите runtime-профилирование.",
            )
        )
        return findings, artifacts, logs, metadata

    metadata["eligible"] = True
    if metadata["strace_available"] and (build_dir / "CTestTestfile.cmake").exists():
        trace_path = output_dir / "process_trace.log"
        result = run_command(
            ["strace", "-ff", "-o", str(trace_path), "ctest", "--test-dir", str(build_dir), "--parallel", "1"],
            cwd=root,
            timeout=240,
        )
        logs.append(f"$ {' '.join(result.command)}")
        if result.stdout.strip():
            logs.append(result.stdout.strip())
        if result.stderr.strip():
            logs.append(result.stderr.strip())
        metadata["process_trace_collected"] = trace_path.exists() or any(output_dir.glob("process_trace.log*"))
        if metadata["process_trace_collected"]:
            artifacts.append(Artifact(label="Process trace", filename=trace_path.name, kind="text"))
            findings.append(
                Finding(
                    category="vm-runtime",
                    severity="info",
                    title="Process trace captured",
                    description="Собран системный trace процессов во время runtime-прогона тестов.",
                    source="vm-runtime",
                    recommendation="Используйте trace для crash replay, анализа процессов и подготовки full-system сценариев.",
                )
            )
    else:
        findings.append(
            Finding(
                category="vm-runtime",
                severity="low",
                title="Trace tooling not fully available",
                description="Для полного process tracing нужен `strace` и набор test entry points в build-каталоге.",
                source="vm-runtime",
                recommendation="Установите `strace` и добавьте исполняемые тесты для full-system runtime режима.",
            )
        )

    if metadata["binary_inventory"]:
        findings.append(
            Finding(
                category="vm-runtime",
                severity="info",
                title="Binary inventory collected",
                description=f"Выявлено {len(metadata['binary_inventory'])} исполняемых артефактов для runtime replay.",
                source="vm-runtime",
                recommendation="Используйте inventory как исходный список для VM, sandbox и replay-профилей.",
            )
        )

    if not metadata["taint_tracking_available"]:
        findings.append(
            Finding(
                category="vm-runtime",
                severity="low",
                title="Taint tracking requires dedicated tooling",
                description="На текущем хосте не найден комплект инструментов для полноценного taint tracking режима.",
                source="vm-runtime",
                recommendation="Для расширенного full-system режима подготовьте QEMU/gdb-профиль или внешний taint backend.",
            )
        )

    return findings, artifacts, logs, metadata
