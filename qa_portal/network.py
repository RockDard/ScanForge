from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def _split_host_port(value: str) -> tuple[str, str]:
    normalized = value.strip()
    if not normalized:
        return "", ""
    if normalized.startswith("[") and "]" in normalized:
        host, _, rest = normalized[1:].partition("]")
        return host.casefold(), rest.removeprefix(":")
    host, separator, port = normalized.partition(":")
    return host.casefold(), port if separator else ""


def configured_allowed_hosts() -> list[str]:
    return _env_list("QA_PORTAL_ALLOWED_HOSTS")


def configured_cors_origins() -> list[str]:
    return _env_list("QA_PORTAL_CORS_ORIGINS")


def cors_allow_credentials() -> bool:
    return _env_bool("QA_PORTAL_CORS_ALLOW_CREDENTIALS", False)


def host_allowed(host_header: str) -> bool:
    allowed_hosts = configured_allowed_hosts()
    if not allowed_hosts:
        return True
    if "*" in allowed_hosts:
        return True

    request_host, request_port = _split_host_port(host_header)
    for allowed in allowed_hosts:
        allowed_host, allowed_port = _split_host_port(allowed)
        if not allowed_host:
            continue
        if allowed_host.startswith("*.") and request_host.endswith(allowed_host[1:]):
            if not allowed_port or allowed_port == request_port:
                return True
            continue
        if request_host == allowed_host and (not allowed_port or allowed_port == request_port):
            return True
    return False


def origin_allowed(origin: str) -> bool:
    allowed_origins = configured_cors_origins()
    if not origin or not allowed_origins:
        return False
    if "*" in allowed_origins:
        return True
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc:
        return False
    normalized = f"{parsed.scheme}://{parsed.netloc}".casefold()
    return normalized in {item.rstrip("/").casefold() for item in allowed_origins}


def cors_headers(origin: str, request_headers: str = "") -> dict[str, str]:
    if not origin_allowed(origin):
        return {}
    origins = configured_cors_origins()
    allow_credentials = cors_allow_credentials()
    allow_origin = "*" if "*" in origins and not allow_credentials else origin
    headers = {
        "Access-Control-Allow-Origin": allow_origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": request_headers or "Authorization, Content-Type",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin",
    }
    if allow_credentials:
        headers["Access-Control-Allow-Credentials"] = "true"
    return headers


def _address_payload(address: str) -> dict[str, Any] | None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_unspecified:
        return None
    return {
        "address": str(parsed),
        "family": "ipv6" if parsed.version == 6 else "ipv4",
        "private": parsed.is_private,
        "link_local": parsed.is_link_local,
    }


def local_network_addresses() -> list[dict[str, Any]]:
    addresses: dict[str, dict[str, Any]] = {}

    hostnames = {socket.gethostname(), socket.getfqdn()}
    for hostname in sorted(item for item in hostnames if item):
        try:
            for info in socket.getaddrinfo(hostname, None):
                payload = _address_payload(str(info[4][0]))
                if payload:
                    addresses[payload["address"]] = payload
        except OSError:
            continue

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("1.1.1.1", 80))
            payload = _address_payload(probe.getsockname()[0])
            if payload:
                addresses[payload["address"]] = payload
    except OSError:
        pass

    return sorted(addresses.values(), key=lambda item: (item["family"], item["address"]))


def network_access_status(*, host: str | None = None, port: int | str | None = None) -> dict[str, Any]:
    bind_host = (host if host is not None else os.environ.get("QA_PORTAL_HOST", "0.0.0.0")).strip() or "0.0.0.0"
    try:
        bind_port = int(port if port is not None else os.environ.get("QA_PORTAL_PORT", "8000"))
    except (TypeError, ValueError):
        bind_port = 8000
    addresses = local_network_addresses()
    network_bind = bind_host in {"0.0.0.0", "::", "::0", "[::]"}
    allowed_hosts = configured_allowed_hosts()
    cors_origins = configured_cors_origins()
    urls = [
        f"http://{item['address']}:{bind_port}"
        for item in addresses
        if item["family"] == "ipv4" or ":" not in item["address"]
    ]
    warnings: list[str] = []
    if network_bind and not allowed_hosts:
        warnings.append("Network bind is enabled but QA_PORTAL_ALLOWED_HOSTS is not configured.")
    if cors_origins and not allowed_hosts:
        warnings.append("CORS origins are configured while allowed hosts remain open.")
    return {
        "bind_host": bind_host,
        "bind_port": bind_port,
        "network_bind": network_bind,
        "browser_url": f"http://127.0.0.1:{bind_port}",
        "lan_urls": urls if network_bind else [],
        "addresses": addresses,
        "allowed_hosts": allowed_hosts,
        "allowed_hosts_configured": bool(allowed_hosts),
        "cors_origins": cors_origins,
        "cors_enabled": bool(cors_origins),
        "cors_allow_credentials": cors_allow_credentials(),
        "warnings": warnings,
    }
