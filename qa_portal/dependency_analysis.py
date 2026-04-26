from __future__ import annotations

import json
import re
import tempfile
import xml.etree.ElementTree as ET
from itertools import zip_longest
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from .config import DEPENDENCY_SUPPRESSIONS_PATH
from .knowledge_base import load_knowledge_base
from .models import Finding


UNPINNED_MARKERS = ("*", ">", "<", "~", "^")
EXTERNAL_SOURCE_MARKERS = ("git+", "http://", "https://", "file:", "path=", "svn+", "hg+")
IMPORT_PATTERNS = {
    "python": re.compile(r"^\s*(?:from|import)\s+([A-Za-z0-9_\.]+)", re.MULTILINE),
    "node": re.compile(r"""(?:require\(\s*["']([^"']+)["']\s*\)|from\s+["']([^"']+)["'])""", re.MULTILINE),
    "go": re.compile(r'^\s*require\s+([A-Za-z0-9_./\-]+)\s+([vV][^\s]+)', re.MULTILINE),
}


def _component(
    *,
    name: str,
    ecosystem: str,
    manifest: str,
    version: str = "",
    declared_version: str | None = None,
    resolved_version: str = "",
    version_source: str = "manifest",
    scope: str = "runtime",
    license_name: str = "",
    flags: list[str] | None = None,
    direct: bool = True,
) -> dict[str, Any]:
    version_text = version.strip()
    declared_version_text = version_text if declared_version is None else declared_version.strip()
    resolved_version_text = resolved_version.strip()
    normalized_flags = list(flags or [])
    if not version_text or any(marker in version_text for marker in UNPINNED_MARKERS):
        normalized_flags.append("unpinned")
    if any(marker in version_text.casefold() for marker in EXTERNAL_SOURCE_MARKERS):
        normalized_flags.append("external-source")
    return {
        "name": name.strip(),
        "version": version_text,
        "declared_version": declared_version_text,
        "resolved_version": resolved_version_text,
        "effective_version": resolved_version_text or _extract_exact_version(declared_version_text) or version_text,
        "version_source": version_source,
        "ecosystem": ecosystem,
        "manifest": manifest,
        "scope": scope,
        "license": license_name.strip(),
        "direct": direct,
        "flags": sorted(set(flag for flag in normalized_flags if flag)),
    }


def _dedupe_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in components:
        key = (
            item.get("name", ""),
            item.get("version", ""),
            item.get("ecosystem", ""),
            item.get("manifest", ""),
            item.get("scope", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _clean_version_text(value: str) -> str:
    text = str(value or "").strip().strip("'\"")
    text = text.split(";", 1)[0].strip()
    return text


def _extract_exact_version(value: str) -> str:
    text = _clean_version_text(value)
    if not text:
        return ""
    if text.startswith("==="):
        return text[3:].strip()
    if text.startswith("=="):
        return text[2:].strip()
    if text.startswith("="):
        return text[1:].strip()
    if re.fullmatch(r"v?\d+(?:[.\-_+][A-Za-z0-9]+)*", text):
        return text
    return ""


def _split_python_dependency(value: str) -> tuple[str, str]:
    text = _clean_version_text(value)
    match = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(.*)$", text)
    if not match:
        return text, ""
    name, remainder = match.groups()
    return name.strip(), remainder.strip()


def _normalize_version_for_compare(value: str) -> str:
    text = _clean_version_text(value)
    text = re.sub(r"^(?:===|==|~=|>=|<=|>|<|=|\^|~)", "", text).strip()
    if text.casefold().startswith("v") and len(text) > 1:
        text = text[1:]
    return text


def _version_parts(value: str) -> list[tuple[int, Any]]:
    normalized = _normalize_version_for_compare(value)
    if not normalized:
        return []
    parts: list[tuple[int, Any]] = []
    for item in re.split(r"[.\-_+]+", normalized):
        if not item:
            continue
        if item.isdigit():
            parts.append((0, int(item)))
        else:
            parts.append((1, item.casefold()))
    while parts and parts[-1] == (0, 0):
        parts.pop()
    return parts


def _compare_versions(left: str, right: str) -> int:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    for left_part, right_part in zip_longest(left_parts, right_parts, fillvalue=(0, 0)):
        if left_part == right_part:
            continue
        return -1 if left_part < right_part else 1
    return 0


def _upper_bound_for_caret(version: str) -> str:
    normalized = _normalize_version_for_compare(version)
    numbers = [int(item) for item in re.findall(r"\d+", normalized)[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    major, minor, patch = numbers[:3]
    if major > 0:
        return f"{major + 1}.0.0"
    if minor > 0:
        return f"0.{minor + 1}.0"
    return f"0.0.{patch + 1}"


def _upper_bound_for_tilde(version: str) -> str:
    normalized = _normalize_version_for_compare(version)
    numbers = [int(item) for item in re.findall(r"\d+", normalized)[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    major, minor, _patch = numbers[:3]
    return f"{major}.{minor + 1}.0"


def _constraint_clauses(spec: str) -> list[tuple[str, str]]:
    text = _clean_version_text(spec)
    if not text or "||" in text:
        return []
    if text.startswith("^"):
        version = text[1:].strip()
        return [(">=", version), ("<", _upper_bound_for_caret(version))]
    if text.startswith("~"):
        version = text[1:].strip()
        return [(">=", version), ("<", _upper_bound_for_tilde(version))]
    if re.fullmatch(r"v?\d+(?:[.\-_+][A-Za-z0-9]+)*", text):
        return [("==", text)]

    clauses: list[tuple[str, str]] = []
    for token in re.split(r"[,\s]+", text):
        stripped = token.strip()
        if not stripped:
            continue
        match = re.match(r"^(>=|<=|==|=|>|<|~=)?\s*(.+)$", stripped)
        if not match:
            continue
        operator, version = match.groups()
        clauses.append((operator or "==", version.strip()))
    return clauses


def _version_satisfies_spec(spec: str, candidate_version: str) -> bool:
    candidate = _normalize_version_for_compare(candidate_version)
    clauses = _constraint_clauses(spec)
    if not candidate or not clauses:
        return False
    for operator, version in clauses:
        compare = _compare_versions(candidate, version)
        if operator in {"=", "=="} and compare != 0:
            return False
        if operator == ">=" and compare < 0:
            return False
        if operator == "<=" and compare > 0:
            return False
        if operator == ">" and compare <= 0:
            return False
        if operator == "<" and compare >= 0:
            return False
        if operator == "~=":
            lower_ok = compare >= 0
            upper_ok = _compare_versions(candidate, _upper_bound_for_tilde(version)) < 0
            if not (lower_ok and upper_ok):
                return False
    return True


def _parse_requirements(path: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "#egg=" in stripped:
            egg = stripped.split("#egg=", 1)[1].strip()
            components.append(
                _component(
                    name=egg,
                    version=stripped,
                    ecosystem="python",
                    manifest=str(path.relative_to(path.parent.parent if path.parent.parent.exists() else path.parent)),
                    flags=["external-source"],
                )
            )
            continue
        name, version = _split_python_dependency(stripped)
        if not name:
            continue
        components.append(
            _component(
                name=name,
                version=version,
                ecosystem="python",
                manifest=path.name,
            )
        )
    return components


def _parse_go_mod(path: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("module "):
            continue
        match = re.match(r"([A-Za-z0-9_./\\-]+)\s+(v[^\s]+)", stripped)
        if not match:
            continue
        name, version = match.groups()
        components.append(
            _component(
                name=name,
                version=version,
                ecosystem="go",
                manifest=path.name,
            )
        )
    return components


def _parse_package_json(path: Path) -> tuple[list[dict[str, Any]], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    license_name = str(payload.get("license", "") or "")
    components: list[dict[str, Any]] = []
    for section, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ):
        for name, version in (payload.get(section, {}) or {}).items():
            components.append(
                _component(
                    name=name,
                    version=str(version),
                    ecosystem="node",
                    manifest=path.name,
                    scope=scope,
                    license_name=license_name,
                )
            )
    return components, license_name


def _parse_package_lock(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        return []
    components: list[dict[str, Any]] = []
    for package_path, meta in packages.items():
        if package_path == "" or not isinstance(meta, dict):
            continue
        version = str(meta.get("version", "") or "").strip()
        if not version:
            continue
        name = str(meta.get("name") or package_path.rsplit("node_modules/", 1)[-1]).strip()
        if not name:
            continue
        nested_level = package_path.count("node_modules/")
        direct = nested_level <= 1
        scope = "dev" if meta.get("dev") else ("optional" if meta.get("optional") else ("runtime" if direct else "transitive"))
        flags = ["lockfile", "resolved"]
        if not direct:
            flags.append("transitive")
        components.append(
            _component(
                name=name,
                version=version,
                declared_version="",
                resolved_version=version,
                version_source="lockfile",
                ecosystem="node",
                manifest=path.name,
                scope=scope,
                flags=flags,
                direct=direct,
            )
        )
    return components


def _parse_pyproject(path: Path) -> tuple[list[dict[str, Any]], str]:
    if tomllib is None:
        return [], ""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    project = payload.get("project", {}) if isinstance(payload, dict) else {}
    license_name = ""
    if isinstance(project.get("license"), dict):
        license_name = str(project.get("license", {}).get("text", "") or "")
    elif project.get("license"):
        license_name = str(project.get("license"))
    components: list[dict[str, Any]] = []
    for dependency in project.get("dependencies", []) or []:
        name, version = _split_python_dependency(str(dependency))
        components.append(
            _component(
                name=name,
                version=version,
                ecosystem="python",
                manifest=path.name,
                license_name=license_name,
            )
        )
    for extra_name, dependency_list in (project.get("optional-dependencies", {}) or {}).items():
        for dependency in dependency_list:
            name, version = _split_python_dependency(str(dependency))
            components.append(
                _component(
                    name=name,
                    version=version,
                    ecosystem="python",
                    manifest=path.name,
                    scope=f"optional:{extra_name}",
                    license_name=license_name,
                )
            )
    return components, license_name


def _parse_cmake(path: Path) -> list[dict[str, Any]]:
    content = path.read_text(encoding="utf-8", errors="ignore")
    components: list[dict[str, Any]] = []
    for match in re.finditer(r"find_package\s*\(([^)]+)\)", content, flags=re.IGNORECASE | re.MULTILINE):
        tokens = [token for token in re.split(r"\s+", match.group(1).replace("\n", " ").strip()) if token]
        if not tokens:
            continue
        package_name = tokens[0]
        version = ""
        if len(tokens) > 1 and re.match(r"^\d", tokens[1]):
            version = tokens[1]
        if "COMPONENTS" in tokens:
            component_index = tokens.index("COMPONENTS")
            for token in tokens[component_index + 1:]:
                if token in {"REQUIRED", "OPTIONAL_COMPONENTS", "CONFIG", "MODULE"}:
                    break
                components.append(
                    _component(
                        name=f"{package_name}/{token}",
                        version=version,
                        ecosystem="cmake",
                        manifest=path.name,
                    )
                )
        else:
            components.append(
                _component(
                    name=package_name,
                    version=version,
                    ecosystem="cmake",
                    manifest=path.name,
                )
            )
    return components


def _parse_pipfile_lock(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    components: list[dict[str, Any]] = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        entries = payload.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            raw_version = str(meta.get("version", "") or "").strip()
            resolved_version = _extract_exact_version(raw_version)
            components.append(
                _component(
                    name=str(name),
                    version=raw_version,
                    declared_version="",
                    resolved_version=resolved_version,
                    version_source="lockfile",
                    ecosystem="python",
                    manifest=path.name,
                    scope=scope,
                    flags=["lockfile", "resolved"],
                )
            )
    return components


def _parse_poetry_lock(path: Path) -> list[dict[str, Any]]:
    if tomllib is None:
        return []
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("package") or []
    if not isinstance(packages, list):
        return []
    components: list[dict[str, Any]] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        version = str(item.get("version", "") or "").strip()
        if not name or not version:
            continue
        groups = item.get("groups")
        group_values = [str(value) for value in groups] if isinstance(groups, list) else []
        category = str(item.get("category", "") or "")
        if "dev" in group_values or category == "dev":
            scope = "dev"
        elif bool(item.get("optional")):
            scope = "optional"
        else:
            scope = "runtime"
        components.append(
            _component(
                name=name,
                version=version,
                declared_version="",
                resolved_version=version,
                version_source="lockfile",
                ecosystem="python",
                manifest=path.name,
                scope=scope,
                flags=["lockfile", "resolved", "transitive"],
                direct=False,
            )
        )
    return components


def _parse_qmake(path: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped.startswith("QT +="):
            continue
        modules = [token for token in stripped.split("+=", 1)[1].strip().split() if token]
        for module in modules:
            components.append(
                _component(
                    name=f"Qt/{module}",
                    ecosystem="qmake",
                    manifest=path.name,
                )
            )
    return components


def _parse_go_sum(path: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        tokens = line.strip().split()
        if len(tokens) < 2:
            continue
        name, version = tokens[0], tokens[1]
        if version.endswith("/go.mod"):
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        components.append(
            _component(
                name=name,
                version=version,
                declared_version="",
                resolved_version=version,
                version_source="lockfile",
                ecosystem="go",
                manifest=path.name,
                scope="transitive",
                flags=["lockfile", "resolved", "transitive"],
                direct=False,
            )
        )
    return components


def _load_dependency_suppressions() -> list[dict[str, Any]]:
    if not DEPENDENCY_SUPPRESSIONS_PATH.exists():
        return []
    try:
        payload = json.loads(DEPENDENCY_SUPPRESSIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(payload, dict):
        items = payload.get("rules", [])
    else:
        items = payload
    return [item for item in items if isinstance(item, dict)]


def _normalize_suppression_rule(rule: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "ecosystem": str(rule.get("ecosystem", "")).strip(),
        "name": str(rule.get("name", "")).strip(),
        "version": str(rule.get("version", "")).strip(),
        "cve": str(rule.get("cve", "")).strip().upper(),
        "reason": str(rule.get("reason", "")).strip(),
    }
    return {key: value for key, value in normalized.items() if value}


def _normalize_suppression_payload(payload: Any) -> list[dict[str, Any]]:
    rules = payload.get("rules", []) if isinstance(payload, dict) else payload
    if not isinstance(rules, list):
        raise ValueError("Suppression payload must be a list or an object with a rules list.")
    normalized_rules: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for item in rules:
        if not isinstance(item, dict):
            continue
        normalized = _normalize_suppression_rule(item)
        if not normalized:
            continue
        key = (
            normalized.get("ecosystem", ""),
            normalized.get("name", ""),
            normalized.get("version", ""),
            normalized.get("cve", ""),
            normalized.get("reason", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        normalized_rules.append(normalized)
    return normalized_rules


def save_dependency_suppressions(payload: Any) -> dict[str, Any]:
    rules = _normalize_suppression_payload(payload)
    DEPENDENCY_SUPPRESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(DEPENDENCY_SUPPRESSIONS_PATH.parent),
    ) as handle:
        json.dump({"rules": rules}, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(DEPENDENCY_SUPPRESSIONS_PATH)
    return dependency_suppression_status()


def dependency_suppression_status() -> dict[str, Any]:
    rules = _load_dependency_suppressions()
    return {
        "rules": rules,
        "rule_count": len(rules),
        "path": str(DEPENDENCY_SUPPRESSIONS_PATH),
        "source": "file" if DEPENDENCY_SUPPRESSIONS_PATH.exists() else "default",
    }


def _version_tokens(version: str) -> set[str]:
    tokens = {_normalize_token(version)}
    for item in re.split(r"[^A-Za-z0-9]+", version):
        if item:
            tokens.add(_normalize_token(item))
    return {token for token in tokens if token}


def _component_aliases(component: dict[str, Any]) -> set[str]:
    name = str(component.get("name", ""))
    candidates = {
        _normalize_token(name),
        _normalize_token(name.rsplit("/", 1)[-1]),
        _normalize_token(name.split(":")[-1]),
    }
    for token in re.split(r"[/:@._\-]+", name):
        if token:
            candidates.add(_normalize_token(token))
    return {item for item in candidates if item}


def _is_component_reachable(component: dict[str, Any], imports_index: dict[str, set[str]]) -> bool:
    aliases = _component_aliases(component)
    ecosystem = str(component.get("ecosystem", ""))
    ecosystem_key = {
        "python": "python",
        "node": "node",
        "go": "go",
        "cmake": "cmake",
        "qmake": "qmake",
        "maven": "java",
    }.get(ecosystem, ecosystem)
    imported = imports_index.get(ecosystem_key, set()) | imports_index.get("all", set())
    return bool(aliases & imported)


def _imports_index(root: Path) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {"all": set()}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore") if path.stat().st_size <= 256 * 1024 else ""
        if not text:
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            values = {
                _normalize_token(match.split(".", 1)[0])
                for match in IMPORT_PATTERNS["python"].findall(text)
                if match
            }
            index.setdefault("python", set()).update(values)
            index["all"].update(values)
        elif suffix in {".js", ".ts", ".tsx"}:
            values: set[str] = set()
            for match in IMPORT_PATTERNS["node"].findall(text):
                for candidate in match:
                    if candidate:
                        values.add(_normalize_token(candidate.split("/", 1)[0].lstrip("@")))
            index.setdefault("node", set()).update(values)
            index["all"].update(values)
        elif suffix == ".go":
            values = {
                _normalize_token(item.group(1).split("/", 1)[0])
                for item in re.finditer(r'^\s*import\s+(?:\w+\s+)?\"([^\"]+)\"', text, flags=re.MULTILINE)
            }
            index.setdefault("go", set()).update(values)
            index["all"].update(values)
        elif suffix in {".cpp", ".cc", ".cxx", ".h", ".hpp"}:
            includes = {
                _normalize_token(item.group(1).split("/", 1)[0])
                for item in re.finditer(r'#include\s*[<"]([^">]+)[">]', text)
            }
            index.setdefault("cmake", set()).update(includes)
            index.setdefault("qmake", set()).update(includes)
            index["all"].update(includes)
    return index


def _suppression_match(suppression: dict[str, Any], component: dict[str, Any], vulnerability: dict[str, Any]) -> bool:
    if suppression.get("ecosystem") and suppression.get("ecosystem") != component.get("ecosystem"):
        return False
    if suppression.get("name") and _normalize_token(str(suppression.get("name"))) not in _component_aliases(component):
        return False
    if suppression.get("version") and str(suppression.get("version")).strip() != str(component.get("version", "")).strip():
        return False
    identifier = str(vulnerability.get("id", ""))
    if suppression.get("cve") and str(suppression.get("cve")).upper() != identifier.upper():
        return False
    return True


def _component_version_matches(component: dict[str, Any], vulnerability: dict[str, Any]) -> tuple[bool, str]:
    effective_version = str(component.get("effective_version", "")).strip()
    declared_version = str(component.get("declared_version", "")).strip() or str(component.get("version", "")).strip()
    if not effective_version and not declared_version:
        return False, "unknown"
    version_tokens = _version_tokens(effective_version or declared_version)
    cpe_versions = []
    for cpe in vulnerability.get("cpes", []):
        parts = str(cpe).split(":")
        if len(parts) >= 6:
            cpe_versions.append(parts[5])
    for cpe_version in cpe_versions:
        normalized = _normalize_token(cpe_version)
        if not normalized or normalized in {"*", "-"}:
            continue
        if normalized in version_tokens:
            return True, "resolved-exact" if effective_version else "exact"
        if declared_version and _version_satisfies_spec(declared_version, cpe_version):
            return True, "constraint-overlap"
    return False, "heuristic-miss"


def _match_component_vulnerabilities(
    component: dict[str, Any],
    lookup: dict[str, Any],
    *,
    reachable: bool,
    suppressions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    aliases = _component_aliases(component)
    matches: list[dict[str, Any]] = []
    for cve_id, vulnerability in (lookup.get("cve") or {}).items():
        products = {_normalize_token(item) for item in vulnerability.get("products", [])}
        vendors = {_normalize_token(item) for item in vulnerability.get("vendors", [])}
        if not aliases & (products | vendors):
            continue
        version_match, confidence = _component_version_matches(component, vulnerability)
        if not version_match and "unpinned" not in set(component.get("flags", [])):
            continue
        suppression = next((rule for rule in suppressions if _suppression_match(rule, component, vulnerability)), None)
        matches.append(
            {
                "id": cve_id,
                "severity": vulnerability.get("severity", ""),
                "summary": vulnerability.get("summary", ""),
                "kev": bool(vulnerability.get("kev")),
                "bdu_ids": list(vulnerability.get("bdu_ids", [])),
                "cpes": list(vulnerability.get("cpes", []))[:8],
                "sources": list(vulnerability.get("sources", [])),
                "reachable": reachable,
                "confidence": confidence if version_match else "alias-only",
                "suppressed": bool(suppression),
                "suppression_reason": str((suppression or {}).get("reason", "")),
            }
        )
    matches.sort(key=lambda item: (not item["reachable"], not item["kev"], item["id"]))
    return matches[:12]


def _component_key(component: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(component.get("ecosystem", "")),
        str(component.get("name", "")),
        str(component.get("scope", "")),
    )


def _active_component_vulnerabilities(component: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in component.get("vulnerabilities", []) if not item.get("suppressed")]


def _active_vulnerability_ids(component: dict[str, Any]) -> set[str]:
    return {str(item.get("id", "")).strip() for item in _active_component_vulnerabilities(component) if str(item.get("id", "")).strip()}


def _has_reachable_vulnerability(component: dict[str, Any]) -> bool:
    if not component.get("reachable"):
        return False
    return bool(_active_component_vulnerabilities(component))


def _has_kev_vulnerability(component: dict[str, Any]) -> bool:
    return any(bool(item.get("kev")) for item in _active_component_vulnerabilities(component))


def _top_vulnerable_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(
        (component for component in components if _active_component_vulnerabilities(component)),
        key=lambda item: (
            not _has_kev_vulnerability(item),
            not bool(item.get("reachable")),
            -len(_active_component_vulnerabilities(item)),
            str(item.get("name", "")),
        ),
    )
    summary: list[dict[str, Any]] = []
    for component in ranked[:12]:
        active_vulnerabilities = _active_component_vulnerabilities(component)
        summary.append(
            {
                "name": component.get("name", ""),
                "ecosystem": component.get("ecosystem", ""),
                "scope": component.get("scope", ""),
                "manifest": component.get("manifest", ""),
                "version": component.get("effective_version", "") or component.get("version", ""),
                "reachable": bool(component.get("reachable")),
                "active_vulnerability_count": len(active_vulnerabilities),
                "kev_count": sum(1 for item in active_vulnerabilities if item.get("kev")),
                "bdu_ids": sorted({bdu for item in active_vulnerabilities for bdu in item.get("bdu_ids", []) if str(bdu).strip()})[:10],
                "cve_ids": [str(item.get("id", "")).strip() for item in active_vulnerabilities if str(item.get("id", "")).strip()][:10],
                "sources": sorted({source for item in active_vulnerabilities for source in item.get("sources", []) if str(source).strip()}),
                "suppressed_count": sum(1 for item in component.get("vulnerabilities", []) if item.get("suppressed")),
            }
        )
    return summary


# Строим baseline-aware diff для release gate и отчётов: новые, исправленные и ухудшившиеся зависимости.
def compare_dependency_inventory(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    current_components = {_component_key(item): item for item in current.get("components", [])}
    current_vulnerable_keys = sorted(key for key, item in current_components.items() if _active_component_vulnerabilities(item))
    current_reachable_vulnerable_keys = sorted(key for key, item in current_components.items() if _has_reachable_vulnerability(item))
    if not baseline:
        return {
            "baseline_available": False,
            "added_components": [],
            "added_count": 0,
            "removed_components": [],
            "removed_count": 0,
            "version_changed_components": [],
            "version_changed_count": 0,
            "new_vulnerable_components": [],
            "new_vulnerable_count": 0,
            "fixed_vulnerable_components": [],
            "fixed_vulnerable_count": 0,
            "new_reachable_vulnerable_components": [],
            "new_reachable_vulnerable_count": 0,
            "fixed_reachable_vulnerable_components": [],
            "fixed_reachable_vulnerable_count": 0,
            "worsened_components": [],
            "dependency_regression_count": 0,
            "current_vulnerable_count": len(current_vulnerable_keys),
            "baseline_vulnerable_count": 0,
            "vulnerability_count_delta": 0,
            "current_reachable_vulnerable_count": len(current_reachable_vulnerable_keys),
            "baseline_reachable_vulnerable_count": 0,
            "reachable_vulnerability_count_delta": 0,
        }

    baseline_components = {_component_key(item): item for item in baseline.get("components", [])}

    added_keys = sorted(set(current_components) - set(baseline_components))
    removed_keys = sorted(set(baseline_components) - set(current_components))
    changed_keys = sorted(
        key for key in (set(current_components) & set(baseline_components))
        if str(current_components[key].get("effective_version", "") or current_components[key].get("version", ""))
        != str(baseline_components[key].get("effective_version", "") or baseline_components[key].get("version", ""))
    )

    baseline_vulnerable = {_component_key(item) for item in baseline.get("components", []) if _active_component_vulnerabilities(item)}
    baseline_reachable_vulnerable = {
        _component_key(item) for item in baseline.get("components", []) if _has_reachable_vulnerability(item)
    }
    new_vulnerable_keys = sorted(
        key
        for key, component in current_components.items()
        if _active_component_vulnerabilities(component) and key not in baseline_vulnerable
    )
    fixed_vulnerable_keys = sorted(key for key in baseline_vulnerable if key not in set(current_vulnerable_keys))
    new_reachable_vulnerable_keys = sorted(key for key in current_reachable_vulnerable_keys if key not in baseline_reachable_vulnerable)
    fixed_reachable_vulnerable_keys = sorted(key for key in baseline_reachable_vulnerable if key not in set(current_reachable_vulnerable_keys))

    worsened_components: list[dict[str, Any]] = []
    for key in sorted(set(current_components) & set(baseline_components)):
        current_component = current_components[key]
        baseline_component = baseline_components[key]
        current_active_ids = _active_vulnerability_ids(current_component)
        baseline_active_ids = _active_vulnerability_ids(baseline_component)
        if not current_active_ids or not baseline_active_ids:
            continue
        new_ids = sorted(current_active_ids - baseline_active_ids)
        became_reachable = _has_reachable_vulnerability(current_component) and not _has_reachable_vulnerability(baseline_component)
        kev_regression = _has_kev_vulnerability(current_component) and not _has_kev_vulnerability(baseline_component)
        if not (new_ids or became_reachable or kev_regression):
            continue
        worsened_components.append(
            {
                "ecosystem": key[0],
                "name": key[1],
                "scope": key[2],
                "baseline_version": baseline_component.get("effective_version", "") or baseline_component.get("version", ""),
                "current_version": current_component.get("effective_version", "") or current_component.get("version", ""),
                "baseline_vulnerability_count": len(baseline_active_ids),
                "current_vulnerability_count": len(current_active_ids),
                "new_vulnerability_ids": new_ids[:10],
                "became_reachable": became_reachable,
                "kev_regression": kev_regression,
            }
        )

    return {
        "baseline_available": True,
        "added_components": [current_components[key] for key in added_keys][:20],
        "added_count": len(added_keys),
        "removed_components": [baseline_components[key] for key in removed_keys][:20],
        "removed_count": len(removed_keys),
        "version_changed_components": [
            {
                "ecosystem": key[0],
                "name": key[1],
                "scope": key[2],
                "baseline_version": baseline_components[key].get("effective_version", "") or baseline_components[key].get("version", ""),
                "current_version": current_components[key].get("effective_version", "") or current_components[key].get("version", ""),
            }
            for key in changed_keys[:20]
        ],
        "version_changed_count": len(changed_keys),
        "new_vulnerable_components": [current_components[key] for key in new_vulnerable_keys[:20]],
        "new_vulnerable_count": len(new_vulnerable_keys),
        "fixed_vulnerable_components": [baseline_components[key] for key in fixed_vulnerable_keys[:20]],
        "fixed_vulnerable_count": len(fixed_vulnerable_keys),
        "new_reachable_vulnerable_components": [current_components[key] for key in new_reachable_vulnerable_keys[:20]],
        "new_reachable_vulnerable_count": len(new_reachable_vulnerable_keys),
        "fixed_reachable_vulnerable_components": [baseline_components[key] for key in fixed_reachable_vulnerable_keys[:20]],
        "fixed_reachable_vulnerable_count": len(fixed_reachable_vulnerable_keys),
        "worsened_components": worsened_components[:20],
        "dependency_regression_count": len(worsened_components),
        "current_vulnerable_count": len(current_vulnerable_keys),
        "baseline_vulnerable_count": len(baseline_vulnerable),
        "vulnerability_count_delta": len(current_vulnerable_keys) - len(baseline_vulnerable),
        "current_reachable_vulnerable_count": len(current_reachable_vulnerable_keys),
        "baseline_reachable_vulnerable_count": len(baseline_reachable_vulnerable),
        "reachable_vulnerability_count_delta": len(current_reachable_vulnerable_keys) - len(baseline_reachable_vulnerable),
    }


def _parse_pom(path: Path) -> tuple[list[dict[str, Any]], str]:
    root = ET.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"
    components: list[dict[str, Any]] = []
    license_name = ""
    for license_entry in root.findall(f".//{namespace}licenses/{namespace}license/{namespace}name"):
        if license_entry.text:
            license_name = license_entry.text.strip()
            break
    for dependency in root.findall(f".//{namespace}dependencies/{namespace}dependency"):
        group = dependency.findtext(f"{namespace}groupId", default="").strip()
        artifact = dependency.findtext(f"{namespace}artifactId", default="").strip()
        version = dependency.findtext(f"{namespace}version", default="").strip()
        scope = dependency.findtext(f"{namespace}scope", default="runtime").strip() or "runtime"
        if not artifact:
            continue
        components.append(
            _component(
                name=f"{group}:{artifact}" if group else artifact,
                version=version,
                ecosystem="maven",
                manifest=path.name,
                scope=scope,
                license_name=license_name,
            )
        )
    return components, license_name


def _resolved_match_candidates(component: dict[str, Any]) -> list[tuple[str, str, str]]:
    ecosystem = str(component.get("ecosystem", ""))
    name = str(component.get("name", ""))
    scope = str(component.get("scope", "runtime"))
    candidates = [(ecosystem, name, scope)]
    if scope == "runtime":
        candidates.append((ecosystem, name, "transitive"))
    if scope.startswith("optional"):
        candidates.append((ecosystem, name, "optional"))
        candidates.append((ecosystem, name, "transitive"))
    return candidates


def _merge_declared_and_resolved(
    declared_components: list[dict[str, Any]],
    resolved_components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resolved_index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for component in resolved_components:
        key = (
            str(component.get("ecosystem", "")),
            str(component.get("name", "")),
            str(component.get("scope", "")),
        )
        resolved_index.setdefault(key, []).append(component)

    matched_keys: set[int] = set()
    merged: list[dict[str, Any]] = []
    for component in declared_components:
        match: dict[str, Any] | None = None
        match_index: int | None = None
        for candidate_key in _resolved_match_candidates(component):
            candidate_list = resolved_index.get(candidate_key, [])
            for index, candidate in enumerate(candidate_list):
                if id(candidate) in matched_keys:
                    continue
                match = candidate
                match_index = id(candidate)
                break
            if match is not None:
                break

        merged_component = dict(component)
        if match is not None and match_index is not None:
            matched_keys.add(match_index)
            resolved_version = str(match.get("resolved_version", "") or match.get("version", "")).strip()
            merged_component["resolved_version"] = resolved_version
            merged_component["effective_version"] = resolved_version or merged_component.get("effective_version", "")
            merged_component["version_source"] = str(match.get("manifest", "lockfile"))
            merged_component["flags"] = sorted(
                set(component.get("flags", []))
                | set(match.get("flags", []))
                | {"resolved"}
            )
            if not match.get("direct", True):
                merged_component["flags"] = sorted(set(merged_component["flags"]) | {"transitive"})
        merged.append(merged_component)

    for component in resolved_components:
        if id(component) in matched_keys:
            continue
        merged.append(component)
    return _dedupe_components(merged)


# Формируем SBOM, локальный SCA-слой и diff относительно baseline без внешней сети.
def analyze_dependencies(
    root: Path,
    *,
    knowledge_lookup: dict[str, Any] | None = None,
    baseline_inventory: dict[str, Any] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    manifest_paths = [
        *root.rglob("requirements.txt"),
        *root.rglob("package.json"),
        *root.rglob("package-lock.json"),
        *root.rglob("pyproject.toml"),
        *root.rglob("Pipfile.lock"),
        *root.rglob("poetry.lock"),
        *root.rglob("go.mod"),
        *root.rglob("go.sum"),
        *root.rglob("pom.xml"),
        *root.rglob("CMakeLists.txt"),
        *root.rglob("*.pro"),
    ]
    declared_components: list[dict[str, Any]] = []
    resolved_components: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    findings: list[Finding] = []
    license_gaps: list[str] = []

    lookup = knowledge_lookup if knowledge_lookup is not None else load_knowledge_base()
    suppressions = _load_dependency_suppressions()
    imports_index = _imports_index(root)

    for path in sorted({item for item in manifest_paths if item.is_file()}):
        relative = str(path.relative_to(root))
        parsed_components: list[dict[str, Any]] = []
        declared_license = ""
        role = "manifest"
        if path.name == "requirements.txt":
            parsed_components = _parse_requirements(path)
        elif path.name == "package.json":
            parsed_components, declared_license = _parse_package_json(path)
        elif path.name == "package-lock.json":
            parsed_components = _parse_package_lock(path)
            role = "lockfile"
        elif path.name == "pyproject.toml":
            parsed_components, declared_license = _parse_pyproject(path)
        elif path.name == "Pipfile.lock":
            parsed_components = _parse_pipfile_lock(path)
            role = "lockfile"
        elif path.name == "poetry.lock":
            parsed_components = _parse_poetry_lock(path)
            role = "lockfile"
        elif path.name == "go.mod":
            parsed_components = _parse_go_mod(path)
        elif path.name == "go.sum":
            parsed_components = _parse_go_sum(path)
            role = "lockfile"
        elif path.name == "pom.xml":
            parsed_components, declared_license = _parse_pom(path)
        elif path.name == "CMakeLists.txt":
            parsed_components = _parse_cmake(path)
        elif path.suffix.lower() == ".pro":
            parsed_components = _parse_qmake(path)

        if parsed_components and not declared_license and path.name in {"package.json", "pyproject.toml", "pom.xml"}:
            license_gaps.append(relative)

        manifests.append(
            {
                "path": relative,
                "kind": path.name,
                "role": role,
                "component_count": len(parsed_components),
                "license": declared_license,
            }
        )
        destination = resolved_components if role == "lockfile" else declared_components
        destination.extend([{**component, "manifest": relative} for component in parsed_components])

    components = _merge_declared_and_resolved(_dedupe_components(declared_components), _dedupe_components(resolved_components))
    vulnerable_components = 0
    reachable_vulnerable_components = 0
    suppressed_vulnerabilities = 0
    resolved_components_count = 0
    transitive_components_count = 0
    lockfile_count = sum(1 for manifest in manifests if manifest.get("role") == "lockfile")
    ecosystem_counts: dict[str, int] = {}
    flag_counts: dict[str, int] = {}
    for component in components:
        ecosystem = str(component.get("ecosystem", "unknown"))
        ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
        for flag in component.get("flags", []):
            flag_counts[flag] = flag_counts.get(flag, 0) + 1
        if component.get("resolved_version"):
            resolved_components_count += 1
        if "transitive" in set(component.get("flags", [])):
            transitive_components_count += 1
        reachable = _is_component_reachable(component, imports_index)
        component["reachable"] = reachable
        component["vulnerabilities"] = _match_component_vulnerabilities(
            component,
            lookup,
            reachable=reachable,
            suppressions=suppressions,
        )
        if component["vulnerabilities"]:
            vulnerable_components += 1
            if reachable:
                reachable_vulnerable_components += 1
        suppressed_vulnerabilities += sum(1 for item in component["vulnerabilities"] if item.get("suppressed"))

    unpinned_by_manifest: dict[str, int] = {}
    external_by_manifest: dict[str, int] = {}
    for component in components:
        manifest = str(component.get("manifest", ""))
        flags = set(component.get("flags", []))
        if "unpinned" in flags:
            unpinned_by_manifest[manifest] = unpinned_by_manifest.get(manifest, 0) + 1
        if "external-source" in flags:
            external_by_manifest[manifest] = external_by_manifest.get(manifest, 0) + 1

    for manifest, count in sorted(unpinned_by_manifest.items()):
        findings.append(
            Finding(
                category="dependency",
                severity="medium",
                title="Unpinned dependency constraints",
                description=f"Found {count} dependency entries without exact version pinning in {manifest}.",
                path=manifest,
                source="dependency-inventory",
                recommendation="Pin production dependencies to reviewed versions before release.",
            )
        )

    for manifest, count in sorted(external_by_manifest.items()):
        findings.append(
            Finding(
                category="dependency",
                severity="medium",
                title="External dependency source detected",
                description=f"Found {count} dependency entries that reference external URLs or VCS locations in {manifest}.",
                path=manifest,
                source="dependency-inventory",
                recommendation="Mirror critical dependencies internally and review the trust chain before release.",
            )
        )

    for manifest in license_gaps:
        findings.append(
            Finding(
                category="dependency",
                severity="low",
                title="Dependency manifest without declared license metadata",
                description=f"The manifest {manifest} defines dependencies but does not expose clear package license metadata.",
                path=manifest,
                source="dependency-inventory",
                recommendation="Add or verify license information to simplify compliance review.",
            )
        )

    for component in components:
        active_vulnerabilities = [item for item in component.get("vulnerabilities", []) if not item.get("suppressed")]
        if not active_vulnerabilities:
            continue
        top = active_vulnerabilities[0]
        severity = "critical" if top.get("kev") else ("high" if component.get("reachable") else "medium")
        findings.append(
            Finding(
                category="dependency",
                severity=severity,  # type: ignore[arg-type]
                title="Vulnerable dependency candidate",
                description=(
                    f"Dependency {component.get('name')} "
                    f"{component.get('effective_version') or component.get('version') or '(unpinned)'} "
                    f"matches local vulnerability references: {', '.join(item['id'] for item in active_vulnerabilities[:4])}."
                ),
                path=str(component.get("manifest", "")),
                source="dependency-sca",
                recommendation=(
                    "Review the matched CVE/KEV/FSTEC records, update the component, "
                    "or add a documented suppression when the risk is accepted."
                ),
            )
        )

    if len(ecosystem_counts) > 1 and components:
        findings.append(
            Finding(
                category="dependency",
                severity="info",
                title="Multi-ecosystem dependency surface",
                description=(
                    "Dependencies were discovered across multiple build or package ecosystems: "
                    + ", ".join(sorted(ecosystem_counts))
                    + "."
                ),
                source="dependency-inventory",
                recommendation="Review each dependency ecosystem separately for pinning, provenance, and update policy.",
            )
        )

    dependency_diff = compare_dependency_inventory(
        {
            "components": components,
        },
        baseline_inventory,
    )
    if dependency_diff.get("new_vulnerable_count", 0):
        findings.append(
            Finding(
                category="dependency",
                severity="high",
                title="New vulnerable dependencies introduced",
                description=(
                    f"Baseline comparison found {dependency_diff.get('new_vulnerable_count', 0)} "
                    "new components with local vulnerability matches."
                ),
                source="dependency-diff",
                recommendation="Block release until the new vulnerable dependencies are updated or explicitly suppressed.",
            )
        )

    sbom = {
        "schema": "scanforge-sbom-v1",
        "component_count": len(components),
        "manifest_count": len(manifests),
        "lockfile_count": lockfile_count,
        "ecosystem_counts": ecosystem_counts,
        "flag_counts": flag_counts,
        "manifests": manifests,
        "components": components,
        "license_gap_count": len(license_gaps),
        "resolved_component_count": resolved_components_count,
        "transitive_component_count": transitive_components_count,
        "vulnerable_component_count": vulnerable_components,
        "reachable_vulnerable_component_count": reachable_vulnerable_components,
        "suppressed_vulnerability_count": suppressed_vulnerabilities,
        "suppression_rule_count": len(suppressions),
        "top_vulnerable_components": _top_vulnerable_components(components),
        "dependency_diff": dependency_diff,
    }
    return findings, sbom
