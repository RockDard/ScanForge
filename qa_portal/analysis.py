from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import textwrap
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .config import (
    KEEP_UPLOADS,
    KEEP_WORKSPACE,
    MAX_ARCHIVE_FILE_COUNT,
    MAX_ARCHIVE_TOTAL_BYTES,
    MAX_TEXT_FILE_SIZE,
)
from .hardware import AdaptiveExecutionPlan, build_runtime_env
from .models import Artifact, Finding
from .parser_security import ParserSecurityFinding, analyze_parser_security
from .tooling import run_command


# Расширяем набор распознаваемых текстовых файлов, чтобы видеть полиглотные проекты целиком.
SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".qml",
    ".pro",
    ".pri",
    ".cmake",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".mod",
    ".sum",
    ".lock",
    ".xml",
    ".md",
    ".sh",
    ".java",
    ".rs",
    ".go",
    ".cs",
    ".m",
    ".mm",
    ".ui",
    ".txt",
}
SPECIAL_TEXT_FILENAMES = {
    "CMakeLists.txt",
    "Dockerfile",
    "Pipfile",
    "conftest.py",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "tsconfig.json",
    "yarn.lock",
}
BUILD_MANIFEST_FILENAMES = {
    "CMakeLists.txt",
    "Pipfile",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "pytest.ini",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "tsconfig.json",
    "yarn.lock",
}
BUILD_MANIFEST_SUFFIXES = {".pro", ".pri", ".cmake"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "build",
    "out",
    "dist",
    "node_modules",
    "__pycache__",
    ".idea",
    ".vscode",
}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SECURITY_PATTERNS = [
    (r"\bgets\s*\(", "critical", "Unsafe input API", "Replace gets() with a bounded alternative."),
    (r"\bstrcpy\s*\(", "high", "Potential buffer overflow", "Prefer strncpy_s, std::string, or checked copy helpers."),
    (r"\bstrcat\s*\(", "high", "Potential buffer overflow", "Use safer concatenation with explicit bounds."),
    (r"\bsprintf\s*\(", "high", "Unbounded formatted write", "Use snprintf or fmt-style APIs."),
    (r"\bvsprintf\s*\(", "high", "Unbounded formatted write", "Use vsnprintf or a bounded wrapper."),
    (r"\bmktemp\s*\(", "high", "Insecure temporary file use", "Use mkstemp or platform secure temp helpers."),
    (r"\bsystem\s*\(", "medium", "Shell execution", "Validate inputs and prefer direct process APIs."),
    (r"\bpopen\s*\(", "medium", "Shell pipeline execution", "Avoid shell interpretation where possible."),
    (r"\brand\s*\(", "low", "Weak randomness", "Use a stronger RNG for security-sensitive behavior."),
    (
        r"(password|passwd|secret|token)\s*[:=]\s*[\"'][^\"']+[\"']",
        "high",
        "Possible hard-coded secret",
        "Move secrets to secure configuration or secret storage.",
    ),
]
SECURITY_REFERENCES_BY_TITLE = {
    "Unsafe input API": ("CWE-242", "OWASP-A03"),
    "Potential buffer overflow": ("CWE-120", "OWASP-A03"),
    "Unbounded formatted write": ("CWE-120", "OWASP-A03"),
    "Insecure temporary file use": ("CWE-377",),
    "Shell execution": ("CWE-78", "OWASP-A03"),
    "Shell pipeline execution": ("CWE-78", "OWASP-A03"),
    "Weak randomness": ("CWE-338",),
    "Possible hard-coded secret": ("CWE-798", "OWASP-A02"),
    "Qt TLS verification bypass": ("CWE-295", "OWASP-A02"),
    "Qt process launch through shell": ("CWE-78", "OWASP-A03"),
    "Python eval execution": ("CWE-95", "OWASP-A03"),
    "Python exec execution": ("CWE-95", "OWASP-A03"),
    "Python shell=True": ("CWE-78", "OWASP-A03"),
    "Unsafe pickle deserialization": ("CWE-502", "OWASP-A08"),
    "Unsafe YAML deserialization": ("CWE-502", "OWASP-A08"),
    "Python debug server enabled": ("CWE-489", "OWASP-A05"),
    "JavaScript eval execution": ("CWE-95", "OWASP-A03"),
    "Dynamic Function constructor": ("CWE-95", "OWASP-A03"),
    "Node child_process exec": ("CWE-78", "OWASP-A03"),
    "Node VM dynamic code execution": ("CWE-94", "OWASP-A03"),
    "Go shell command execution": ("CWE-78", "OWASP-A03"),
    "Go HTTP server without explicit middleware": ("CWE-400", "OWASP-A05"),
    "Shell downloads piped to interpreter": ("CWE-494", "OWASP-A08"),
    "SQL query built with string interpolation": ("CWE-89", "OWASP-A03"),
    "Permissive CORS policy": ("CWE-942", "OWASP-A05"),
    "Container runs as root": ("CWE-250", "OWASP-A05"),
    "Container image uses default root user": ("CWE-250", "OWASP-A05"),
    "User-controlled data reaches shell execution": ("CWE-78", "OWASP-A03"),
    "User-controlled data reaches dynamic code execution": ("CWE-95", "OWASP-A03"),
    "User-controlled data reaches SQL query construction": ("CWE-89", "OWASP-A03"),
}
SECURITY_REFERENCE_CATALOG = {
    "CWE-78": ("OS Command Injection", "https://cwe.mitre.org/data/definitions/78.html"),
    "CWE-89": ("SQL Injection", "https://cwe.mitre.org/data/definitions/89.html"),
    "CWE-94": ("Code Injection", "https://cwe.mitre.org/data/definitions/94.html"),
    "CWE-95": ("Eval Injection", "https://cwe.mitre.org/data/definitions/95.html"),
    "CWE-120": ("Classic Buffer Overflow", "https://cwe.mitre.org/data/definitions/120.html"),
    "CWE-242": ("Use of Inherently Dangerous Function", "https://cwe.mitre.org/data/definitions/242.html"),
    "CWE-250": ("Execution with Unnecessary Privileges", "https://cwe.mitre.org/data/definitions/250.html"),
    "CWE-295": ("Improper Certificate Validation", "https://cwe.mitre.org/data/definitions/295.html"),
    "CWE-338": ("Weak PRNG", "https://cwe.mitre.org/data/definitions/338.html"),
    "CWE-377": ("Insecure Temporary File", "https://cwe.mitre.org/data/definitions/377.html"),
    "CWE-400": ("Uncontrolled Resource Consumption", "https://cwe.mitre.org/data/definitions/400.html"),
    "CWE-489": ("Active Debug Code", "https://cwe.mitre.org/data/definitions/489.html"),
    "CWE-494": ("Download of Code Without Integrity Check", "https://cwe.mitre.org/data/definitions/494.html"),
    "CWE-502": ("Deserialization of Untrusted Data", "https://cwe.mitre.org/data/definitions/502.html"),
    "CWE-798": ("Hard-coded Credentials", "https://cwe.mitre.org/data/definitions/798.html"),
    "CWE-942": ("Permissive Cross-domain Policy", "https://cwe.mitre.org/data/definitions/942.html"),
    "OWASP-A02": ("OWASP A02 Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "OWASP-A03": ("OWASP A03 Injection", "https://owasp.org/Top10/A03_2021-Injection/"),
    "OWASP-A05": ("OWASP A05 Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "OWASP-A08": ("OWASP A08 Software and Data Integrity Failures", "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
}
QT_IGNORE_SSL_PATTERN = re.compile(r"\b(?:ignoreSslErrors|setPeerVerifyMode\s*\(\s*QSslSocket::VerifyNone)", re.IGNORECASE)
QT_PROCESS_SHELL_PATTERN = re.compile(
    r"\bQProcess::(?:start|startDetached)\s*\([^)]*(?:\"(?:/bin/)?sh\"|\"bash\"|\"cmd(?:\.exe)?\"|\"powershell(?:\.exe)?\")",
    re.IGNORECASE,
)
QT_SIGNAL_SLOT_PATTERN = re.compile(r"\bSIGNAL\s*\(|\bSLOT\s*\(", re.IGNORECASE)
QT_OBJECT_WITHOUT_PARENT_PATTERN = re.compile(
    r"\bnew\s+(?:QObject|QWidget|QDialog|QMainWindow|QNetworkAccessManager)\s*\(\s*\)",
    re.IGNORECASE,
)
QML_DEBUG_PATTERN = re.compile(r"\bQT_QML_DEBUG\b|\bqmlscene\b", re.IGNORECASE)
TRANSLATION_BYPASS_PATTERN = re.compile(
    r"\b(?:setText|setWindowTitle|setTitle|showMessage)\s*\([^)]*\"[^\"]{3,}\"|^\s*text\s*:\s*\"[^\"]{3,}\"",
    re.MULTILINE,
)
CODE_FRAGMENT_KEYWORDS = re.compile(
    r"\b("
    r"if|else|for|while|switch|case|return|class|struct|namespace|template|typedef|using|const|auto|void|"
    r"int|char|float|double|bool|QString|QObject|QWidget|signals|slots|public|private|protected"
    r")\b"
)
FUNCTION_LIKE_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_:<>]*\s*\(")
DECLARATION_LIKE_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_:<>*&]+\s+[A-Za-z_][A-Za-z0-9_]*\s*(=|;)")
PYTHON_TEST_PATTERN = re.compile(r"\b(import\s+pytest|from\s+pytest\b|unittest\.TestCase\b|def\s+test_[A-Za-z0-9_]*\s*\()", re.MULTILINE)
GO_TEST_PATTERN = re.compile(r"\bfunc\s+Test[A-Za-z0-9_]*\s*\(", re.MULTILINE)
JS_TEST_PATTERN = re.compile(r"\b(?:describe|it|test)\s*\(", re.MULTILINE)
DEFAULT_NPM_TEST_PATTERN = re.compile(r"echo\s+[\"']?Error:\s+no test specified", re.IGNORECASE)
LANGUAGE_BY_SUFFIX = {
    ".c": "C/C++",
    ".cc": "C/C++",
    ".cpp": "C/C++",
    ".cxx": "C/C++",
    ".h": "C/C++",
    ".hh": "C/C++",
    ".hpp": "C/C++",
    ".hxx": "C/C++",
    ".qml": "QML",
    ".pro": "QMake",
    ".pri": "QMake",
    ".cmake": "CMake",
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".json": "JSON",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".xml": "XML",
    ".md": "Markdown",
    ".sh": "Shell",
    ".java": "Java",
    ".rs": "Rust",
    ".go": "Go",
    ".cs": "C#",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".ui": "Qt Designer UI",
}
LANGUAGE_BY_FILENAME = {
    "cmakelists.txt": "CMake",
    "dockerfile": "Docker",
    "go.mod": "Go",
    "package.json": "JavaScript",
    "pyproject.toml": "Python",
    "setup.py": "Python",
    "setup.cfg": "Python",
    "tox.ini": "Python",
    "pytest.ini": "Python",
}
PROGRAMMING_LANGUAGES = {
    "C/C++",
    "QML",
    "Python",
    "JavaScript",
    "TypeScript",
    "Java",
    "Rust",
    "Go",
    "C#",
    "Objective-C",
    "Objective-C++",
}


class ExtractionError(RuntimeError):
    pass


def _ensure_safe_archive_path(destination_root: Path, member_name: str) -> Path:
    target = destination_root / member_name
    try:
        target.resolve().relative_to(destination_root.resolve())
    except ValueError as exc:
        raise ExtractionError(f"Archive entry escapes extraction root: {member_name}") from exc
    return target


def _validate_archive_limits(entry_count: int, total_bytes: int) -> None:
    if entry_count > MAX_ARCHIVE_FILE_COUNT:
        raise ExtractionError(
            f"Archive contains too many files ({entry_count}); limit is {MAX_ARCHIVE_FILE_COUNT}."
        )
    if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
        raise ExtractionError(
            f"Archive expands to {total_bytes} bytes; limit is {MAX_ARCHIVE_TOTAL_BYTES} bytes."
        )


def _extract_zip_safely(upload_path: Path, destination_root: Path) -> None:
    total_bytes = 0
    entry_count = 0
    with zipfile.ZipFile(upload_path) as archive:
        infos = archive.infolist()
        for info in infos:
            if info.is_dir():
                continue
            entry_count += 1
            total_bytes += int(info.file_size)
        _validate_archive_limits(entry_count, total_bytes)

        for info in infos:
            target = _ensure_safe_archive_path(destination_root, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _extract_tar_safely(upload_path: Path, destination_root: Path) -> None:
    total_bytes = 0
    entry_count = 0
    with tarfile.open(upload_path) as archive:
        members = archive.getmembers()
        for member in members:
            if not member.isfile():
                continue
            entry_count += 1
            total_bytes += int(member.size)
        _validate_archive_limits(entry_count, total_bytes)

        for member in members:
            target = _ensure_safe_archive_path(destination_root, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def is_archive(path: Path) -> bool:
    suffixes = {path.suffix.lower(), "".join(path.suffixes[-2:]).lower()}
    return any(suffix in ARCHIVE_EXTENSIONS for suffix in suffixes) or zipfile.is_zipfile(path) or tarfile.is_tarfile(path)


def extract_input(upload_path: Path, workspace_dir: Path) -> tuple[Path, str]:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    source_dir = workspace_dir / "source"
    source_dir.mkdir(parents=True, exist_ok=True)

    if is_archive(upload_path):
        if zipfile.is_zipfile(upload_path):
            _extract_zip_safely(upload_path, source_dir)
        else:
            _extract_tar_safely(upload_path, source_dir)
        return normalize_root(source_dir), "archive"

    copied = source_dir / upload_path.name
    shutil.copy2(upload_path, copied)
    return source_dir, "single_file"


def cleanup_job_paths(upload_path: Path, workspace_dir: Path) -> list[str]:
    logs: list[str] = []
    if workspace_dir.exists() and not KEEP_WORKSPACE:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        logs.append(f"Removed workspace: {workspace_dir}")
    if upload_path.exists() and not KEEP_UPLOADS:
        upload_path.unlink(missing_ok=True)
        logs.append(f"Removed upload: {upload_path}")
    return logs


def normalize_root(source_dir: Path) -> Path:
    children = [child for child in source_dir.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return source_dir


def iter_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in SOURCE_EXTENSIONS or path.name in SPECIAL_TEXT_FILENAMES:
            files.append(path)
    return files


def safe_read_text(path: Path) -> str:
    if path.stat().st_size > MAX_TEXT_FILE_SIZE:
        return ""
    for encoding in ("utf-8", "cp1251", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return ""


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def iter_project_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        files[str(path.relative_to(root))] = path
    return files


# Определяем языки по расширениям и служебным именам файлов.
def detect_language_inventory(root: Path) -> dict[str, Any]:
    language_counts: dict[str, int] = {}
    for relative_path in iter_project_files(root):
        path = Path(relative_path)
        language = LANGUAGE_BY_FILENAME.get(path.name.casefold())
        if not language:
            language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if not language:
            continue
        language_counts[language] = language_counts.get(language, 0) + 1

    ordered_languages = sorted(language_counts, key=lambda item: (-language_counts[item], item.casefold()))
    programming_languages = [item for item in ordered_languages if item in PROGRAMMING_LANGUAGES]
    return {
        "language_counts": language_counts,
        "languages": ordered_languages,
        "programming_language_counts": {item: language_counts[item] for item in programming_languages},
        "programming_languages": programming_languages,
        "polyglot": len(programming_languages) > 1,
    }


def assess_multilinguality(language_inventory: dict[str, Any], *, has_tests: bool, build_systems: list[str]) -> dict[str, Any]:
    programming_languages = list(language_inventory.get("programming_languages", []))
    notes: list[str] = []
    if len(programming_languages) > 1:
        notes.append(f"Detected a polyglot codebase with {len(programming_languages)} programming languages.")
    if len(programming_languages) >= 3:
        notes.append("Cross-language ownership and integration checks should be treated as a release risk.")
    if len(programming_languages) > 1 and not has_tests:
        notes.append("No automated tests were detected for a project that spans multiple languages.")
    if len(programming_languages) > 1 and not build_systems:
        notes.append("No build manifest was detected for a polyglot project layout.")
    risk_level = "none"
    if len(programming_languages) > 1:
        risk_level = "medium" if not has_tests else "low"
    if len(programming_languages) >= 3 and not has_tests:
        risk_level = "high"
    return {
        "polyglot": len(programming_languages) > 1,
        "programming_language_count": len(programming_languages),
        "primary_language": programming_languages[0] if programming_languages else None,
        "secondary_languages": programming_languages[1:],
        "risk_level": risk_level,
        "notes": notes,
    }


def is_build_manifest(relative_path: str) -> bool:
    path = Path(relative_path)
    return path.name in BUILD_MANIFEST_FILENAMES or path.suffix.lower() in BUILD_MANIFEST_SUFFIXES


def is_test_related_path(relative_path: str) -> bool:
    lowered = relative_path.casefold()
    name = Path(relative_path).name.casefold()
    return (
        "/tests/" in f"/{lowered}/"
        or name.startswith("test")
        or "_test" in name
        or ".spec." in name
        or ".test." in name
        or name in {"conftest.py", "pytest.ini"}
        or "qtest" in lowered
    )


def _load_json_file(path: Path) -> dict[str, Any] | None:
    content = safe_read_text(path)
    if not content.strip():
        return None
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _detect_test_frameworks(relative_path: str, content: str, package_meta: dict[str, Any] | None = None) -> list[str]:
    frameworks: set[str] = set()
    suffix = Path(relative_path).suffix.lower()
    lowered = relative_path.casefold()
    if suffix == ".py":
        if is_test_related_path(relative_path) or PYTHON_TEST_PATTERN.search(content):
            frameworks.add("python")
    elif suffix == ".go":
        if lowered.endswith("_test.go") or GO_TEST_PATTERN.search(content):
            frameworks.add("go")
    elif suffix in {".js", ".ts", ".tsx"}:
        if is_test_related_path(relative_path) or JS_TEST_PATTERN.search(content):
            frameworks.add("node")
    if Path(relative_path).name == "package.json" and package_meta:
        scripts = package_meta.get("scripts")
        test_script = scripts.get("test") if isinstance(scripts, dict) else ""
        if isinstance(test_script, str) and test_script.strip() and not DEFAULT_NPM_TEST_PATTERN.search(test_script):
            frameworks.add("node")
    if any(marker in content for marker in ("QTEST_MAIN", "QTEST_APPLESS_MAIN", "add_test(", "Qt6::Test", "Qt5::Test")):
        frameworks.add("qt")
    return sorted(frameworks)


def compare_project_versions(current_root: Path, baseline_root: Path) -> tuple[dict, list[Path]]:
    current_map = iter_project_files(current_root)
    baseline_map = iter_project_files(baseline_root)
    current_only = sorted(set(current_map) - set(baseline_map))
    removed = sorted(set(baseline_map) - set(current_map))
    modified: list[str] = []

    for relative in sorted(set(current_map) & set(baseline_map)):
        if hash_file(current_map[relative]) != hash_file(baseline_map[relative]):
            modified.append(relative)

    changed = sorted(set(current_only + modified))
    text_map = {str(path.relative_to(current_root)): path for path in iter_text_files(current_root)}
    changed_text_files = [text_map[relative] for relative in changed if relative in text_map]

    summary = {
        "has_changes": bool(changed or removed),
        "baseline_root_name": baseline_root.name,
        "baseline_file_count": len(baseline_map),
        "current_file_count": len(current_map),
        "changed_file_count": len(changed),
        "changed_text_file_count": len(changed_text_files),
        "added_files": current_only,
        "modified_files": modified,
        "removed_files": removed,
        "changed_files": changed,
        "changed_text_files": [str(path.relative_to(current_root)) for path in changed_text_files],
        "build_files_changed": any(is_build_manifest(relative) for relative in changed + removed),
        "test_related_files_changed": any(is_test_related_path(relative) for relative in changed + removed),
        "source_files_changed": any(
            Path(relative).suffix.lower() in SOURCE_EXTENSIONS or Path(relative).name == "CMakeLists.txt"
            for relative in changed
        ),
    }
    return summary, changed_text_files


def line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def detect_project(root: Path) -> dict:
    files = iter_text_files(root)
    language_inventory = detect_language_inventory(root)
    file_paths = [str(path.relative_to(root)) for path in files]
    extension_counts: dict[str, int] = {}
    qt_markers = 0
    test_markers = 0
    fuzz_markers = 0
    build_systems: set[str] = set()
    test_frameworks: set[str] = set()

    for path in files:
        relative = str(path.relative_to(root))
        extension_counts[path.suffix.lower() or path.name] = extension_counts.get(path.suffix.lower() or path.name, 0) + 1
        if path.name == "CMakeLists.txt":
            build_systems.add("cmake")
        if path.suffix.lower() in {".pro", ".pri"}:
            build_systems.add("qmake")
        if path.name in {"pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "tox.ini", "pytest.ini", "Pipfile", "poetry.lock"}:
            build_systems.add("python")
        if path.name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "tsconfig.json"}:
            build_systems.add("node")
        if path.name in {"go.mod", "go.sum"}:
            build_systems.add("go")
        content = safe_read_text(path)
        package_meta = _load_json_file(path) if path.name == "package.json" else None
        if any(marker in content for marker in ("Qt6::", "Qt5::", "QApplication", "QWidget", "QObject", "QML_ELEMENT", "QT +=")):
            qt_markers += 1
        detected_frameworks = _detect_test_frameworks(relative, content, package_meta)
        if detected_frameworks:
            test_markers += 1
            test_frameworks.update(detected_frameworks)
        if any(marker in content for marker in ("LLVMFuzzerTestOneInput", "afl::", "AFL_LOOP", "fuzz")):
            fuzz_markers += 1

    top_level = sorted(child.name for child in root.iterdir()) if root.exists() else []
    multilinguality = assess_multilinguality(
        language_inventory,
        has_tests=test_markers > 0,
        build_systems=sorted(build_systems),
    )
    return {
        "root": str(root),
        "relative_root_name": root.name,
        "file_count": len(files),
        "files": file_paths,
        "build_systems": sorted(build_systems),
        "extension_counts": extension_counts,
        "is_qt_project": qt_markers > 0 or any(path.endswith(".qml") for path in file_paths),
        "has_tests": test_markers > 0,
        "detected_test_frameworks": sorted(test_frameworks),
        "has_fuzz_targets": fuzz_markers > 0,
        "top_level_entries": top_level,
        "languages": language_inventory["languages"],
        "language_counts": language_inventory["language_counts"],
        "programming_languages": language_inventory["programming_languages"],
        "programming_language_counts": language_inventory["programming_language_counts"],
        "polyglot": language_inventory["polyglot"],
        "multilinguality": multilinguality,
    }


def _parallel_map_files(files: list[Path], workers: int, handler):
    if workers <= 1 or len(files) <= 1:
        return [handler(path) for path in files]
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(handler, path) for path in files]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def _security_references_for(title: str) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for identifier in SECURITY_REFERENCES_BY_TITLE.get(title, ()):
        label, url = SECURITY_REFERENCE_CATALOG.get(identifier, (identifier, ""))
        references.append(
            {
                "id": identifier,
                "title": label,
                "url": url,
            }
        )
    return references


def _security_finding(
    *,
    severity: str,
    title: str,
    description: str,
    path: str,
    line: int | None = None,
    source: str,
    recommendation: str,
    confidence: str = "medium",
    evidence: str = "",
    trace: list[dict[str, Any]] | None = None,
) -> Finding:
    return Finding(
        category="security",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        description=description,
        path=path,
        line=line,
        source=source,
        recommendation=recommendation,
        references=_security_references_for(title),
        confidence=confidence,
        evidence=evidence,
        trace=trace or [],
    )


def _finding_from_parser_spec(relative: str, spec: ParserSecurityFinding) -> Finding:
    return _security_finding(
        severity=spec.severity,
        title=spec.title,
        description=spec.description,
        path=relative,
        line=spec.line,
        source=spec.source,
        recommendation=spec.recommendation,
        confidence=spec.confidence,
        evidence=spec.evidence,
        trace=spec.trace,
    )


def _dedupe_security_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, int | None]] = set()
    for finding in findings:
        key = (finding.title, finding.path, finding.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _analyze_security_file(root: Path, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    content = safe_read_text(path)
    if not content:
        return findings
    relative = str(path.relative_to(root))
    findings.extend(
        _finding_from_parser_spec(relative, spec)
        for spec in analyze_parser_security(relative, content, path.suffix.lower())
    )
    for pattern, severity, title, recommendation in SECURITY_PATTERNS:
        for match in re.finditer(pattern, content, flags=re.IGNORECASE):
            line = line_number_for_offset(content, match.start())
            findings.append(
                _security_finding(
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=f"Matched pattern `{match.group(0)}` in source.",
                    path=relative,
                    line=line,
                    source="built-in-security-rules",
                    recommendation=recommendation,
                )
            )
    findings.extend(_qt_security_findings(relative, content))
    findings.extend(_language_security_findings(relative, content, path.suffix.lower()))
    findings.extend(_injection_security_findings(relative, content, path))
    findings.extend(_taint_security_findings(relative, content, path.suffix.lower()))
    return _dedupe_security_findings(findings)


def _qt_security_findings(relative: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in QT_IGNORE_SSL_PATTERN.finditer(content):
        findings.append(
            _security_finding(
                severity="high",
                title="Qt TLS verification bypass",
                description=f"Detected Qt TLS verification bypass marker `{match.group(0)}`.",
                path=relative,
                line=line_number_for_offset(content, match.start()),
                source="qt-security-rules",
                recommendation="Do not disable SSL verification in production code paths.",
            )
        )
    for match in QT_PROCESS_SHELL_PATTERN.finditer(content):
        findings.append(
            _security_finding(
                severity="medium",
                title="Qt process launch through shell",
                description="A Qt process launch appears to invoke a shell interpreter.",
                path=relative,
                line=line_number_for_offset(content, match.start()),
                source="qt-security-rules",
                recommendation="Prefer direct executable invocation with explicit argument arrays.",
            )
        )
    return findings


def _language_security_findings(relative: str, content: str, suffix: str) -> list[Finding]:
    findings: list[Finding] = []
    language_rules: list[tuple[re.Pattern[str], str, str, str]]
    if suffix == ".py":
        language_rules = [
            (re.compile(r"\beval\s*\("), "high", "Python eval execution", "Избегайте eval() для данных из недоверенных источников."),
            (re.compile(r"\bexec\s*\("), "high", "Python exec execution", "Избегайте exec() и используйте безопасные диспетчеры."),
            (re.compile(r"subprocess\.(?:run|Popen)\([^)]*shell\s*=\s*True"), "high", "Python shell=True", "Запускайте процессы без shell=True."),
            (re.compile(r"\bpickle\.loads?\s*\("), "high", "Unsafe pickle deserialization", "Не десериализуйте недоверенные данные через pickle."),
            (re.compile(r"\byaml\.load\s*\((?![^)]*SafeLoader)"), "high", "Unsafe YAML deserialization", "Используйте yaml.safe_load() или SafeLoader."),
            (re.compile(r"\bapp\.run\s*\([^)]*debug\s*=\s*True"), "medium", "Python debug server enabled", "Не запускайте production-сервис с debug=True."),
        ]
    elif suffix in {".js", ".ts", ".tsx"}:
        language_rules = [
            (re.compile(r"\beval\s*\("), "high", "JavaScript eval execution", "Уберите eval() и используйте безопасный парсинг данных."),
            (re.compile(r"new\s+Function\s*\("), "high", "Dynamic Function constructor", "Не создавайте код во время выполнения через Function()."),
            (re.compile(r"child_process\.(?:exec|execSync)\s*\("), "high", "Node child_process exec", "Предпочитайте execFile/spawn с явными аргументами."),
            (re.compile(r"\bvm\.runIn(?:This|New)Context\s*\("), "high", "Node VM dynamic code execution", "Не исполняйте недоверенный код через vm.* без sandbox-политики."),
        ]
    elif suffix == ".go":
        language_rules = [
            (re.compile(r"exec\.Command\s*\(\s*\"(?:/bin/)?sh\""), "high", "Go shell command execution", "Избегайте передачи команд через shell."),
            (re.compile(r"http\.ListenAndServe\s*\([^,]+,\s*nil\s*\)"), "low", "Go HTTP server without explicit middleware", "Проверьте наличие timeout и защитных middleware."),
        ]
    elif suffix == ".sh":
        language_rules = [
            (re.compile(r"\b(?:curl|wget)\b[^|\n]+\|\s*(?:sh|bash)\b"), "high", "Shell downloads piped to interpreter", "Скачивайте артефакт отдельно, проверяйте подпись/хэш и только потом запускайте."),
        ]
    else:
        return findings

    for pattern, severity, title, recommendation in language_rules:
        for match in pattern.finditer(content):
            findings.append(
                _security_finding(
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=f"Detected language-specific security pattern `{match.group(0)}`.",
                    path=relative,
                    line=line_number_for_offset(content, match.start()),
                    source="language-security-rules",
                    recommendation=recommendation,
                )
            )
    return findings


def _injection_security_findings(relative: str, content: str, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    filename = path.name.casefold()
    rules: list[tuple[re.Pattern[str], str, str, str, str]] = []
    if suffix == ".py":
        rules.extend(
            [
                (
                    re.compile(r"\.execute\s*\(\s*f[\"'][^\"']*\b(?:select|insert|update|delete|where)\b", re.IGNORECASE),
                    "high",
                    "SQL query built with string interpolation",
                    "An SQL execution call appears to use an f-string query.",
                    "Use parameterized SQL bindings instead of interpolating values into query text.",
                ),
                (
                    re.compile(r"\.execute\s*\([^)]*(?:\.format\s*\(|%\s*[\w({])", re.IGNORECASE),
                    "high",
                    "SQL query built with string interpolation",
                    "An SQL execution call appears to format query text dynamically.",
                    "Pass untrusted values as query parameters instead of formatting SQL strings.",
                ),
                (
                    re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*", re.IGNORECASE),
                    "medium",
                    "Permissive CORS policy",
                    "The service appears to allow every origin.",
                    "Restrict CORS origins to the exact trusted frontend domains.",
                ),
            ]
        )
    if suffix in {".js", ".ts", ".tsx"}:
        rules.extend(
            [
                (
                    re.compile(r"\.(?:query|execute)\s*\(\s*`[^`]*(?:select|insert|update|delete|where)[^`]*\$\{", re.IGNORECASE),
                    "high",
                    "SQL query built with string interpolation",
                    "A database query appears to interpolate values inside a template literal.",
                    "Use parameterized query APIs and pass values separately.",
                ),
                (
                    re.compile(r"Access-Control-Allow-Origin[\"']?\s*,\s*[\"']\*|origin\s*:\s*[\"']\*", re.IGNORECASE),
                    "medium",
                    "Permissive CORS policy",
                    "The service appears to allow every origin.",
                    "Restrict CORS origins to the exact trusted frontend domains.",
                ),
            ]
        )
    if filename == "dockerfile":
        rules.append(
            (
                re.compile(r"^\s*USER\s+(?:root|0)\s*$", re.IGNORECASE | re.MULTILINE),
                "medium",
                "Container runs as root",
                "The Dockerfile explicitly leaves the runtime user as root.",
                "Create and switch to a non-root runtime user for the final image stage.",
            )
        )
    for pattern, severity, title, description, recommendation in rules:
        for match in pattern.finditer(content):
            findings.append(
                _security_finding(
                    severity=severity,
                    title=title,
                    description=description,
                    path=relative,
                    line=line_number_for_offset(content, match.start()),
                    source="injection-security-rules",
                    recommendation=recommendation,
                )
            )
    if filename == "dockerfile" and not any(item.title == "Container runs as root" for item in findings):
        final_stage_line = _dockerfile_final_stage_without_user_line(content)
        if final_stage_line is not None:
            findings.append(
                _security_finding(
                    severity="medium",
                    title="Container image uses default root user",
                    description="The final Dockerfile stage does not set USER, so the image defaults to root.",
                    path=relative,
                    line=final_stage_line,
                    source="injection-security-rules",
                    recommendation="Create and switch to a non-root runtime user in the final image stage.",
                )
            )
    return findings


def _dockerfile_final_stage_without_user_line(content: str) -> int | None:
    final_stage_line = 1
    final_user: str | None = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"FROM\b", stripped, flags=re.IGNORECASE):
            final_stage_line = line_number
            final_user = None
            continue
        match = re.match(r"USER\s+([^\s#]+)", stripped, flags=re.IGNORECASE)
        if match:
            final_user = match.group(1).strip("\"'")
    if final_user:
        return None
    return final_stage_line


def _taint_sources_for_suffix(suffix: str) -> list[re.Pattern[str]]:
    common_assignment = r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*"
    if suffix == ".py":
        return [
            re.compile(common_assignment + r"(?:request\.(?:args|form|json|data|headers|cookies)|request\.get_json\s*\(|input\s*\(|sys\.argv|os\.environ)", re.IGNORECASE),
        ]
    if suffix in {".js", ".ts", ".tsx"}:
        return [
            re.compile(r"(?:const|let|var)\s+" + common_assignment + r"(?:req\.(?:query|body|params|headers|cookies)|request\.(?:query|body|params|headers|cookies)|location\.(?:search|hash)|document\.URL|process\.argv)", re.IGNORECASE),
        ]
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
        return [
            re.compile(r"(?:auto|char\s*\*|std::string|QString)?\s*" + common_assignment + r"(?:argv\s*\[|getenv\s*\(|qgetenv\s*\(|QCoreApplication::arguments)", re.IGNORECASE),
        ]
    if suffix == ".go":
        return [
            re.compile(common_assignment + r"(?:r\.(?:FormValue|PostFormValue)\s*\(|r\.URL\.Query\(\)\.Get\s*\(|r\.Header\.Get\s*\(|os\.Args)", re.IGNORECASE),
        ]
    return []


def _taint_sink_rules_for_suffix(suffix: str) -> list[tuple[re.Pattern[str], str, str, str]]:
    command_recommendation = "Validate input with an allowlist and invoke processes without shell interpretation."
    code_recommendation = "Do not execute user-controlled text as code; map allowed actions to explicit handlers."
    sql_recommendation = "Use parameterized SQL APIs and keep user data out of query text."
    if suffix == ".py":
        return [
            (re.compile(r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output))\s*\("), "critical", "User-controlled data reaches shell execution", command_recommendation),
            (re.compile(r"\b(?:eval|exec)\s*\("), "critical", "User-controlled data reaches dynamic code execution", code_recommendation),
            (re.compile(r"\.execute\s*\("), "high", "User-controlled data reaches SQL query construction", sql_recommendation),
        ]
    if suffix in {".js", ".ts", ".tsx"}:
        return [
            (re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\("), "critical", "User-controlled data reaches shell execution", command_recommendation),
            (re.compile(r"\b(?:eval|Function|vm\.runIn(?:This|New)Context)\s*\("), "critical", "User-controlled data reaches dynamic code execution", code_recommendation),
            (re.compile(r"\.(?:query|execute)\s*\("), "high", "User-controlled data reaches SQL query construction", sql_recommendation),
        ]
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
        return [
            (re.compile(r"\b(?:system|popen)\s*\("), "critical", "User-controlled data reaches shell execution", command_recommendation),
        ]
    if suffix == ".go":
        return [
            (re.compile(r"\bexec\.Command\s*\("), "critical", "User-controlled data reaches shell execution", command_recommendation),
            (re.compile(r"\bdb\.(?:Query|Exec|QueryRow)\s*\("), "high", "User-controlled data reaches SQL query construction", sql_recommendation),
        ]
    return []


def _taint_security_findings(relative: str, content: str, suffix: str) -> list[Finding]:
    source_patterns = _taint_sources_for_suffix(suffix)
    sink_rules = _taint_sink_rules_for_suffix(suffix)
    if not source_patterns or not sink_rules:
        return []

    lines = content.splitlines()
    tainted: dict[str, tuple[int, str]] = {}
    for index, line in enumerate(lines, start=1):
        for pattern in source_patterns:
            match = pattern.search(line)
            if match:
                tainted.setdefault(match.group("var"), (index, line.strip()))

    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for variable, (source_line, source_text) in tainted.items():
        variable_pattern = re.compile(rf"\b{re.escape(variable)}\b")
        for index, line in enumerate(lines[source_line - 1 :], start=source_line):
            if not variable_pattern.search(line):
                continue
            for sink_pattern, severity, title, recommendation in sink_rules:
                if not sink_pattern.search(line):
                    continue
                key = (variable, title, index)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _security_finding(
                        severity=severity,
                        title=title,
                        description=(
                            f"Variable `{variable}` is assigned from a user-controlled source on line {source_line} "
                            f"and reaches a sensitive sink on line {index}."
                        ),
                        path=relative,
                        line=index,
                        source="taint-security-rules",
                        recommendation=f"{recommendation} Source expression: {source_text}",
                    )
                )
    return findings


def analyze_security(root: Path, files: list[Path], max_workers: int = 1) -> list[Finding]:
    findings: list[Finding] = []
    for result in _parallel_map_files(files, max_workers, lambda path: _analyze_security_file(root, path)):
        findings.extend(result)
    return findings


def _analyze_style_file(root: Path, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    content = safe_read_text(path)
    if not content:
        return findings
    relative = str(path.relative_to(root))
    lines = content.splitlines()
    for index, line in enumerate(lines, start=1):
        if re.match(r"^\t+", line):
            findings.append(
                Finding(
                    category="style",
                    severity="low",
                    title="Tab indentation",
                    description="Tabs used for indentation reduce formatting consistency.",
                    path=relative,
                    line=index,
                    source="built-in-style-rules",
                    recommendation="Prefer spaces or project-specific formatter rules.",
                )
            )
        if line.rstrip() != line:
            findings.append(
                Finding(
                    category="style",
                    severity="info",
                    title="Trailing whitespace",
                    description="Remove trailing whitespace to keep diffs cleaner.",
                    path=relative,
                    line=index,
                    source="built-in-style-rules",
                    recommendation="Trim whitespace at end of line.",
                )
            )
        if len(line) > 120:
            findings.append(
                Finding(
                    category="style",
                    severity="low",
                    title="Long line",
                    description=f"Line length is {len(line)} characters.",
                    path=relative,
                    line=index,
                    source="built-in-style-rules",
                    recommendation="Wrap or refactor long lines for readability.",
                )
            )
        if "using namespace std;" in line:
            findings.append(
                Finding(
                    category="style",
                    severity="low",
                    title="Global namespace import",
                    description="Avoid importing std into the global namespace in shared code.",
                    path=relative,
                    line=index,
                    source="built-in-style-rules",
                    recommendation="Use explicit std:: qualifiers instead.",
                )
            )
    if content and not content.endswith("\n"):
        findings.append(
            Finding(
                category="style",
                severity="info",
                title="Missing newline at EOF",
                description="Text file does not end with a newline.",
                path=relative,
                source="built-in-style-rules",
                recommendation="End source files with a newline.",
            )
        )
    return findings


def analyze_style(root: Path, files: list[Path], max_workers: int = 1) -> list[Finding]:
    findings: list[Finding] = []
    for result in _parallel_map_files(files, max_workers, lambda path: _analyze_style_file(root, path)):
        findings.extend(result)
    return findings


def parse_clang_tidy_output(root: Path, output: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"^(.*?):(\d+):(\d+):\s+(warning|error):\s+(.*?)(?:\s+\[([^\]]+)\])?\s*$",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        raw_path, line, _column, level, message, check_name = match.groups()
        path = Path(raw_path)
        try:
            relative = str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            relative = raw_path
        severity = "medium" if level == "warning" else "high"
        findings.append(
            Finding(
                category="style",
                severity=severity,  # type: ignore[arg-type]
                title=f"clang-tidy {level}",
                description=message,
                path=relative,
                line=int(line),
                source=f"clang-tidy:{check_name or 'unknown'}",
                recommendation="Review the diagnostic and align the code with the suggested check.",
            )
        )
    return findings


def run_clang_tidy(
    root: Path,
    build_dir: Path,
    tools: dict[str, str | None],
    plan: AdaptiveExecutionPlan | None = None,
    focus_files: list[Path] | None = None,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    logs: list[str] = []
    tool = tools.get("clang_tidy")
    compile_commands = build_dir / "compile_commands.json"
    if not tool or not compile_commands.exists():
        return findings, logs

    focus_files = focus_files or []
    source_files = [
        path
        for path in (focus_files or iter_text_files(root))
        if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}
    ][:20]
    runtime_env = build_runtime_env(plan)

    def execute(path: Path):
        result = run_command(
            [tool, "-p", str(build_dir), str(path)],
            cwd=root,
            timeout=180,
            env=runtime_env,
        )
        return path, result

    workers = max(1, plan.clang_tidy_workers if plan else 1)
    if workers <= 1 or len(source_files) <= 1:
        results = [execute(path) for path in source_files]
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(execute, path) for path in source_files]
            results = [future.result() for future in as_completed(futures)]
    for _path, result in results:
        logs.append(f"$ {' '.join(result.command)}")
        if result.stdout.strip():
            logs.append(result.stdout.strip())
        if result.stderr.strip():
            logs.append(result.stderr.strip())
        findings.extend(parse_clang_tidy_output(root, result.stdout + "\n" + result.stderr))
    return findings, logs


def map_cppcheck_severity(severity: str) -> str:
    mapping = {
        "error": "high",
        "warning": "medium",
        "style": "low",
        "performance": "low",
        "portability": "low",
        "information": "info",
        "debug": "info",
    }
    return mapping.get(severity.lower(), "info")


def run_cppcheck(
    root: Path,
    files: list[Path],
    tools: dict[str, str | None],
    plan: AdaptiveExecutionPlan | None = None,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    logs: list[str] = []
    tool = tools.get("cppcheck")
    if not tool:
        return findings, logs

    source_files = [
        str(path)
        for path in files
        if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
    ]
    if not source_files:
        return findings, logs

    result = run_command(
        [
            tool,
            "--xml",
            "--xml-version=2",
            "--enable=warning,style,performance,portability,information",
            "--force",
            "--inconclusive",
            "-j",
            str(max(1, plan.cppcheck_jobs if plan else 1)),
            *source_files,
        ],
        cwd=root,
        timeout=300,
        env=build_runtime_env(plan),
    )
    logs.append(f"$ {' '.join(result.command)}")
    if result.stdout.strip():
        logs.append(result.stdout.strip())
    if result.stderr.strip():
        logs.append(result.stderr.strip())

    xml_content = result.stderr[result.stderr.find("<results") :] if "<results" in result.stderr else ""
    if not xml_content:
        return findings, logs

    try:
        tree = ET.fromstring(xml_content)
    except ET.ParseError:
        return findings, logs

    for error in tree.findall(".//error"):
        severity = map_cppcheck_severity(error.attrib.get("severity", "information"))
        locations = error.findall("location")
        location = locations[0] if locations else None
        file_path = location.attrib.get("file", "") if location is not None else ""
        line = int(location.attrib["line"]) if location is not None and location.attrib.get("line", "").isdigit() else None
        try:
            relative = str(Path(file_path).resolve().relative_to(root.resolve())) if file_path else ""
        except ValueError:
            relative = file_path
        findings.append(
            Finding(
                category="quality",
                severity=severity,  # type: ignore[arg-type]
                title=error.attrib.get("id", "cppcheck issue"),
                description=error.attrib.get("msg", "Cppcheck reported an issue."),
                path=relative,
                line=line,
                source="cppcheck",
                recommendation=error.attrib.get("verbose", "Review and fix the reported issue."),
            )
        )

    return findings, logs


def _analyze_quality_file(root: Path, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    content = safe_read_text(path)
    if not content:
        return findings
    relative = str(path.relative_to(root))
    lines = content.splitlines()
    complexity = len(re.findall(r"\b(if|for|while|case|catch)\b|\?", content))
    if len(lines) > 400:
        findings.append(
            Finding(
                category="quality",
                severity="medium" if len(lines) > 800 else "low",
                title="Large source file",
                description=f"File contains {len(lines)} lines.",
                path=relative,
                source="built-in-quality-rules",
                recommendation="Split the file into smaller units where practical.",
            )
        )
    if complexity > 15:
        findings.append(
            Finding(
                category="quality",
                severity="medium" if complexity > 30 else "low",
                title="High branching complexity",
                description=f"Approximate complexity score is {complexity}.",
                path=relative,
                source="built-in-quality-rules",
                recommendation="Extract smaller functions and simplify branching.",
            )
        )
    for marker in ("TODO", "FIXME", "HACK"):
        if marker in content:
            findings.append(
                Finding(
                    category="quality",
                    severity="info",
                    title=f"Outstanding marker: {marker}",
                    description="Source contains a maintenance marker that should be reviewed.",
                    path=relative,
                    source="built-in-quality-rules",
                    recommendation="Track the item or remove the marker after completion.",
                )
            )
    findings.extend(_find_redundancy_findings(relative, lines, content, path))
    findings.extend(_find_qt_quality_findings(relative, content))
    findings.extend(_find_translation_bypass_findings(relative, content, path.suffix.lower()))
    return findings


def _normalize_comment_text(text: str) -> str:
    normalized = re.sub(r"^\s*(//+|/\*+|\*+/|\*+|#)\s?", "", text)
    return normalized.strip()


def _looks_like_code_fragment(text: str) -> bool:
    normalized = _normalize_comment_text(text)
    if len(normalized) < 12:
        return False
    if normalized.startswith(("#include", "import ", "QT +=", "target_", "add_", "find_package(")):
        return True
    has_code_symbol = any(token in normalized for token in (";", "{", "}", "(", ")", "=", "::", "->", "<", ">"))
    if not has_code_symbol:
        return False
    if CODE_FRAGMENT_KEYWORDS.search(normalized):
        return True
    if FUNCTION_LIKE_PATTERN.search(normalized):
        return True
    return bool(DECLARATION_LIKE_PATTERN.search(normalized))


def _comment_block_finding(
    *,
    relative: str,
    line: int,
    title: str,
    description: str,
    recommendation: str,
    severity: str = "low",
) -> Finding:
    return Finding(
        category="quality",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        description=description,
        path=relative,
        line=line,
        source="built-in-redundancy-rules",
        recommendation=recommendation,
    )


def _find_line_comment_code(relative: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    block_lines: list[tuple[int, str]] = []

    def flush_block() -> None:
        if not block_lines:
            return
        code_like = [(line_no, text) for line_no, text in block_lines if _looks_like_code_fragment(text)]
        if len(code_like) >= 2:
            findings.append(
                _comment_block_finding(
                    relative=relative,
                    line=code_like[0][0],
                    title="Commented-out code block",
                    description=(
                        f"Detected {len(code_like)} code-like lines inside a line-comment block "
                        f"that spans {len(block_lines)} lines."
                    ),
                    recommendation="Remove dead code or restore it from version control when needed.",
                )
            )
        elif len(code_like) == 1:
            findings.append(
                _comment_block_finding(
                    relative=relative,
                    line=code_like[0][0],
                    title="Commented-out code line",
                    description="A single line comment looks like disabled source code.",
                    recommendation="Delete stale disabled code to keep the file easier to review.",
                    severity="info",
                )
            )
        block_lines.clear()

    for index, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            block_lines.append((index, line))
        else:
            flush_block()
    flush_block()
    return findings


def _find_block_comment_code(relative: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"/\*.*?\*/", content, flags=re.DOTALL):
        block = match.group(0)
        block_lines = block.splitlines()
        code_like_lines = [line for line in block_lines if _looks_like_code_fragment(line)]
        if len(code_like_lines) < 2:
            continue
        findings.append(
            _comment_block_finding(
                relative=relative,
                line=line_number_for_offset(content, match.start()),
                title="Commented-out code block",
                description=(
                    f"Detected {len(code_like_lines)} code-like lines inside a block comment "
                    f"that spans {len(block_lines)} lines."
                ),
                recommendation="Prefer removing old code and relying on version history for recovery.",
            )
        )
    return findings


def _find_disabled_preprocessor_code(relative: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"^\s*#if\s+0\b(?P<body>.*?)^\s*#endif\b", re.MULTILINE | re.DOTALL)
    for match in pattern.finditer(content):
        body = match.group("body")
        code_like_lines = [line for line in body.splitlines() if _looks_like_code_fragment(line)]
        if not code_like_lines:
            continue
        findings.append(
            _comment_block_finding(
                relative=relative,
                line=line_number_for_offset(content, match.start()),
                title="Disabled code region",
                description=(
                    f"Found {len(code_like_lines)} code-like lines hidden behind a `#if 0` block."
                ),
                recommendation="Remove dead code or switch to a feature flag with explicit ownership.",
                severity="medium" if len(code_like_lines) >= 3 else "low",
            )
        )
    return findings


def _find_duplicate_imports(relative: str, lines: list[str], suffix: str) -> list[Finding]:
    findings: list[Finding] = []
    directives: dict[str, list[int]] = {}
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#include "):
            directives.setdefault(stripped, []).append(index)
        elif suffix == ".qml" and stripped.startswith("import "):
            directives.setdefault(stripped, []).append(index)
    for directive, occurrences in directives.items():
        if len(occurrences) < 2:
            continue
        findings.append(
            _comment_block_finding(
                relative=relative,
                line=occurrences[1],
                title="Duplicate include/import directive",
                description=f"The same directive appears {len(occurrences)} times in this file: {directive}",
                recommendation="Keep a single include/import to reduce noise and avoid redundant dependencies.",
            )
        )
    return findings


def _find_redundancy_findings(relative: str, lines: list[str], content: str, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_line_comment_code(relative, lines))
    findings.extend(_find_block_comment_code(relative, content))
    findings.extend(_find_disabled_preprocessor_code(relative, content))
    findings.extend(_find_duplicate_imports(relative, lines, path.suffix.lower()))
    return findings


def _find_qt_quality_findings(relative: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in QT_SIGNAL_SLOT_PATTERN.finditer(content):
        findings.append(
            Finding(
                category="quality",
                severity="low",
                title="Legacy Qt SIGNAL/SLOT syntax",
                description="The file uses the string-based SIGNAL/SLOT syntax instead of typed connections.",
                path=relative,
                line=line_number_for_offset(content, match.start()),
                source="qt-quality-rules",
                recommendation="Prefer function-pointer or lambda based QObject::connect calls for compile-time safety.",
            )
        )
        break
    for match in QT_OBJECT_WITHOUT_PARENT_PATTERN.finditer(content):
        findings.append(
            Finding(
                category="quality",
                severity="low",
                title="Qt object allocated without parent",
                description="A QObject-derived allocation without an explicit parent was detected.",
                path=relative,
                line=line_number_for_offset(content, match.start()),
                source="qt-quality-rules",
                recommendation="Assign an ownership parent or switch to RAII/smart-pointer ownership.",
            )
        )
    for match in QML_DEBUG_PATTERN.finditer(content):
        findings.append(
            Finding(
                category="quality",
                severity="info",
                title="Qt/QML debug marker present",
                description="Debug-only Qt/QML marker was detected in the source tree.",
                path=relative,
                line=line_number_for_offset(content, match.start()),
                source="qt-quality-rules",
                recommendation="Review whether QML debug helpers should be disabled in release builds.",
            )
        )
        break
    return findings


def _find_translation_bypass_findings(relative: str, content: str, suffix: str) -> list[Finding]:
    if suffix not in {".cpp", ".cc", ".cxx", ".h", ".hpp", ".qml"}:
        return []
    findings: list[Finding] = []
    if "tr(" in content or "qsTr(" in content or "QT_TRANSLATE_NOOP" in content:
        return findings
    for match in TRANSLATION_BYPASS_PATTERN.finditer(content):
        findings.append(
            Finding(
                category="quality",
                severity="low",
                title="Potential untranslated UI string",
                description="A user-facing string literal was detected without an obvious Qt translation wrapper.",
                path=relative,
                line=line_number_for_offset(content, match.start()),
                source="i18n-quality-rules",
                recommendation="Wrap user-facing strings in tr()/qsTr() or an explicit translation macro.",
            )
        )
        break
    return findings


def analyze_quality(root: Path, files: list[Path], project_info: dict, max_workers: int = 1) -> list[Finding]:
    findings: list[Finding] = []
    for result in _parallel_map_files(files, max_workers, lambda path: _analyze_quality_file(root, path)):
        findings.extend(result)
    if not project_info.get("has_tests"):
        findings.append(
            Finding(
                category="quality",
                severity="medium",
                title="No test entry points detected",
                description="No Qt Test or CTest markers were found in the uploaded project.",
                source="project-discovery",
                recommendation="Add automated tests to improve regression safety.",
            )
        )
    programming_languages = project_info.get("programming_languages", [])
    multilinguality = project_info.get("multilinguality", {})
    if programming_languages and len(programming_languages) > 1:
        findings.append(
            Finding(
                category="quality",
                severity="info",
                title="Polyglot project detected",
                description=(
                    "The uploaded project contains multiple programming languages: "
                    f"{', '.join(programming_languages)}."
                ),
                source="language-discovery",
                recommendation="Check language boundaries, adapters, and shared contracts during review.",
            )
        )
    if multilinguality.get("polyglot") and not project_info.get("has_tests"):
        findings.append(
            Finding(
                category="quality",
                severity="medium",
                title="Polyglot project without detected tests",
                description="Multiple programming languages were detected, but automated tests were not found.",
                source="multilinguality-checks",
                recommendation="Add automated coverage for cross-language paths before release.",
            )
        )
    if multilinguality.get("programming_language_count", 0) >= 3:
        findings.append(
            Finding(
                category="quality",
                severity="low",
                title="Cross-language integration complexity",
                description=(
                    "Three or more programming languages were detected in one project, "
                    "which raises the chance of integration drift."
                ),
                source="multilinguality-checks",
                recommendation="Review language ownership, interfaces, and build/test orchestration for each layer.",
            )
        )
    return findings


def _append_command_logs(logs: list[str], result) -> None:
    logs.append(f"$ {' '.join(result.command)}")
    if result.stdout.strip():
        logs.append(result.stdout.strip())
    if result.stderr.strip():
        logs.append(result.stderr.strip())


def _record_functionality_result(
    metadata: dict[str, Any],
    ecosystem: str,
    *,
    configured: bool,
    built: bool,
    tests_ran: bool,
    test_runner: str = "",
) -> None:
    ecosystem_results = metadata.setdefault("ecosystem_results", {})
    ecosystem_results[ecosystem] = {
        "configured": configured,
        "built": built,
        "tests_ran": tests_ran,
        "test_runner": test_runner,
    }
    values = list(ecosystem_results.values())
    metadata["configured"] = all(bool(item.get("configured")) for item in values) if values else False
    metadata["built"] = all(bool(item.get("built")) for item in values) if values else False
    metadata["tests_ran"] = any(bool(item.get("tests_ran")) for item in values)


def _node_local_tool(root: Path, tool_name: str) -> str | None:
    candidate = root / "node_modules" / ".bin" / tool_name
    if candidate.exists() and candidate.is_file():
        return str(candidate)
    return None


def _node_test_command(root: Path, tools: dict[str, str | None]) -> tuple[list[str] | None, str]:
    package_meta = _load_json_file(root / "package.json") or {}
    scripts = package_meta.get("scripts")
    test_script = scripts.get("test") if isinstance(scripts, dict) else ""
    if not isinstance(test_script, str) or not test_script.strip() or DEFAULT_NPM_TEST_PATTERN.search(test_script):
        return None, ""
    if _node_local_tool(root, "vitest"):
        return [_node_local_tool(root, "vitest") or "", "run"], "vitest"
    if _node_local_tool(root, "jest"):
        return [_node_local_tool(root, "jest") or "", "--runInBand"], "jest"
    if _node_local_tool(root, "mocha"):
        return [_node_local_tool(root, "mocha") or "", "--reporter", "dot"], "mocha"
    npm_tool = tools.get("npm") or shutil.which("npm")
    if npm_tool and (root / "node_modules").exists():
        return [npm_tool, "test", "--", "--ci"], "npm-test"
    return None, ""


def _tsc_command(root: Path, tools: dict[str, str | None]) -> list[str] | None:
    tsc_tool = tools.get("tsc") or _node_local_tool(root, "tsc")
    if not tsc_tool:
        return None
    return [tsc_tool, "--noEmit", "--pretty", "false"]


def analyze_functionality(
    root: Path,
    project_info: dict,
    tools: dict[str, str | None],
    build_dir: Path,
    plan: AdaptiveExecutionPlan | None = None,
    changes_only: bool = False,
    changed_files: list[str] | None = None,
) -> tuple[list[Finding], list[str], dict]:
    findings: list[Finding] = []
    logs: list[str] = []
    metadata = {
        "configured": False,
        "built": False,
        "tests_ran": False,
        "compile_commands": str(build_dir / "compile_commands.json"),
        "ecosystem_results": {},
    }
    changed_files = changed_files or []
    build_dir.mkdir(parents=True, exist_ok=True)
    runtime_env = build_runtime_env(plan)

    if changes_only:
        metadata["incremental_mode"] = True
        metadata["changed_files_considered"] = changed_files
        findings.append(
            Finding(
                category="functionality",
                severity="info",
                title="Incremental retest mode enabled",
                description="The run is scoped to changed files relative to the previous project upload.",
                source="retest-scope",
                recommendation="Use a full-project retest before release if the changes are large or cross-cutting.",
            )
        )
        if not changed_files:
            findings.append(
                Finding(
                    category="functionality",
                    severity="info",
                    title="No changed source files detected",
                    description="No added or modified analyzable files were found relative to the selected baseline run.",
                    source="retest-diff",
                    recommendation="Use a full-project retest if you still need a full confidence pass.",
                )
            )
            metadata["incremental_summary"] = "No changed analyzable files detected."
            metadata["build_parallelism"] = max(1, plan.build_parallelism if plan else 2)
            metadata["test_parallelism"] = max(1, plan.test_parallelism if plan else 1)
            metadata["assigned_gpu_ids"] = list(plan.assigned_gpu_ids) if plan else []
            metadata["gpu_strategy"] = plan.gpu_strategy if plan else "cpu-only"
            return findings, logs, metadata

        changed_build_files = [relative for relative in changed_files if is_build_manifest(relative)]
        changed_tests = [relative for relative in changed_files if is_test_related_path(relative)]
        metadata["incremental_summary"] = (
            f"Focused functionality retest across {len(changed_files)} changed files; "
            "full configure/build/test was intentionally skipped."
        )
        metadata["changed_build_files"] = changed_build_files
        metadata["changed_test_files"] = changed_tests
        if changed_build_files:
            findings.append(
                Finding(
                    category="functionality",
                    severity="medium",
                    title="Build manifest changed",
                    description="Project build metadata changed, but incremental mode skipped a full build.",
                    source="retest-diff",
                    recommendation="Run a full-project retest to validate the updated build configuration.",
                )
            )
        if changed_tests:
            findings.append(
                Finding(
                    category="functionality",
                    severity="info",
                    title="Test-related files changed",
                    description="Test files were updated in this submission.",
                    source="retest-diff",
                    recommendation="Review the changed tests and run a full-project retest if they affect shared behavior.",
                )
            )
        metadata["build_parallelism"] = max(1, plan.build_parallelism if plan else 2)
        metadata["test_parallelism"] = max(1, plan.test_parallelism if plan else 1)
        metadata["assigned_gpu_ids"] = list(plan.assigned_gpu_ids) if plan else []
        metadata["gpu_strategy"] = plan.gpu_strategy if plan else "cpu-only"
        return findings, logs, metadata

    supported_manifests = {"cmake", "qmake", "python", "go", "node"}

    if "cmake" in project_info.get("build_systems", []):
        ecosystem_metadata = {"configured": False, "built": False, "tests_ran": False, "test_runner": ""}
        if not tools.get("cmake"):
            findings.append(
                Finding(
                    category="functionality",
                    severity="medium",
                    title="CMake project detected but cmake is unavailable",
                    description="The platform detected CMake files but the cmake binary is not installed on this host.",
                    source="toolchain-discovery",
                    recommendation="Install cmake and a compiler toolchain to enable configure/build/test execution.",
                )
            )
        else:
            configure_command = [tools["cmake"], "-S", str(root), "-B", str(build_dir), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
            if tools.get("ninja"):
                configure_command.extend(["-G", "Ninja"])
            result = run_command(configure_command, cwd=root, timeout=180, env=runtime_env)
            _append_command_logs(logs, result)
            if result.returncode != 0:
                findings.append(
                    Finding(
                        category="functionality",
                        severity="high",
                        title="CMake configure failed",
                        description="The project could not be configured from the uploaded sources.",
                        source="cmake",
                        recommendation="Review missing toolchain packages, dependencies, or invalid CMake configuration.",
                    )
                )
            else:
                ecosystem_metadata["configured"] = True
                build_result = run_command(
                    [tools["cmake"], "--build", str(build_dir), "--parallel", str(max(1, plan.build_parallelism if plan else 2))],
                    cwd=root,
                    timeout=300,
                    env=runtime_env,
                )
                _append_command_logs(logs, build_result)
                if build_result.returncode != 0:
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="high",
                            title="Build failed",
                            description="The project configured successfully but the build step failed.",
                            source="cmake-build",
                            recommendation="Review compiler errors and ensure all dependencies are available.",
                        )
                    )
                else:
                    ecosystem_metadata["built"] = True
                    if tools.get("ctest") and (build_dir / "CTestTestfile.cmake").exists():
                        test_result = run_command(
                            [
                                tools["ctest"],
                                "--test-dir",
                                str(build_dir),
                                "--output-on-failure",
                                "--parallel",
                                str(max(1, plan.test_parallelism if plan else 1)),
                            ],
                            cwd=root,
                            timeout=300,
                            env=runtime_env,
                        )
                        _append_command_logs(logs, test_result)
                        ecosystem_metadata["tests_ran"] = True
                        ecosystem_metadata["test_runner"] = "ctest"
                        if test_result.returncode != 0:
                            findings.append(
                                Finding(
                                    category="functionality",
                                    severity="high",
                                    title="Automated tests failed",
                                    description="CTest executed but at least one test returned a non-zero result.",
                                    source="ctest",
                                    recommendation="Inspect failing test output and fix runtime or logic regressions.",
                                )
                            )
        _record_functionality_result(metadata, "cmake", **ecosystem_metadata)
    elif "qmake" in project_info.get("build_systems", []):
        ecosystem_metadata = {"configured": False, "built": False, "tests_ran": False, "test_runner": ""}
        if not tools.get("qmake"):
            findings.append(
                Finding(
                    category="functionality",
                    severity="medium",
                    title="qmake project detected but qmake is unavailable",
                    description="The platform detected qmake files but qmake is not installed on this host.",
                    source="toolchain-discovery",
                    recommendation="Install Qt build tools to execute qmake-based builds.",
                )
            )
        else:
            pro_files = sorted(root.rglob("*.pro"))
            if not pro_files:
                findings.append(
                    Finding(
                        category="functionality",
                        severity="medium",
                        title="qmake project metadata missing",
                        description="A qmake-style project was detected, but no .pro file was found.",
                        source="project-discovery",
                        recommendation="Upload the complete qmake project, including the main .pro file.",
                    )
                )
            else:
                result = run_command(
                    [tools["qmake"], str(pro_files[0])],
                    cwd=build_dir,
                    timeout=180,
                    env=runtime_env,
                )
                _append_command_logs(logs, result)
                if result.returncode != 0:
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="high",
                            title="qmake configure failed",
                            description="The qmake configuration step failed.",
                            source="qmake",
                            recommendation="Review the qmake project file and installed Qt modules.",
                        )
                    )
                else:
                    ecosystem_metadata["configured"] = True
                    build_tool = tools.get("make") or "make"
                    build_result = run_command(
                        [build_tool, f"-j{max(1, plan.build_parallelism if plan else 2)}"],
                        cwd=build_dir,
                        timeout=300,
                        env=runtime_env,
                    )
                    _append_command_logs(logs, build_result)
                    if build_result.returncode != 0:
                        findings.append(
                            Finding(
                                category="functionality",
                                severity="high",
                                title="qmake build failed",
                                description="The project configured via qmake but the build step failed.",
                                source="make",
                                recommendation="Review compiler output and project dependencies.",
                            )
                        )
                    else:
                        ecosystem_metadata["built"] = True
        _record_functionality_result(metadata, "qmake", **ecosystem_metadata)

    if "python" in project_info.get("build_systems", []):
        ecosystem_metadata = {"configured": False, "built": False, "tests_ran": False, "test_runner": ""}
        python_tool = tools.get("python3") or shutil.which("python3")
        if not python_tool:
            findings.append(
                Finding(
                    category="functionality",
                    severity="medium",
                    title="Python project detected but python3 is unavailable",
                    description="Проект содержит Python-манифесты, но интерпретатор python3 не найден на хосте.",
                    source="toolchain-discovery",
                    recommendation="Установите python3 и повторите сканирование для compile/test checks.",
                )
            )
        else:
            compile_result = run_command(
                [python_tool, "-m", "compileall", str(root)],
                cwd=root,
                timeout=240,
                env=runtime_env,
            )
            _append_command_logs(logs, compile_result)
            ecosystem_metadata["configured"] = compile_result.returncode == 0
            ecosystem_metadata["built"] = compile_result.returncode == 0
            if compile_result.returncode != 0:
                findings.append(
                    Finding(
                        category="functionality",
                        severity="high",
                        title="Python syntax or bytecode compilation failed",
                        description="`python -m compileall` завершился с ошибкой.",
                        source="python-compileall",
                        recommendation="Исправьте синтаксические ошибки и несовместимые модули Python.",
                    )
                )
            elif project_info.get("has_tests"):
                test_command = [tools["pytest"], "-q"] if tools.get("pytest") else [python_tool, "-m", "pytest", "-q"]
                test_result = run_command(
                    test_command,
                    cwd=root,
                    timeout=300,
                    env=runtime_env,
                )
                _append_command_logs(logs, test_result)
                ecosystem_metadata["tests_ran"] = True
                ecosystem_metadata["test_runner"] = "pytest"
                pytest_missing = "No module named pytest" in f"{test_result.stdout}\n{test_result.stderr}"
                if test_result.returncode != 0 and pytest_missing:
                    fallback_result = run_command(
                        [python_tool, "-m", "unittest", "discover", "-q"],
                        cwd=root,
                        timeout=300,
                        env=runtime_env,
                    )
                    _append_command_logs(logs, fallback_result)
                    test_result = fallback_result
                    ecosystem_metadata["test_runner"] = "unittest"
                if "Ran 0 tests" in f"{test_result.stdout}\n{test_result.stderr}":
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="medium",
                            title="Python tests were not collected",
                            description="Обнаружены Python-тесты, но test runner не нашел исполняемых тестовых случаев.",
                            source=ecosystem_metadata["test_runner"] or "python-tests",
                            recommendation="Проверьте структуру тестов, naming convention и используемый runner.",
                        )
                    )
                elif test_result.returncode != 0:
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="high",
                            title="Python tests failed",
                            description="Проект прошел compileall, но Python test runner вернул ненулевой код завершения.",
                            source=ecosystem_metadata["test_runner"] or "python-tests",
                            recommendation="Разберите упавшие тесты и устраните регрессии поведения.",
                        )
                    )
        _record_functionality_result(metadata, "python", **ecosystem_metadata)

    if "go" in project_info.get("build_systems", []):
        ecosystem_metadata = {"configured": False, "built": False, "tests_ran": False, "test_runner": ""}
        go_tool = tools.get("go") or shutil.which("go")
        if not go_tool:
            findings.append(
                Finding(
                    category="functionality",
                    severity="medium",
                    title="Go project detected but go toolchain is unavailable",
                    description="Обнаружен `go.mod`, но бинарник `go` не найден.",
                    source="toolchain-discovery",
                    recommendation="Установите Go toolchain для build/test проверок.",
                )
            )
        else:
            go_result = run_command(
                [go_tool, "test", "./..."],
                cwd=root,
                timeout=360,
                env=runtime_env,
            )
            _append_command_logs(logs, go_result)
            ecosystem_metadata["configured"] = go_result.returncode == 0
            ecosystem_metadata["built"] = go_result.returncode == 0
            ecosystem_metadata["tests_ran"] = True
            ecosystem_metadata["test_runner"] = "go test"
            if go_result.returncode != 0:
                findings.append(
                    Finding(
                        category="functionality",
                        severity="high",
                        title="Go tests or build failed",
                        description="`go test ./...` завершился с ошибкой.",
                        source="go-test",
                        recommendation="Исправьте ошибки сборки, импортов или тестов Go-модулей.",
                    )
                )
            else:
                vet_result = run_command(
                    [go_tool, "vet", "./..."],
                    cwd=root,
                    timeout=240,
                    env=runtime_env,
                )
                _append_command_logs(logs, vet_result)
                if vet_result.returncode != 0:
                    findings.append(
                        Finding(
                            category="quality",
                            severity="medium",
                            title="Go vet reported issues",
                            description="`go vet ./...` нашел потенциальные проблемы в коде Go.",
                            source="go-vet",
                            recommendation="Разберите предупреждения go vet и устраните дефекты до релиза.",
                        )
                    )
        _record_functionality_result(metadata, "go", **ecosystem_metadata)

    if "node" in project_info.get("build_systems", []):
        ecosystem_metadata = {"configured": False, "built": False, "tests_ran": False, "test_runner": ""}
        node_tool = tools.get("node") or shutil.which("node")
        js_files = [path for path in iter_text_files(root) if path.suffix.lower() in {".js", ".ts", ".tsx"}][:30]
        if not node_tool:
            findings.append(
                Finding(
                    category="functionality",
                    severity="medium",
                    title="Node/TypeScript project detected but node is unavailable",
                    description="Обнаружен `package.json`, но `node` не найден на хосте.",
                    source="toolchain-discovery",
                    recommendation="Установите Node.js для runtime и syntax checks.",
                )
            )
        else:
            ecosystem_metadata["configured"] = True
            ecosystem_metadata["built"] = True
            for js_file in [path for path in js_files if path.suffix.lower() == ".js"][:10]:
                js_result = run_command(
                    [node_tool, "--check", str(js_file)],
                    cwd=root,
                    timeout=60,
                    env=runtime_env,
                )
                _append_command_logs(logs, js_result)
                if js_result.returncode != 0:
                    ecosystem_metadata["built"] = False
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="high",
                            title="JavaScript syntax check failed",
                            description=f"`node --check` нашел проблему в {js_file.relative_to(root)}.",
                            path=str(js_file.relative_to(root)),
                            source="node-check",
                            recommendation="Исправьте синтаксис JavaScript до запуска следующих стадий.",
                        )
                    )
            tsc_command = _tsc_command(root, tools)
            if tsc_command and any(path.suffix.lower() in {".ts", ".tsx"} for path in js_files):
                ts_result = run_command(
                    tsc_command,
                    cwd=root,
                    timeout=240,
                    env=runtime_env,
                )
                _append_command_logs(logs, ts_result)
                if ts_result.returncode != 0:
                    ecosystem_metadata["built"] = False
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="high",
                            title="TypeScript type check failed",
                            description="`tsc --noEmit` завершился с ошибкой.",
                            source="tsc",
                            recommendation="Исправьте ошибки типизации и конфигурации TypeScript.",
                        )
                    )
            node_test_command, node_test_runner = _node_test_command(root, tools)
            if project_info.get("has_tests") and node_test_command:
                node_test_env = dict(runtime_env)
                node_test_env["CI"] = "1"
                node_test_result = run_command(
                    node_test_command,
                    cwd=root,
                    timeout=300,
                    env=node_test_env,
                )
                _append_command_logs(logs, node_test_result)
                ecosystem_metadata["tests_ran"] = True
                ecosystem_metadata["test_runner"] = node_test_runner
                if node_test_result.returncode != 0:
                    findings.append(
                        Finding(
                            category="functionality",
                            severity="high",
                            title="Node.js tests failed",
                            description="Node.js/TypeScript test runner завершился с ошибкой.",
                            source=node_test_runner or "node-tests",
                            recommendation="Проверьте тестовые зависимости, scripts.test и упавшие сценарии.",
                        )
                    )
            elif project_info.get("has_tests") and (_load_json_file(root / "package.json") or {}).get("scripts", {}).get("test"):
                findings.append(
                    Finding(
                        category="functionality",
                        severity="medium",
                        title="Node.js tests are declared but cannot be executed",
                        description="В package.json найден test script, но локальные test-инструменты или node_modules недоступны.",
                        source="package.json",
                        recommendation="Подготовьте локальные зависимости проекта и повторите test stage.",
                    )
                )
        _record_functionality_result(metadata, "node", **ecosystem_metadata)

    if not set(project_info.get("build_systems", [])) & supported_manifests:
        findings.append(
            Finding(
                category="functionality",
                severity="info",
                title="No supported build manifest detected",
                description="The upload does not contain a supported build or ecosystem manifest for CMake, qmake, Python, Go, or Node.js.",
                source="project-discovery",
                recommendation="Upload a full project with build metadata for deeper execution checks.",
            )
        )

    if project_info.get("is_qt_project") and not project_info.get("has_tests"):
        findings.append(
            Finding(
                category="functionality",
                severity="medium",
                title="Qt project without obvious automated tests",
                description="Qt markers were found, but no Qt Test entry points were detected.",
                source="project-discovery",
                recommendation="Add Qt Test or Qt Quick Test suites to validate runtime behavior.",
            )
        )

    metadata["build_parallelism"] = max(1, plan.build_parallelism if plan else 2)
    metadata["test_parallelism"] = max(1, plan.test_parallelism if plan else 1)
    metadata["assigned_gpu_ids"] = list(plan.assigned_gpu_ids) if plan else []
    metadata["gpu_strategy"] = plan.gpu_strategy if plan else "cpu-only"
    return findings, logs, metadata


# Пытаемся выполнить отдельный инструментированный прогон через sanitizer-сборку.
def analyze_dynamic(
    root: Path,
    project_info: dict,
    tools: dict[str, str | None],
    build_dir: Path,
    output_dir: Path,
    functionality_meta: dict[str, Any] | None,
    plan: AdaptiveExecutionPlan | None = None,
) -> tuple[list[Finding], list[Artifact], list[str], dict[str, Any]]:
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    logs: list[str] = []
    metadata: dict[str, Any] = {
        "eligible": False,
        "sanitizer_configured": False,
        "sanitizer_built": False,
        "sanitizer_tests_ran": False,
        "valgrind_available": bool(tools.get("valgrind")),
    }
    runtime_env = build_runtime_env(plan)
    report_lines = [
        "# Dynamic analysis",
        "",
        f"Build systems: {', '.join(project_info.get('build_systems', [])) or 'none'}",
        f"Configured in primary build: {'yes' if functionality_meta and functionality_meta.get('configured') else 'no'}",
        f"Built in primary build: {'yes' if functionality_meta and functionality_meta.get('built') else 'no'}",
        f"Primary tests ran: {'yes' if functionality_meta and functionality_meta.get('tests_ran') else 'no'}",
        f"Valgrind available: {'yes' if tools.get('valgrind') else 'no'}",
        "",
    ]

    if not functionality_meta or not functionality_meta.get("configured") or not functionality_meta.get("built"):
        findings.append(
            Finding(
                category="dynamic",
                severity="info",
                title="Instrumented dynamic analysis skipped",
                description="Dynamic instrumentation requires the primary configure/build stage to succeed first.",
                source="dynamic-analysis",
                recommendation="Fix configure/build blockers, then re-run to unlock sanitizer-backed checks.",
            )
        )
        report_lines.append("Instrumented run skipped because the main build was not ready.")
        dynamic_report = output_dir / "dynamic_analysis.md"
        dynamic_report.write_text("\n".join(report_lines).strip() + "\n", encoding="utf-8")
        artifacts.append(Artifact(label="Dynamic analysis plan", filename=dynamic_report.name, kind="text"))
        return findings, artifacts, logs, metadata

    metadata["eligible"] = True
    build_systems = set(project_info.get("build_systems", []))
    if "cmake" in build_systems and tools.get("cmake") and tools.get("clangxx"):
        sanitizer_dir = build_dir.parent / "build_sanitized"
        sanitizer_flags = "-fsanitize=address,undefined -fno-omit-frame-pointer"
        configure_command = [
            tools["cmake"],
            "-S",
            str(root),
            "-B",
            str(sanitizer_dir),
            f"-DCMAKE_CXX_COMPILER={tools['clangxx']}",
            f"-DCMAKE_CXX_FLAGS={sanitizer_flags}",
            f"-DCMAKE_C_FLAGS={sanitizer_flags}",
            f"-DCMAKE_EXE_LINKER_FLAGS={sanitizer_flags}",
        ]
        if tools.get("clang"):
            configure_command.append(f"-DCMAKE_C_COMPILER={tools['clang']}")
        if tools.get("ninja"):
            configure_command.extend(["-G", "Ninja"])
        configure_result = run_command(configure_command, cwd=root, timeout=240, env=runtime_env)
        logs.append(f"$ {' '.join(configure_result.command)}")
        if configure_result.stdout.strip():
            logs.append(configure_result.stdout.strip())
        if configure_result.stderr.strip():
            logs.append(configure_result.stderr.strip())
        if configure_result.returncode != 0:
            findings.append(
                Finding(
                    category="dynamic",
                    severity="medium",
                    title="Sanitizer configure failed",
                    description="The instrumented CMake configure step did not complete successfully.",
                    source="dynamic-analysis",
                    recommendation="Review compiler or dependency issues that prevent sanitizer builds.",
                )
            )
            report_lines.append("Sanitizer configure: failed")
        else:
            metadata["sanitizer_configured"] = True
            report_lines.append("Sanitizer configure: passed")
            build_result = run_command(
                [
                    tools["cmake"],
                    "--build",
                    str(sanitizer_dir),
                    "--parallel",
                    str(max(1, plan.build_parallelism if plan else 2)),
                ],
                cwd=root,
                timeout=480,
                env=runtime_env,
            )
            logs.append(f"$ {' '.join(build_result.command)}")
            if build_result.stdout.strip():
                logs.append(build_result.stdout.strip())
            if build_result.stderr.strip():
                logs.append(build_result.stderr.strip())
            if build_result.returncode != 0:
                findings.append(
                    Finding(
                        category="dynamic",
                        severity="medium",
                        title="Sanitizer build failed",
                        description="The instrumented build failed before dynamic checks could run.",
                        source="dynamic-analysis",
                        recommendation="Fix the sanitizer build errors and rerun the analysis.",
                    )
                )
                report_lines.append("Sanitizer build: failed")
            else:
                metadata["sanitizer_built"] = True
                report_lines.append("Sanitizer build: passed")
                ctest_path = sanitizer_dir / "CTestTestfile.cmake"
                if tools.get("ctest") and ctest_path.exists():
                    test_result = run_command(
                        [
                            tools["ctest"],
                            "--test-dir",
                            str(sanitizer_dir),
                            "--output-on-failure",
                            "--parallel",
                            str(max(1, plan.test_parallelism if plan else 1)),
                        ],
                        cwd=root,
                        timeout=480,
                        env=runtime_env,
                    )
                    logs.append(f"$ {' '.join(test_result.command)}")
                    if test_result.stdout.strip():
                        logs.append(test_result.stdout.strip())
                    if test_result.stderr.strip():
                        logs.append(test_result.stderr.strip())
                    metadata["sanitizer_tests_ran"] = True
                    if test_result.returncode != 0:
                        findings.append(
                            Finding(
                                category="dynamic",
                                severity="high",
                                title="Sanitizer-backed tests failed",
                                description="The instrumented test run reported at least one runtime failure.",
                                source="dynamic-analysis",
                                recommendation="Inspect sanitizer output and fix memory or undefined-behavior defects before release.",
                            )
                        )
                        report_lines.append("Sanitizer tests: failed")
                    else:
                        findings.append(
                            Finding(
                                category="dynamic",
                                severity="info",
                                title="Sanitizer-backed tests passed",
                                description="The instrumented test run completed without detected sanitizer failures.",
                                source="dynamic-analysis",
                                recommendation="Keep sanitizer runs in the CI gate for changed native modules.",
                            )
                        )
                        report_lines.append("Sanitizer tests: passed")
                else:
                    findings.append(
                        Finding(
                            category="dynamic",
                            severity="info",
                            title="No instrumented tests available",
                            description="The sanitizer build completed, but no CTest entry points were available in the instrumented build.",
                            source="dynamic-analysis",
                            recommendation="Add automated tests to make instrumented dynamic analysis meaningful.",
                        )
                    )
                    report_lines.append("Sanitizer tests: no CTest targets found")
    else:
        findings.append(
            Finding(
                category="dynamic",
                severity="info",
                title="Instrumented run not supported for detected build layout",
                description="The current dynamic analysis implementation is optimized for CMake builds with Clang available.",
                source="dynamic-analysis",
                recommendation="Use a CMake+Clang toolchain or extend the dynamic runner for the current build system.",
            )
        )
        report_lines.append("Instrumented run not attempted because the detected build layout is not yet supported.")

    if tools.get("valgrind"):
        report_lines.append("Valgrind is installed and can be used for follow-up targeted runtime sessions.")

    dynamic_report = output_dir / "dynamic_analysis.md"
    dynamic_report.write_text("\n".join(report_lines).strip() + "\n", encoding="utf-8")
    artifacts.append(Artifact(label="Dynamic analysis", filename=dynamic_report.name, kind="text"))
    metadata["report"] = dynamic_report.name
    return findings, artifacts, logs, metadata


def discover_fuzz_targets(files: list[Path], root: Path) -> list[str]:
    targets: list[str] = []
    for path in files:
        relative = str(path.relative_to(root))
        content = safe_read_text(path)
        name = path.name.lower()
        if "fuzz" in name or "LLVMFuzzerTestOneInput" in content or "AFL_LOOP" in content:
            targets.append(relative)
    return targets


def generate_harness(target: str) -> str:
    return textwrap.dedent(
        f"""\
        #include <cstddef>
        #include <cstdint>
        #include <string>

        // Автоматически сгенерированный стартовый harness для: {target}
        // Замените участки TODO на вызов парсера или API, который нужно фаззить.
        extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {{
            std::string input(reinterpret_cast<const char*>(data), size);

            // TODO: передайте `input` в парсер, декодер или Qt-ориентированный API под тестом.
            // Пример:
            // TargetParser parser;
            // parser.parse(input);

            return 0;
        }}
        """
    )


def analyze_fuzzing(
    root: Path,
    files: list[Path],
    tools: dict[str, str | None],
    mode: str,
    output_dir: Path,
    duration_seconds: int,
    plan: AdaptiveExecutionPlan | None = None,
    focus_files: list[Path] | None = None,
) -> tuple[list[Finding], list[Artifact], list[str]]:
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    logs: list[str] = []
    focus_mode = focus_files is not None
    focus_files = focus_files or []
    scan_files = focus_files if focus_mode else files
    targets = discover_fuzz_targets(scan_files, root)

    if targets:
        findings.append(
            Finding(
                category="fuzzing",
                severity="info",
                title="Existing fuzz target markers detected",
                description=f"Detected {len(targets)} candidate fuzz target files.",
                source="project-discovery",
                recommendation="Wire these targets into AFL++ or libFuzzer execution when toolchain binaries are available.",
            )
        )
    else:
        findings.append(
            Finding(
                category="fuzzing",
                severity="medium",
                title="No existing fuzz target discovered",
                description="The project does not expose a ready-made fuzz harness.",
                source="project-discovery",
                recommendation="Add at least one harness with LLVMFuzzerTestOneInput or an AFL-compatible wrapper.",
            )
        )
    if focus_mode:
        findings.append(
            Finding(
                category="fuzzing",
                severity="info",
                title="Targeted fuzzing scope",
                description=f"Fuzzing preparation focused on {len(focus_files)} changed files from the current retest.",
                source="retest-scope",
                recommendation="Run a full-project fuzz assessment after the focused retest if the parser surface expanded.",
            )
        )

    harness_target = targets[0] if targets else next(
        (
            str(path.relative_to(root))
            for path in scan_files
            if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}
        ),
        "target.cpp",
    )
    harness_path = output_dir / "generated_fuzz_harness.cpp"
    harness_path.write_text(generate_harness(harness_target), encoding="utf-8")
    artifacts.append(Artifact(label="Generated fuzz harness", filename=harness_path.name, kind="code"))

    plan_path = output_dir / "fuzz_plan.md"
    plan_text = textwrap.dedent(
        f"""\
        # Fuzzing plan

        Mode: {mode}
        Planned time budget: {duration_seconds} seconds
        CPU threads budget: {plan.cpu_threads_for_job if plan else 1}
        GPU assignment: {", ".join(str(item) for item in plan.assigned_gpu_ids) if plan and plan.assigned_gpu_ids else "cpu-only"}
        GPU strategy: {plan.gpu_strategy if plan else "cpu-only"}

        Detected target candidates:
        {chr(10).join(f"- {target}" for target in targets) if targets else "- No explicit fuzz targets detected"}

        Tool availability:
        - afl-fuzz: {"yes" if tools.get("afl_fuzz") else "no"}
        - clang++: {"yes" if tools.get("clangxx") else "no"}

        Recommended next steps:
        - Build at least one dedicated fuzz target for the parser or decoding boundary that handles untrusted input.
        - Enable AddressSanitizer and UndefinedBehaviorSanitizer during fuzz builds.
        - Seed the corpus with valid and edge-case project inputs.
        - Run time-boxed fuzzing in isolated workers, then merge crashes into the main report.
        """
    )
    plan_path.write_text(plan_text, encoding="utf-8")
    artifacts.append(Artifact(label="Fuzzing plan", filename=plan_path.name, kind="text"))

    if not tools.get("afl_fuzz") or not tools.get("clangxx"):
        findings.append(
            Finding(
                category="fuzzing",
                severity="medium",
                title="Fuzz execution skipped",
                description="Runtime fuzzing requires afl-fuzz and clang++ on the host.",
                source="toolchain-discovery",
                recommendation="Install AFL++ and LLVM/Clang to enable executable fuzz sessions.",
            )
        )
    elif not targets:
        findings.append(
            Finding(
                category="fuzzing",
                severity="medium",
                title="Fuzz execution skipped because no harness exists",
                description="The platform can prepare fuzzing, but it needs at least one runnable harness.",
                source="project-discovery",
                recommendation="Implement a fuzz harness and re-run the job.",
            )
        )
    else:
        logs.append(
            "Fuzzing toolchain detected. This build prepares the plan and harness artifacts; "
            f"full automated execution can be time-boxed to {duration_seconds} seconds in the next iteration."
        )
        if plan and plan.assigned_gpu_ids:
            logs.append(
                "GPU devices reserved for future GPU-capable fuzz or acceleration-aware test stages: "
                + ", ".join(str(item) for item in plan.assigned_gpu_ids)
            )

    return findings, artifacts, logs


def highest_severity(severity_counts: dict[str, int]) -> str:
    for severity in ("critical", "high", "medium", "low", "info"):
        if severity_counts.get(severity, 0):
            return severity
    return "info"


def risk_score(severity_counts: dict[str, int]) -> int:
    raw_score = (
        severity_counts.get("critical", 0) * 40
        + severity_counts.get("high", 0) * 22
        + severity_counts.get("medium", 0) * 10
        + severity_counts.get("low", 0) * 4
        + severity_counts.get("info", 0)
    )
    return min(raw_score, 100)


def execution_verdict(functionality: dict | None, project_info: dict | None) -> str:
    if not functionality:
        return "not-run"
    if functionality.get("configured") and functionality.get("built"):
        if project_info and project_info.get("has_tests"):
            return "build-and-tests-ran" if functionality.get("tests_ran") else "build-passed-tests-missing"
        return "build-passed"
    if functionality.get("configured"):
        return "configured-only"
    return "blocked"


def next_actions(findings: list[Finding]) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    seen: set[str] = set()
    ordered = sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER[item.severity], item.category, item.path, item.line or 0),
        reverse=True,
    )
    for finding in ordered:
        recommendation = finding.recommendation or f"Review {finding.title}."
        if recommendation in seen:
            continue
        seen.add(recommendation)
        actions.append(
            {
                "severity": finding.severity,
                "title": finding.title,
                "recommendation": recommendation,
            }
        )
        if len(actions) == 5:
            break
    return actions


def summarize_findings(
    findings: list[Finding],
    *,
    functionality: dict | None = None,
    project_info: dict | None = None,
    selected_checks: list[str] | None = None,
) -> dict:
    severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    category_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.severity] += 1
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
    sorted_findings = sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER[item.severity], item.category, item.path, item.line or 0),
        reverse=True,
    )
    category_breakdown = [
        {"category": category, "count": count}
        for category, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "category_breakdown": category_breakdown,
        "total_findings": len(findings),
        "highest_severity": highest_severity(severity_counts),
        "risk_score": risk_score(severity_counts),
        "execution_verdict": execution_verdict(functionality, project_info),
        "selected_checks": selected_checks or [],
        "next_actions": next_actions(findings),
        "top_findings": [finding.__dict__ for finding in sorted_findings[:20]],
    }
