from __future__ import annotations

import hashlib
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
CODE_FRAGMENT_KEYWORDS = re.compile(
    r"\b("
    r"if|else|for|while|switch|case|return|class|struct|namespace|template|typedef|using|const|auto|void|"
    r"int|char|float|double|bool|QString|QObject|QWidget|signals|slots|public|private|protected"
    r")\b"
)
FUNCTION_LIKE_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_:<>]*\s*\(")
DECLARATION_LIKE_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_:<>*&]+\s+[A-Za-z_][A-Za-z0-9_]*\s*(=|;)")
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
        if path.suffix.lower() in SOURCE_EXTENSIONS or path.name in {"CMakeLists.txt"}:
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
    return path.name == "CMakeLists.txt" or path.suffix.lower() in {".pro", ".pri", ".cmake"}


def is_test_related_path(relative_path: str) -> bool:
    lowered = relative_path.casefold()
    name = Path(relative_path).name.casefold()
    return "/tests/" in f"/{lowered}/" or name.startswith("test") or "_test" in name or "qtest" in lowered


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

    for path in files:
        extension_counts[path.suffix.lower() or path.name] = extension_counts.get(path.suffix.lower() or path.name, 0) + 1
        if path.name == "CMakeLists.txt":
            build_systems.add("cmake")
        if path.suffix.lower() in {".pro", ".pri"}:
            build_systems.add("qmake")
        content = safe_read_text(path)
        if any(marker in content for marker in ("Qt6::", "Qt5::", "QApplication", "QWidget", "QObject", "QML_ELEMENT", "QT +=")):
            qt_markers += 1
        if any(marker in content for marker in ("QTEST_MAIN", "QTEST_APPLESS_MAIN", "add_test(", "Qt6::Test", "Qt5::Test")):
            test_markers += 1
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


def _analyze_security_file(root: Path, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    content = safe_read_text(path)
    if not content:
        return findings
    relative = str(path.relative_to(root))
    for pattern, severity, title, recommendation in SECURITY_PATTERNS:
        for match in re.finditer(pattern, content, flags=re.IGNORECASE):
            line = line_number_for_offset(content, match.start())
            findings.append(
                Finding(
                    category="security",
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=f"Matched pattern `{match.group(0)}` in source.",
                    path=relative,
                    line=line,
                    source="built-in-security-rules",
                    recommendation=recommendation,
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

    if "cmake" in project_info.get("build_systems", []):
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
            logs.append(f"$ {' '.join(result.command)}")
            if result.stdout.strip():
                logs.append(result.stdout.strip())
            if result.stderr.strip():
                logs.append(result.stderr.strip())
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
                metadata["configured"] = True
                build_result = run_command(
                    [tools["cmake"], "--build", str(build_dir), "--parallel", str(max(1, plan.build_parallelism if plan else 2))],
                    cwd=root,
                    timeout=300,
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
                            category="functionality",
                            severity="high",
                            title="Build failed",
                            description="The project configured successfully but the build step failed.",
                            source="cmake-build",
                            recommendation="Review compiler errors and ensure all dependencies are available.",
                        )
                    )
                else:
                    metadata["built"] = True
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
                        logs.append(f"$ {' '.join(test_result.command)}")
                        if test_result.stdout.strip():
                            logs.append(test_result.stdout.strip())
                        if test_result.stderr.strip():
                            logs.append(test_result.stderr.strip())
                        metadata["tests_ran"] = True
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
    elif "qmake" in project_info.get("build_systems", []):
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
                logs.append(f"$ {' '.join(result.command)}")
                if result.stdout.strip():
                    logs.append(result.stdout.strip())
                if result.stderr.strip():
                    logs.append(result.stderr.strip())
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
                    metadata["configured"] = True
                    build_tool = tools.get("make") or "make"
                    build_result = run_command(
                        [build_tool, f"-j{max(1, plan.build_parallelism if plan else 2)}"],
                        cwd=build_dir,
                        timeout=300,
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
                                category="functionality",
                                severity="high",
                                title="qmake build failed",
                                description="The project configured via qmake but the build step failed.",
                                source="make",
                                recommendation="Review compiler output and project dependencies.",
                            )
                        )
                    else:
                        metadata["built"] = True
    else:
        findings.append(
            Finding(
                category="functionality",
                severity="info",
                title="No supported build manifest detected",
                description="The upload does not contain CMakeLists.txt or qmake project files.",
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
