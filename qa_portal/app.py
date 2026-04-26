from __future__ import annotations

from dataclasses import asdict
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import PROJECT_NAME, PROJECT_VERSION
from .analysis import is_archive
from .audit import append_audit_event, audit_actor_from_request, audit_status, request_audit_details
from .auth import AuthContext, authenticate_request, auth_status
from .ai_review import ai_backend_status, probe_ai_backend, start_local_model_download
from .config import (
    AUTOSTART_WORKER,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_FILES,
    STALE_RUNNING_SECONDS,
    STATIC_DIR,
    TEMPLATES_DIR,
    UPLOAD_DIR,
    save_ai_settings,
)
from .dependency_analysis import dependency_suppression_status, save_dependency_suppressions
from .environment import build_environment_status
from .finding_lifecycle import VALID_REVIEW_STATES, set_review_state
from .hardware import detect_host_hardware, recommended_worker_processes
from .i18n import (
    DEFAULT_LANGUAGE,
    LANG_COOKIE_NAME,
    SUPPORTED_LANGUAGES,
    build_ui_i18n,
    normalize_language,
    translate,
    translate_value,
)
from .integrations import (
    integration_status,
    record_integration_event,
    save_integration_settings,
)
from .knowledge_base import (
    knowledge_base_status,
    start_background_knowledge_base_sync,
    start_knowledge_base_scheduler,
    stop_knowledge_base_scheduler,
)
from .models import JobOptions, JobRecord
from .network import cors_headers, host_allowed, network_access_status, origin_allowed
from .presets import list_presets, normalize_preset_name, preset_options
from .release_gate import release_gate_policy_status, save_release_gate_policy
from .runtime import CURRENT_RUNTIME_SIGNATURE
from .runtime_logs import runtime_log_status
from .storage import JobStore, default_steps
from .tooling import (
    describe_toolchain,
    detect_toolchain,
    dry_run_host_tool,
    list_tool_install_jobs,
    start_tool_install_job,
    tool_install_job_status,
    tool_install_preflight,
)


app = FastAPI(title=PROJECT_NAME, version=PROJECT_VERSION)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
store = JobStore()


# Блок локализации: определяем язык из query-параметра или cookie.
def resolve_language(request: Request) -> str:
    requested = request.query_params.get("lang")
    if requested in SUPPORTED_LANGUAGES:
        return requested
    cookie_value = request.cookies.get(LANG_COOKIE_NAME)
    if cookie_value in SUPPORTED_LANGUAGES:
        return cookie_value
    return DEFAULT_LANGUAGE


def build_lang_switch_urls(request: Request) -> dict[str, str]:
    return {
        code: str(request.url.include_query_params(lang=code))
        for code in SUPPORTED_LANGUAGES
    }


def build_modes(language: str) -> list[tuple[str, str]]:
    return [
        ("full_scan", translate_value(language, "mode", "full_scan")),
        ("fuzz_single", translate_value(language, "mode", "fuzz_single")),
        ("fuzz_project", translate_value(language, "mode", "fuzz_project")),
    ]


def build_review_state_choices(language: str) -> list[tuple[str, str]]:
    ordered_states = ("open", "accepted-risk", "false-positive", "muted", "fixed-intended")
    return [
        (state, translate_value(language, "review_state", state))
        for state in ordered_states
        if state in VALID_REVIEW_STATES
    ]


def template_context(request: Request, data: dict) -> dict:
    language = resolve_language(request)
    request_auth = getattr(request.state, "auth", AuthContext(enabled=False, username="local", role="admin"))
    return {
        **data,
        "lang": language,
        "tr": lambda text, **kwargs: translate(language, text, **kwargs),
        "label": lambda category, value: translate_value(language, category, value),
        "lang_switch_urls": build_lang_switch_urls(request),
        "ui_i18n": build_ui_i18n(language),
        "auth": {
            "enabled": request_auth.enabled,
            "username": request_auth.username,
            "role": request_auth.role,
            "is_admin": request_auth.is_admin,
        },
    }


@app.middleware("http")
async def persist_language_cookie(request: Request, call_next):
    response = await call_next(request)
    requested = request.query_params.get("lang")
    if requested in SUPPORTED_LANGUAGES:
        response.set_cookie(
            LANG_COOKIE_NAME,
            requested,
            max_age=365 * 24 * 60 * 60,
            samesite="lax",
        )
    return response


@app.middleware("http")
async def enforce_access_control(request: Request, call_next):
    authenticated = authenticate_request(request)
    if isinstance(authenticated, Response):
        if request.headers.get("authorization"):
            append_audit_event(
                "auth.login",
                outcome="denied",
                actor={"username": "unknown", "role": "unknown", "client": getattr(request.client, "host", "") or ""},
                resource_type="auth",
                details={
                    **request_audit_details(request),
                    "status_code": authenticated.status_code,
                },
            )
        return authenticated
    request.state.auth = authenticated
    if authenticated.enabled and request.headers.get("authorization"):
        append_audit_event(
            "auth.login",
            actor=audit_actor_from_request(request),
            resource_type="auth",
            details=request_audit_details(request),
        )
    return await call_next(request)


@app.middleware("http")
async def enforce_network_policy(request: Request, call_next):
    if not host_allowed(request.headers.get("host", "")):
        return Response("Host header is not allowed.", status_code=400)

    origin = request.headers.get("origin", "")
    if request.method.upper() == "OPTIONS" and origin and request.headers.get("access-control-request-method"):
        if not origin_allowed(origin):
            return Response("CORS origin is not allowed.", status_code=403)
        response = Response(status_code=204)
        for header, value in cors_headers(origin, request.headers.get("access-control-request-headers", "")).items():
            response.headers[header] = value
        return response

    response = await call_next(request)
    for header, value in cors_headers(origin).items():
        response.headers[header] = value
    return response


@app.on_event("startup")
async def app_startup() -> None:
    recover_stale_jobs()
    start_knowledge_base_scheduler()


@app.on_event("shutdown")
async def app_shutdown() -> None:
    stop_knowledge_base_scheduler()


# Небольшие утилиты UI и очереди, которые переиспользуются в маршрутах и шаблонах.
def worker_mode() -> str:
    return "autostart-subprocess" if AUTOSTART_WORKER else "external-worker"


def recover_stale_jobs() -> list[JobRecord]:
    return store.recover_stale_running(STALE_RUNNING_SECONDS)


def current_base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def parse_checkbox(value: str | None) -> bool:
    return value in {"on", "true", "1", "yes"}


def normalize_timeout_seconds(value: int | str | None, *, default: int = 3) -> int:
    try:
        normalized = int(value or default)
    except (TypeError, ValueError):
        normalized = default
    return max(1, min(normalized, 30))


def normalize_runtime_request_headers(value: str) -> dict[str, str] | str:
    normalized = value.strip()
    if not normalized:
        return ""
    try:
        payload = json.loads(normalized)
    except ValueError:
        return normalized
    if not isinstance(payload, dict):
        return normalized
    return {
        str(key).strip(): str(item).strip()
        for key, item in payload.items()
        if str(key).strip() and str(item).strip()
    }


def requested_runtime_auth_mode(payload: dict[str, Any]) -> str:
    if str(payload.get("basic_auth_username", "")).strip() and str(payload.get("basic_auth_password", "")).strip():
        return "basic"
    if str(payload.get("auth_token", "")).strip():
        header_name = str(payload.get("auth_header_name", "Authorization")).strip() or "Authorization"
        token_prefix = str(payload.get("auth_token_prefix", "Bearer")).strip()
        if header_name.lower() == "authorization" and token_prefix.casefold() == "bearer":
            return "bearer"
        return "header"
    if str(payload.get("auth_cookie_name", "")).strip() and str(payload.get("auth_cookie", "")).strip():
        return "cookie"
    return "none"


def build_service_runtime_request(
    *,
    service_target_url: str,
    service_runtime_profile: str,
    service_request_timeout_seconds: int,
    auth_token: str,
    auth_header_name: str,
    auth_token_prefix: str,
    basic_auth_username: str,
    basic_auth_password: str,
    auth_cookie_name: str,
    auth_cookie: str,
    service_request_headers: str,
) -> dict[str, Any]:
    payload = {
        "target_url": service_target_url.strip(),
        "service_runtime_profile": "safe-active" if service_runtime_profile.strip().casefold() == "safe-active" else "passive",
        "request_timeout_seconds": normalize_timeout_seconds(service_request_timeout_seconds),
        "auth_token": auth_token.strip(),
        "auth_header_name": auth_header_name.strip() or "Authorization",
        "auth_token_prefix": auth_token_prefix.strip() or "Bearer",
        "basic_auth_username": basic_auth_username.strip(),
        "basic_auth_password": basic_auth_password.strip(),
        "auth_cookie_name": auth_cookie_name.strip(),
        "auth_cookie": auth_cookie.strip(),
        "request_headers": normalize_runtime_request_headers(service_request_headers),
    }
    meaningful = (
        payload["target_url"]
        or payload["service_runtime_profile"] != "passive"
        or payload["request_timeout_seconds"] != 3
        or payload["auth_token"]
        or payload["basic_auth_username"]
        or payload["basic_auth_password"]
        or payload["auth_cookie_name"]
        or payload["auth_cookie"]
        or payload["request_headers"]
    )
    return payload if meaningful else {}


def build_service_runtime_public_summary(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload:
        return {}
    profile = str(payload.get("service_runtime_profile") or payload.get("verification_profile") or "passive").strip()
    normalized_profile = "safe-active" if profile.casefold() == "safe-active" else "passive"
    request_headers = payload.get("request_headers", "")
    has_custom_headers = bool(payload.get("has_custom_headers")) or (
        bool(request_headers) if isinstance(request_headers, dict) else bool(str(request_headers).strip())
    )
    auth_mode_requested = str(payload.get("auth_mode_requested", "")).strip() or requested_runtime_auth_mode(payload)
    summary = {
        "target_url": str(payload.get("target_url", "")).strip(),
        "service_runtime_profile": normalized_profile,
        "request_timeout_seconds": normalize_timeout_seconds(payload.get("request_timeout_seconds", 3)),
        "auth_mode_requested": auth_mode_requested or "none",
        "has_custom_headers": has_custom_headers,
    }
    meaningful = (
        summary["target_url"]
        or summary["service_runtime_profile"] != "passive"
        or summary["request_timeout_seconds"] != 3
        or summary["auth_mode_requested"] != "none"
        or summary["has_custom_headers"]
    )
    if not meaningful:
        return {}
    return summary


def normalize_project_key(filename: str) -> str:
    normalized = Path(filename.strip() or "upload").name.casefold()
    archive_suffixes = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar", ".gz", ".bz2", ".xz")
    for suffix in archive_suffixes:
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            return normalized[: -len(suffix)]
    return normalized


def related_jobs_for_project(project_key: str, *, exclude_job_ids: set[str] | None = None) -> list[JobRecord]:
    excluded = exclude_job_ids or set()
    related = [
        job for job in store.list()
        if job.id not in excluded
        and (job.metadata.get("project_key") or normalize_project_key(job.original_filename)) == project_key
    ]
    return sorted(related, key=lambda job: job.created_at, reverse=True)


def latest_baseline_for(project_key: str, *, exclude_job_ids: set[str] | None = None) -> JobRecord | None:
    candidates = [
        job
        for job in related_jobs_for_project(project_key, exclude_job_ids=exclude_job_ids)
        if Path(job.upload_path).exists()
    ]
    return candidates[0] if candidates else None


def repeat_submission_catalog(jobs: list[JobRecord]) -> list[dict[str, str]]:
    seen: set[str] = set()
    catalog: list[dict[str, str]] = []
    for job in sorted(jobs, key=lambda item: item.created_at, reverse=True):
        project_key = job.metadata.get("project_key") or normalize_project_key(job.original_filename)
        if project_key in seen:
            continue
        seen.add(project_key)
        catalog.append(
            {
                "project_key": project_key,
                "original_filename": job.original_filename,
            }
        )
    return catalog


def dashboard_overview(jobs: list[JobRecord]) -> dict[str, int]:
    return {
        "total_jobs": len(jobs),
        "running_jobs": sum(1 for job in jobs if job.status == "running"),
        "paused_jobs": sum(1 for job in jobs if job.status == "paused"),
        "queued_jobs": sum(1 for job in jobs if job.status == "queued"),
        "completed_jobs": sum(1 for job in jobs if job.status == "completed"),
        "failed_jobs": sum(1 for job in jobs if job.status == "failed"),
        "risky_jobs": sum(
            1 for job in jobs if any(finding.severity in {"critical", "high"} for finding in job.findings)
        ),
    }


def start_background_job(job_id: str) -> None:
    del job_id
    if not AUTOSTART_WORKER:
        return
    env = os.environ.copy()
    subprocess.Popen(
        [sys.executable, "-m", "qa_portal.worker", "once"],
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )


def sanitize_return_path(target: str | None) -> str:
    if not target:
        return "/"
    if not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


def sort_findings(job: JobRecord):
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return sorted(
        job.findings,
        key=lambda item: (severity_order.get(item.severity, 0), item.category, item.path, item.line or 0),
        reverse=True,
    )


def serialize_job(job: JobRecord, *, include_findings: bool = False) -> dict:
    payload = job.to_dict()
    metadata = dict(payload.get("metadata", {}))
    public_runtime_summary = build_service_runtime_public_summary(
        dict(job.metadata.get("service_runtime_request", {})) or dict(metadata.get("service_runtime_request_public", {}))
    )
    if public_runtime_summary:
        metadata["service_runtime_request_public"] = public_runtime_summary
    else:
        metadata.pop("service_runtime_request_public", None)
    metadata.pop("service_runtime_request", None)
    payload["metadata"] = metadata
    payload["selected_checks"] = job.options.enabled_checks(job.mode)
    payload["report_preview_url"] = f"/jobs/{job.id}/artifacts/{job.html_report}" if job.html_report else None
    payload["view_report_url"] = f"/jobs/{job.id}/report" if job.html_report else None
    payload["can_rerun"] = Path(job.upload_path).exists()
    payload["queue_controls_enabled"] = job.status in {"queued", "paused"}
    payload["can_delete"] = job.status != "running"
    payload["project_key"] = job.metadata.get("project_key") or normalize_project_key(job.original_filename)
    if include_findings:
        payload["sorted_findings"] = [finding.__dict__ for finding in sort_findings(job)]
    return payload


def allowed_artifact_names(job: JobRecord) -> set[str]:
    names = {
        Path(name).name
        for name in [job.html_report, job.pdf_report]
        if name
    }
    names.update(Path(artifact.filename).name for artifact in job.artifacts if artifact.filename)
    return {name for name in names if name}


def filter_jobs(
    jobs: list[JobRecord],
    *,
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
) -> list[JobRecord]:
    normalized_query = query.strip().casefold()
    filtered: list[JobRecord] = []
    for job in jobs:
        if normalized_query:
            haystack = " ".join([job.id, job.name, job.original_filename]).casefold()
            if normalized_query not in haystack:
                continue
        if status != "all" and job.status != status:
            continue
        if mode != "all" and job.mode != mode:
            continue
        if preset != "all" and job.options.preset != preset:
            continue
        filtered.append(job)
    return filtered


def queue_ordered_jobs(jobs: list[JobRecord]) -> list[JobRecord]:
    status_rank = {
        "running": 0,
        "queued": 1,
        "paused": 2,
        "failed": 3,
        "completed": 4,
        "cancelled": 5,
    }
    return sorted(
        jobs,
        key=lambda job: (
            status_rank.get(job.status, 99),
            job.queue_position if job.queue_position > 0 else 10**9,
            job.created_at,
        ),
    )


def build_job_options(
    *,
    preset: str,
    mode: str,
    retest_scope: str | None,
    run_functionality: str | None,
    run_security: str | None,
    run_style: str | None,
    run_quality: str | None,
    run_fuzzing: str | None,
    fuzz_duration_seconds: int,
    max_report_findings: int,
) -> JobOptions:
    normalized_preset = normalize_preset_name(preset)
    options = preset_options(normalized_preset, mode)
    options.preset = normalized_preset
    if retest_scope in {"full_project", "changes_only"}:
        options.retest_scope = retest_scope  # type: ignore[assignment]
    if run_functionality is not None:
        options.run_functionality = parse_checkbox(run_functionality)
    if run_security is not None:
        options.run_security = parse_checkbox(run_security)
    if run_style is not None:
        options.run_style = parse_checkbox(run_style)
    if run_quality is not None:
        options.run_quality = parse_checkbox(run_quality)
    if run_fuzzing is not None or mode in {"fuzz_single", "fuzz_project"}:
        options.run_fuzzing = parse_checkbox(run_fuzzing) or mode in {"fuzz_single", "fuzz_project"}
    options.fuzz_duration_seconds = max(10, min(fuzz_duration_seconds, 3600))
    options.max_report_findings = max(20, min(max_report_findings, 1000))
    return options


def _job_redirect_url(created_jobs: list[JobRecord]) -> str:
    if len(created_jobs) == 1:
        return f"/jobs/{created_jobs[0].id}"
    return "/"


def create_job_record(
    *,
    name: str,
    mode: str,
    original_name: str,
    upload_path: Path,
    options: JobOptions,
    metadata: dict | None = None,
) -> JobRecord:
    job_id = uuid.uuid4().hex[:12]
    job_dir = store.job_dir(job_id)
    workspace_path = job_dir / "workspace"
    output_dir = job_dir / "reports"
    workspace_path.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_type = "archive" if is_archive(upload_path) else "single_file"
    job = JobRecord(
        id=job_id,
        name=name.strip() or "Untitled job",
        mode=mode,  # type: ignore[arg-type]
        input_type=input_type,  # type: ignore[arg-type]
        original_filename=original_name,
        upload_path=str(upload_path),
        workspace_path=str(workspace_path),
        output_dir=str(output_dir),
        queue_position=store.next_queue_position(),
        options=options,
        steps=default_steps(mode, options),
    )
    job.metadata.update(
        {
            "project_key": normalize_project_key(original_name),
            "retest_scope": options.retest_scope,
            "repeat_submission": False,
        }
    )
    if metadata:
        job.metadata.update(metadata)
    return job


# Общий helper для HTML-формы и API-загрузки, чтобы не дублировать job-creation логику.
async def create_jobs_from_uploads(
    *,
    request: Request,
    name: str,
    mode: str,
    preset: str,
    retest_scope: str | None,
    run_functionality: str | None,
    run_security: str | None,
    run_style: str | None,
    run_quality: str | None,
    run_fuzzing: str | None,
    fuzz_duration_seconds: int,
    max_report_findings: int,
    integration_provider: str,
    repository_url: str,
    branch: str,
    commit_sha: str,
    pipeline_url: str,
    merge_request: str,
    service_target_url: str,
    service_runtime_profile: str,
    service_request_timeout_seconds: int,
    auth_token: str,
    auth_header_name: str,
    auth_token_prefix: str,
    basic_auth_username: str,
    basic_auth_password: str,
    auth_cookie_name: str,
    auth_cookie: str,
    service_request_headers: str,
    upload: list[UploadFile],
) -> list[JobRecord]:
    if mode not in {"full_scan", "fuzz_single", "fuzz_project"}:
        raise HTTPException(status_code=400, detail="Unsupported job mode.")

    ui_language = resolve_language(request)
    options = build_job_options(
        preset=preset,
        mode=mode,
        retest_scope=retest_scope,
        run_functionality=run_functionality,
        run_security=run_security,
        run_style=run_style,
        run_quality=run_quality,
        run_fuzzing=run_fuzzing,
        fuzz_duration_seconds=fuzz_duration_seconds,
        max_report_findings=max_report_findings,
    )
    if not options.enabled_checks(mode):
        raise HTTPException(status_code=400, detail="Select at least one analysis type.")

    uploads = [item for item in upload if item.filename]
    if not uploads:
        raise HTTPException(status_code=400, detail="Upload at least one project archive or source file.")
    if len(uploads) > MAX_UPLOAD_FILES:
        raise HTTPException(status_code=413, detail=f"Too many uploads. Maximum is {MAX_UPLOAD_FILES} files.")

    created_jobs: list[JobRecord] = []
    existing_jobs = store.list()
    ci_context = {
        "integration_provider": integration_provider.strip(),
        "repository_url": repository_url.strip(),
        "branch": branch.strip(),
        "commit_sha": commit_sha.strip(),
        "pipeline_url": pipeline_url.strip(),
        "merge_request": merge_request.strip(),
    }
    if not any(ci_context.values()):
        ci_context = {}
    service_runtime_request = build_service_runtime_request(
        service_target_url=service_target_url,
        service_runtime_profile=service_runtime_profile,
        service_request_timeout_seconds=service_request_timeout_seconds,
        auth_token=auth_token,
        auth_header_name=auth_header_name,
        auth_token_prefix=auth_token_prefix,
        basic_auth_username=basic_auth_username,
        basic_auth_password=basic_auth_password,
        auth_cookie_name=auth_cookie_name,
        auth_cookie=auth_cookie,
        service_request_headers=service_request_headers,
    )
    service_runtime_request_public = build_service_runtime_public_summary(service_runtime_request)
    for index, item in enumerate(uploads, start=1):
        original_name = Path(item.filename or "upload.bin").name
        upload_path = UPLOAD_DIR / f"{uuid.uuid4().hex[:12]}_{original_name}"
        upload_path.parent.mkdir(parents=True, exist_ok=True)

        written_bytes = 0
        try:
            with upload_path.open("wb") as handle:
                while True:
                    chunk = await item.read(1024 * 1024)
                    if not chunk:
                        break
                    written_bytes += len(chunk)
                    if written_bytes > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Upload is too large. Maximum is {MAX_UPLOAD_BYTES} bytes per file.",
                        )
                    handle.write(chunk)
        except Exception:
            upload_path.unlink(missing_ok=True)
            raise

        job_name = name
        if len(uploads) > 1:
            job_name = f"{name.strip() or 'Batch job'} #{index}: {original_name}"
        project_key = normalize_project_key(original_name)
        baseline = latest_baseline_for(project_key, exclude_job_ids={job.id for job in created_jobs})
        job_retest_scope = options.retest_scope if baseline else "full_project"
        job_options = JobOptions(**asdict(options))
        job_options.retest_scope = job_retest_scope  # type: ignore[assignment]
        job = create_job_record(
            name=job_name,
            mode=mode,
            original_name=original_name,
            upload_path=upload_path,
            options=job_options,
            metadata={
                "project_key": project_key,
                "retest_scope": job_retest_scope,
                "repeat_submission": baseline is not None,
                "baseline_job_id": baseline.id if baseline else None,
                "baseline_job_name": baseline.name if baseline else None,
                "baseline_created_at": baseline.created_at if baseline else None,
                "ui_language": ui_language,
                "ci_context": ci_context,
                "service_runtime_request": service_runtime_request,
                "service_runtime_request_public": service_runtime_request_public,
                "repeat_detected_from_history": any(
                    (job.metadata.get("project_key") or normalize_project_key(job.original_filename)) == project_key
                    for job in existing_jobs
                ),
            },
        )
        store.save(job)
        created_jobs.append(job)

    for job in created_jobs:
        start_background_job(job.id)
        append_audit_event(
            "analysis.start",
            actor=audit_actor_from_request(request),
            resource_type="job",
            resource_id=job.id,
            details={
                **request_audit_details(request),
                "mode": job.mode,
                "preset": job.options.preset,
                "project_key": job.metadata.get("project_key", ""),
                "retest_scope": job.metadata.get("retest_scope", ""),
            },
        )
    return created_jobs


def clone_job(
    job: JobRecord,
    *,
    retest_scope: str = "full_project",
    baseline_job: JobRecord | None = None,
    ui_language: str | None = None,
) -> JobRecord:
    clone_options = JobOptions(**asdict(job.options))
    clone_options.retest_scope = retest_scope  # type: ignore[assignment]
    baseline = baseline_job or job
    cloned_runtime_request = dict(job.metadata.get("service_runtime_request", {}))
    cloned_runtime_public = build_service_runtime_public_summary(
        cloned_runtime_request or dict(job.metadata.get("service_runtime_request_public", {}))
    )
    cloned = create_job_record(
        name=f"{job.name} (rerun)",
        mode=job.mode,
        original_name=job.original_filename,
        upload_path=Path(job.upload_path),
        options=clone_options,
        metadata={
            "project_key": job.metadata.get("project_key", normalize_project_key(job.original_filename)),
            "retest_scope": retest_scope,
            "repeat_submission": True,
            "baseline_job_id": baseline.id,
            "baseline_job_name": baseline.name,
            "baseline_created_at": baseline.created_at,
            "ui_language": normalize_language(ui_language or str(job.metadata.get("ui_language", DEFAULT_LANGUAGE))),
            "ci_context": dict(job.metadata.get("ci_context", {})),
            "service_runtime_request": cloned_runtime_request,
            "service_runtime_request_public": cloned_runtime_public,
        },
    )
    cloned.metadata["rerun_of"] = job.id
    return cloned


# Блок HTTP-маршрутов: от дашборда и загрузки до управления артефактами.
@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/runtime")
async def runtime_info() -> dict[str, object]:
    return {
        "name": "ScanForge",
        "version": str(app.version),
        "runtime_signature": CURRENT_RUNTIME_SIGNATURE,
    }


@app.get("/api/runtime/logs")
async def runtime_logs_api() -> dict[str, object]:
    return runtime_log_status()


@app.get("/api/auth")
async def auth_api(request: Request) -> dict[str, object]:
    request_auth = getattr(request.state, "auth", AuthContext(enabled=False, username="local", role="admin"))
    return {
        **auth_status(),
        "current_user": request_auth.username,
        "current_role": request_auth.role,
    }


@app.get("/api/audit")
async def audit_api(request: Request, limit: int = 100) -> dict[str, object]:
    request_auth = getattr(request.state, "auth", AuthContext(enabled=False, username="local", role="admin"))
    if request_auth.enabled and not request_auth.is_admin:
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return audit_status(limit=max(1, min(limit, 500)))


@app.get("/")
async def index(
    request: Request,
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
):
    language = resolve_language(request)
    recover_stale_jobs()
    all_jobs = store.list()
    jobs = filter_jobs(all_jobs, query=query, status=status, mode=mode, preset=preset)
    known_repeat_projects = repeat_submission_catalog(all_jobs)
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context(request, {
            "jobs": jobs,
            "queue_jobs": queue_ordered_jobs(jobs),
            "all_jobs_count": len(all_jobs),
            "modes": build_modes(language),
            "overview": dashboard_overview(jobs),
            "presets": list_presets(language),
            "known_repeat_projects": known_repeat_projects,
            "filters": {
                "query": query,
                "status": status,
                "mode": mode,
                "preset": preset,
            },
        }),
    )


@app.get("/settings")
async def settings_page(request: Request):
    recover_stale_jobs()
    hardware = detect_host_hardware()
    language = resolve_language(request)
    return templates.TemplateResponse(
        request,
        "settings.html",
        template_context(request, {
            "tool_inventory": describe_toolchain(),
            "tool_install_preflight": tool_install_preflight(),
            "tool_install_jobs": list_tool_install_jobs(),
            "ai_backend": ai_backend_status(),
            "release_gate_policy": release_gate_policy_status(),
            "dependency_suppressions": dependency_suppression_status(),
            "knowledge_base": knowledge_base_status(),
            "hardware": hardware.to_dict(),
            "environment": build_environment_status(),
            "integrations": integration_status(current_base_url(request)),
            "auth_status": auth_status(),
            "network": network_access_status(),
            "runtime_logs": runtime_log_status(),
            "upload_limits": {
                "max_files": MAX_UPLOAD_FILES,
                "max_bytes": MAX_UPLOAD_BYTES,
            },
            "recommended_workers": recommended_worker_processes(hardware),
            "worker_mode": worker_mode(),
            "modes": build_modes(language),
            "presets": list_presets(language),
        }),
    )


@app.post("/jobs")
async def create_job(
    request: Request,
    name: str = Form(""),
    mode: str = Form(...),
    preset: str = Form("balanced"),
    retest_scope: str | None = Form(None),
    run_functionality: str | None = Form(None),
    run_security: str | None = Form(None),
    run_style: str | None = Form(None),
    run_quality: str | None = Form(None),
    run_fuzzing: str | None = Form(None),
    fuzz_duration_seconds: int = Form(60),
    max_report_findings: int = Form(200),
    integration_provider: str = Form(""),
    repository_url: str = Form(""),
    branch: str = Form(""),
    commit_sha: str = Form(""),
    pipeline_url: str = Form(""),
    merge_request: str = Form(""),
    service_target_url: str = Form(""),
    service_runtime_profile: str = Form("passive"),
    service_request_timeout_seconds: int = Form(3),
    auth_token: str = Form(""),
    auth_header_name: str = Form("Authorization"),
    auth_token_prefix: str = Form("Bearer"),
    basic_auth_username: str = Form(""),
    basic_auth_password: str = Form(""),
    auth_cookie_name: str = Form(""),
    auth_cookie: str = Form(""),
    service_request_headers: str = Form(""),
    upload: list[UploadFile] = File(...),
):
    created_jobs = await create_jobs_from_uploads(
        request=request,
        name=name,
        mode=mode,
        preset=preset,
        retest_scope=retest_scope,
        run_functionality=run_functionality,
        run_security=run_security,
        run_style=run_style,
        run_quality=run_quality,
        run_fuzzing=run_fuzzing,
        fuzz_duration_seconds=fuzz_duration_seconds,
        max_report_findings=max_report_findings,
        integration_provider=integration_provider,
        repository_url=repository_url,
        branch=branch,
        commit_sha=commit_sha,
        pipeline_url=pipeline_url,
        merge_request=merge_request,
        service_target_url=service_target_url,
        service_runtime_profile=service_runtime_profile,
        service_request_timeout_seconds=service_request_timeout_seconds,
        auth_token=auth_token,
        auth_header_name=auth_header_name,
        auth_token_prefix=auth_token_prefix,
        basic_auth_username=basic_auth_username,
        basic_auth_password=basic_auth_password,
        auth_cookie_name=auth_cookie_name,
        auth_cookie=auth_cookie,
        service_request_headers=service_request_headers,
        upload=upload,
    )
    return RedirectResponse(url=_job_redirect_url(created_jobs), status_code=303)


@app.post("/api/jobs/upload")
async def create_job_api(
    request: Request,
    name: str = Form(""),
    mode: str = Form(...),
    preset: str = Form("balanced"),
    retest_scope: str | None = Form(None),
    run_functionality: str | None = Form(None),
    run_security: str | None = Form(None),
    run_style: str | None = Form(None),
    run_quality: str | None = Form(None),
    run_fuzzing: str | None = Form(None),
    fuzz_duration_seconds: int = Form(60),
    max_report_findings: int = Form(200),
    integration_provider: str = Form(""),
    repository_url: str = Form(""),
    branch: str = Form(""),
    commit_sha: str = Form(""),
    pipeline_url: str = Form(""),
    merge_request: str = Form(""),
    service_target_url: str = Form(""),
    service_runtime_profile: str = Form("passive"),
    service_request_timeout_seconds: int = Form(3),
    auth_token: str = Form(""),
    auth_header_name: str = Form("Authorization"),
    auth_token_prefix: str = Form("Bearer"),
    basic_auth_username: str = Form(""),
    basic_auth_password: str = Form(""),
    auth_cookie_name: str = Form(""),
    auth_cookie: str = Form(""),
    service_request_headers: str = Form(""),
    upload: list[UploadFile] = File(...),
):
    created_jobs = await create_jobs_from_uploads(
        request=request,
        name=name,
        mode=mode,
        preset=preset,
        retest_scope=retest_scope,
        run_functionality=run_functionality,
        run_security=run_security,
        run_style=run_style,
        run_quality=run_quality,
        run_fuzzing=run_fuzzing,
        fuzz_duration_seconds=fuzz_duration_seconds,
        max_report_findings=max_report_findings,
        integration_provider=integration_provider,
        repository_url=repository_url,
        branch=branch,
        commit_sha=commit_sha,
        pipeline_url=pipeline_url,
        merge_request=merge_request,
        service_target_url=service_target_url,
        service_runtime_profile=service_runtime_profile,
        service_request_timeout_seconds=service_request_timeout_seconds,
        auth_token=auth_token,
        auth_header_name=auth_header_name,
        auth_token_prefix=auth_token_prefix,
        basic_auth_username=basic_auth_username,
        basic_auth_password=basic_auth_password,
        auth_cookie_name=auth_cookie_name,
        auth_cookie=auth_cookie,
        service_request_headers=service_request_headers,
        upload=upload,
    )
    return {
        "jobs": [serialize_job(job) for job in created_jobs],
        "redirect_url": _job_redirect_url(created_jobs),
    }


@app.get("/jobs/{job_id}/rerun")
async def rerun_job_options(request: Request, job_id: str):
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    related_jobs = related_jobs_for_project(
        job.metadata.get("project_key", normalize_project_key(job.original_filename)),
        exclude_job_ids={job.id},
    )
    return templates.TemplateResponse(
        request,
        "retest.html",
        template_context(request, {
            "job": job,
            "baseline_job": job,
            "related_jobs": related_jobs[:5],
        }),
    )


@app.post("/jobs/{job_id}/rerun")
async def rerun_job(request: Request, job_id: str, retest_scope: str = Form("full_project")):
    try:
        original = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    upload_path = Path(original.upload_path)
    if not upload_path.exists():
        raise HTTPException(status_code=400, detail="Original upload is no longer available.")

    normalized_scope = retest_scope if retest_scope in {"full_project", "changes_only"} else "full_project"
    cloned = clone_job(
        original,
        retest_scope=normalized_scope,
        baseline_job=original,
        ui_language=resolve_language(request),
    )
    store.save(cloned)
    start_background_job(cloned.id)
    append_audit_event(
        "analysis.rerun",
        actor=audit_actor_from_request(request),
        resource_type="job",
        resource_id=cloned.id,
        details={
            **request_audit_details(request),
            "source_job_id": original.id,
            "retest_scope": normalized_scope,
            "project_key": cloned.metadata.get("project_key", ""),
        },
    )
    return RedirectResponse(url=f"/jobs/{cloned.id}", status_code=303)


@app.get("/jobs/{job_id}")
async def job_detail(request: Request, job_id: str):
    recover_stale_jobs()
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    report_preview_url = f"/jobs/{job.id}/artifacts/{job.html_report}" if job.html_report else None
    return templates.TemplateResponse(
        request,
        "job.html",
        template_context(request, {
            "job": job,
            "runtime_request_public": build_service_runtime_public_summary(
                dict(job.metadata.get("service_runtime_request", {})) or dict(job.metadata.get("service_runtime_request_public", {}))
            ),
            "findings": sort_findings(job),
            "report_preview_url": report_preview_url,
            "selected_checks": job.options.enabled_checks(job.mode),
            "ai_backend": ai_backend_status(),
            "worker_mode": worker_mode(),
            "tool_inventory": describe_toolchain(),
            "finding_review_states": build_review_state_choices(resolve_language(request)),
            "queue_jobs": queue_ordered_jobs(store.list()),
            "related_jobs": related_jobs_for_project(
                job.metadata.get("project_key", normalize_project_key(job.original_filename)),
                exclude_job_ids={job.id},
            )[:5],
        }),
    )


@app.get("/api/jobs/{job_id}")
async def job_api(job_id: str):
    recover_stale_jobs()
    try:
        return serialize_job(store.load(job_id), include_findings=True)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc


@app.get("/api/jobs")
async def jobs_api(
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
):
    recover_stale_jobs()
    jobs = filter_jobs(store.list(), query=query, status=status, mode=mode, preset=preset)
    return [serialize_job(job) for job in jobs]


@app.get("/api/dashboard")
async def dashboard_api(
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
):
    recover_stale_jobs()
    all_jobs = store.list()
    jobs = filter_jobs(all_jobs, query=query, status=status, mode=mode, preset=preset)
    return {
        "jobs": [serialize_job(job) for job in queue_ordered_jobs(jobs)],
        "overview": dashboard_overview(jobs),
        "all_jobs_count": len(all_jobs),
        "tool_inventory": describe_toolchain(),
        "ai_backend": ai_backend_status(),
        "knowledge_base": knowledge_base_status(),
        "worker_mode": worker_mode(),
    }


@app.get("/api/tools")
async def tools_api():
    return {
        "paths": detect_toolchain(),
        "inventory": describe_toolchain(),
        "install_preflight": tool_install_preflight(),
        "install_jobs": list_tool_install_jobs(),
    }


@app.get("/api/tools/preflight")
async def tools_preflight_api():
    return tool_install_preflight()


@app.get("/api/tools/install-jobs")
async def tool_install_jobs_api():
    return {"jobs": list_tool_install_jobs()}


@app.get("/api/tools/install-jobs/{install_job_id}")
async def tool_install_job_api(install_job_id: str):
    try:
        return tool_install_job_status(install_job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Install job not found.") from exc


@app.post("/api/tools/install/{tool_key}/dry-run")
async def install_tool_dry_run_api(tool_key: str, request: Request):
    result = dry_run_host_tool(tool_key)
    append_audit_event(
        "tool.install.dry_run",
        outcome="success" if result.get("ok") is not False else "failed",
        actor=audit_actor_from_request(request),
        resource_type="tool",
        resource_id=tool_key,
        details={
            **request_audit_details(request),
            "status": result.get("status", ""),
            "packages": result.get("packages", []),
        },
    )
    return result


@app.post("/api/tools/install/{tool_key}")
async def install_tool_api(tool_key: str, request: Request):
    payload: dict[str, Any] = {}
    if request.headers.get("content-type", "").lower().startswith("application/json"):
        try:
            parsed = await request.json()
        except ValueError:
            parsed = {}
        if isinstance(parsed, dict):
            payload = parsed
    confirmed = bool(payload.get("confirmed")) or request.query_params.get("confirmed") in {"1", "true", "yes", "on"}
    confirmed_packages = payload.get("packages")
    if confirmed_packages is not None and not isinstance(confirmed_packages, list):
        raise HTTPException(status_code=400, detail="packages must be a list.")
    if not confirmed or confirmed_packages is None:
        dry_run = dry_run_host_tool(tool_key)
        return JSONResponse(
            status_code=409,
            content={
                **dry_run,
                "ok": False,
                "status": "confirmation-required",
                "message": "Confirm the package dry-run before installing.",
                "tool_inventory": describe_toolchain(),
            },
        )
    result = start_tool_install_job(
        tool_key,
        confirmed_packages=[str(item) for item in confirmed_packages] if confirmed_packages is not None else None,
    )
    append_audit_event(
        "tool.install.queue",
        outcome="success" if result.get("ok", True) is not False else "failed",
        actor=audit_actor_from_request(request),
        resource_type="tool",
        resource_id=tool_key,
        details={
            **request_audit_details(request),
            "status": result.get("status", "queued"),
            "packages": confirmed_packages or [],
            "install_job_id": result.get("id", ""),
        },
    )
    response_payload = {
        "ok": result.get("ok", True) is not False,
        "status": result.get("status", "queued"),
        "message": result.get("message", "Tool installation queued."),
        "install_job": result,
        **result,
        "tool_inventory": describe_toolchain(),
        "install_jobs": list_tool_install_jobs(),
    }
    if result.get("ok") is False:
        conflict_statuses = {"confirmation-required", "package-confirmation-mismatch", "requires-admin"}
        return JSONResponse(
            status_code=409 if result.get("status") in conflict_statuses else 400,
            content=response_payload,
        )
    return response_payload


@app.post("/tools/install/{tool_key}")
async def install_tool_web(
    request: Request,
    tool_key: str,
    next_url: str = Form("/"),
    confirmed: str | None = Form("1"),
    packages: list[str] | None = Form(None),
):
    if parse_checkbox(confirmed) and packages:
        result = start_tool_install_job(tool_key, confirmed_packages=[str(item) for item in packages])
        append_audit_event(
            "tool.install.queue",
            outcome="success" if result.get("ok", True) is not False else "failed",
            actor=audit_actor_from_request(request),
            resource_type="tool",
            resource_id=tool_key,
            details={
                **request_audit_details(request),
                "status": result.get("status", "queued"),
                "packages": packages,
                "install_job_id": result.get("id", ""),
            },
        )
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.get("/api/knowledge-base")
async def knowledge_base_api():
    return knowledge_base_status()


@app.post("/knowledge-base/sync")
async def knowledge_base_sync_now(next_url: str = Form("/")):
    start_background_knowledge_base_sync(force=True)
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/knowledge-base/sync")
async def knowledge_base_sync_now_api():
    started = start_background_knowledge_base_sync(force=True)
    return {
        "started": started,
        "knowledge_base": knowledge_base_status(),
    }


@app.post("/assistant/models/{model_id}/download")
async def assistant_model_download(model_id: str, next_url: str = Form("/")):
    start_local_model_download(model_id)
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/assistant/models/{model_id}/download")
async def assistant_model_download_api(model_id: str):
    return start_local_model_download(model_id)


# Настройки AI-бэкенда редактируются из веб-интерфейса и применяются без ручной правки файлов.
@app.post("/assistant/config")
async def assistant_config_web(
    request: Request,
    next_url: str = Form("/settings"),
    enabled: str | None = Form(None),
    provider: str = Form("openai-compatible"),
    url: str = Form(""),
    model: str = Form(""),
    api_key: str = Form(""),
    timeout_seconds: int = Form(30),
    routing_mode: str = Form("auto"),
    preferred_local_model: str = Form("auto"),
):
    payload: dict[str, Any] = {
        "enabled": parse_checkbox(enabled),
        "provider": provider,
        "url": url,
        "model": model,
        "timeout_seconds": timeout_seconds,
        "routing_mode": routing_mode,
        "preferred_local_model": preferred_local_model,
    }
    if api_key.strip():
        payload["api_key"] = api_key
    save_ai_settings(payload)
    append_audit_event(
        "settings.update",
        actor=audit_actor_from_request(request),
        resource_type="settings",
        resource_id="ai_backend",
        details={**request_audit_details(request), "payload": payload},
    )
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/assistant/config")
async def assistant_config_api(request: Request, payload: dict = Body(...)):
    save_ai_settings(payload)
    append_audit_event(
        "settings.update",
        actor=audit_actor_from_request(request),
        resource_type="settings",
        resource_id="ai_backend",
        details={**request_audit_details(request), "payload": payload},
    )
    return ai_backend_status()


@app.post("/api/assistant/probe")
async def assistant_probe_api():
    return probe_ai_backend()


@app.post("/release-gate/config")
async def release_gate_config_web(
    request: Request,
    next_url: str = Form("/settings"),
    block_on_critical_findings: str | None = Form(None),
    block_on_new_high_findings: str | None = Form(None),
    block_on_new_critical_findings: str | None = Form(None),
    block_on_new_vulnerable_dependencies: str | None = Form(None),
    block_on_new_reachable_vulnerable_dependencies: str | None = Form(None),
    block_on_dependency_baseline_regression: str | None = Form(None),
    review_on_persisting_high_findings: str | None = Form(None),
    review_on_risk_score_regression: str | None = Form(None),
    review_on_net_new_findings: str | None = Form(None),
    review_on_high_severity_regression: str | None = Form(None),
    review_on_risk_score_above: int = Form(55),
):
    payload = {
        "block_on_critical_findings": parse_checkbox(block_on_critical_findings),
        "block_on_new_high_findings": parse_checkbox(block_on_new_high_findings),
        "block_on_new_critical_findings": parse_checkbox(block_on_new_critical_findings),
        "block_on_new_vulnerable_dependencies": parse_checkbox(block_on_new_vulnerable_dependencies),
        "block_on_new_reachable_vulnerable_dependencies": parse_checkbox(block_on_new_reachable_vulnerable_dependencies),
        "block_on_dependency_baseline_regression": parse_checkbox(block_on_dependency_baseline_regression),
        "review_on_persisting_high_findings": parse_checkbox(review_on_persisting_high_findings),
        "review_on_risk_score_regression": parse_checkbox(review_on_risk_score_regression),
        "review_on_net_new_findings": parse_checkbox(review_on_net_new_findings),
        "review_on_high_severity_regression": parse_checkbox(review_on_high_severity_regression),
        "review_on_risk_score_above": review_on_risk_score_above,
    }
    save_release_gate_policy(payload)
    append_audit_event(
        "settings.update",
        actor=audit_actor_from_request(request),
        resource_type="settings",
        resource_id="release_gate",
        details={**request_audit_details(request), "payload": payload},
    )
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/release-gate/config")
async def release_gate_config_api(request: Request, payload: dict = Body(...)):
    save_release_gate_policy(payload)
    append_audit_event(
        "settings.update",
        actor=audit_actor_from_request(request),
        resource_type="settings",
        resource_id="release_gate",
        details={**request_audit_details(request), "payload": payload},
    )
    return release_gate_policy_status()


@app.post("/dependency-suppressions/config")
async def dependency_suppressions_config_web(
    request: Request,
    next_url: str = Form("/settings"),
    rules_json: str = Form("[]"),
):
    try:
        payload = json.loads(rules_json)
        save_dependency_suppressions(payload)
        append_audit_event(
            "settings.update",
            actor=audit_actor_from_request(request),
            resource_type="settings",
            resource_id="dependency_suppressions",
            details={**request_audit_details(request), "rule_count": len(payload) if isinstance(payload, list) else 0},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid dependency suppression JSON.") from exc
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/dependency-suppressions/config")
async def dependency_suppressions_config_api(request: Request, payload: dict | list = Body(...)):
    try:
        result = save_dependency_suppressions(payload)
        append_audit_event(
            "settings.update",
            actor=audit_actor_from_request(request),
            resource_type="settings",
            resource_id="dependency_suppressions",
            details={**request_audit_details(request), "rule_count": result.get("rule_count", 0)},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid dependency suppression payload.") from exc


@app.get("/api/system")
async def system_api(request: Request):
    recover_stale_jobs()
    hardware = detect_host_hardware()
    jobs = store.list()
    request_auth = getattr(request.state, "auth", AuthContext(enabled=False, username="local", role="admin"))
    return {
        "tools": detect_toolchain(),
        "tool_inventory": describe_toolchain(),
        "tool_install_preflight": tool_install_preflight(),
        "tool_install_jobs": list_tool_install_jobs(),
        "ai_backend": ai_backend_status(),
        "release_gate_policy": release_gate_policy_status(),
        "dependency_suppressions": dependency_suppression_status(),
        "knowledge_base": knowledge_base_status(),
        "hardware": hardware.to_dict(),
        "environment": build_environment_status(),
        "integrations": integration_status(current_base_url(request)),
        "auth_status": auth_status(),
        "current_auth": {
            "enabled": request_auth.enabled,
            "username": request_auth.username,
            "role": request_auth.role,
            "is_admin": request_auth.is_admin,
        },
        "network": network_access_status(),
        "runtime_logs": runtime_log_status(),
        "upload_limits": {
            "max_files": MAX_UPLOAD_FILES,
            "max_bytes": MAX_UPLOAD_BYTES,
        },
        "recommended_worker_processes": recommended_worker_processes(hardware),
        "worker_mode": worker_mode(),
        "queued_jobs": sum(1 for job in jobs if job.status == "queued"),
        "paused_jobs": sum(1 for job in jobs if job.status == "paused"),
    }


@app.get("/api/environment")
async def environment_api():
    return build_environment_status()


@app.get("/api/integrations")
async def integrations_api(request: Request):
    return integration_status(current_base_url(request))


@app.post("/api/integrations/config")
async def integrations_config_api(request: Request, payload: dict = Body(...)):
    save_integration_settings(payload)
    append_audit_event(
        "settings.update",
        actor=audit_actor_from_request(request),
        resource_type="settings",
        resource_id="integrations",
        details={**request_audit_details(request), "payload": payload},
    )
    return integration_status(current_base_url(request))


@app.post("/api/integrations/webhooks/{provider}")
async def integrations_webhook_api(provider: str, request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {"raw_body": (await request.body()).decode("utf-8", errors="ignore")}
    if provider not in {"gitlab", "github", "jenkins", "teamcity", "azure_devops"}:
        raise HTTPException(status_code=404, detail="Unsupported integration provider.")
    try:
        event = record_integration_event(
            provider,
            headers={key: value for key, value in request.headers.items()},
            payload=payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return event


@app.post("/api/projects/{project_key}/findings/{fingerprint}/review")
async def finding_review_state_api(
    request: Request,
    project_key: str,
    fingerprint: str,
    review_state: str = Body(...),
    review_note: str = Body(""),
    muted_until: str | None = Body(None),
):
    try:
        saved = set_review_state(
            project_key,
            fingerprint,
            review_state=review_state,
            review_note=review_note,
            muted_until=muted_until,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    append_audit_event(
        "finding.review",
        actor=audit_actor_from_request(request),
        resource_type="finding",
        resource_id=fingerprint,
        details={
            **request_audit_details(request),
            "project_key": project_key,
            "review_state": review_state,
            "muted_until": muted_until or "",
        },
    )
    return {
        "ok": True,
        "project_key": project_key,
        "fingerprint": fingerprint,
        **saved,
    }


@app.post("/jobs/{job_id}/cancel")
async def cancel_job(request: Request, job_id: str, force: bool = False):
    try:
        job = store.request_cancel(job_id, force=force)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    append_audit_event(
        "job.cancel",
        actor=audit_actor_from_request(request),
        resource_type="job",
        resource_id=job_id,
        details={**request_audit_details(request), "force": force, "status": job.status},
    )
    if job.status == "cancelled":
        return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job_api(request: Request, job_id: str, force: bool = False):
    try:
        job = store.request_cancel(job_id, force=force)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    append_audit_event(
        "job.cancel",
        actor=audit_actor_from_request(request),
        resource_type="job",
        resource_id=job_id,
        details={**request_audit_details(request), "force": force, "status": job.status},
    )
    return serialize_job(job)


@app.post("/jobs/{job_id}/delete")
async def delete_job(job_id: str, next_url: str = Form("/")):
    recover_stale_jobs()
    try:
        store.delete(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/jobs/{job_id}/delete")
async def delete_job_api(job_id: str):
    recover_stale_jobs()
    try:
        store.delete(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"deleted": True, "job_id": job_id}


@app.post("/jobs/{job_id}/pause")
async def pause_job(job_id: str):
    try:
        store.request_pause(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.post("/api/jobs/{job_id}/pause")
async def pause_job_api(job_id: str):
    try:
        store.request_pause(job_id)
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    return serialize_job(job)


@app.post("/jobs/{job_id}/resume")
async def resume_job(job_id: str):
    try:
        job = store.resume_job(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    if job.status == "queued":
        start_background_job(job.id)
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.post("/api/jobs/{job_id}/resume")
async def resume_job_api(job_id: str):
    try:
        job = store.resume_job(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    if job.status == "queued":
        start_background_job(job.id)
    return serialize_job(job)


@app.post("/jobs/{job_id}/queue/up")
async def move_job_up(job_id: str):
    try:
        store.move_in_queue(job_id, -1)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/jobs/{job_id}/queue/up")
async def move_job_up_api(job_id: str):
    try:
        job = store.move_in_queue(job_id, -1)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return serialize_job(job)


@app.post("/jobs/{job_id}/queue/down")
async def move_job_down(job_id: str):
    try:
        store.move_in_queue(job_id, 1)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/jobs/{job_id}/queue/down")
async def move_job_down_api(job_id: str):
    try:
        job = store.move_in_queue(job_id, 1)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return serialize_job(job)


@app.post("/api/jobs/{job_id}/queue/reposition")
async def reposition_job_in_queue(
    job_id: str,
    target_job_id: str = Body(...),
    placement: str = Body("before"),
):
    if placement not in {"before", "after"}:
        raise HTTPException(status_code=400, detail="Placement must be 'before' or 'after'.")
    try:
        job = store.reposition_in_queue(job_id, target_job_id, place_after=placement == "after")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return serialize_job(job)


@app.get("/jobs/{job_id}/report")
async def view_job_report(job_id: str):
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    if not job.html_report:
        return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)
    return RedirectResponse(url=f"/jobs/{job_id}/artifacts/{job.html_report}", status_code=303)


@app.get("/jobs/{job_id}/artifacts/{filename}")
async def download_artifact(job_id: str, filename: str):
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    if Path(filename).name != filename or filename not in allowed_artifact_names(job):
        raise HTTPException(status_code=404, detail="Artifact not found.")

    output_dir = Path(job.output_dir).resolve()
    artifact_path = (output_dir / filename).resolve()
    try:
        artifact_path.relative_to(output_dir)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Artifact not found.") from exc
    if not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return FileResponse(str(artifact_path), filename=artifact_path.name)
