# ScanForge

This repository now contains an MVP web platform for uploading C/C++ and Qt-oriented projects on Linux, running broad analysis, tracking progress, and downloading HTML or PDF reports.

## What the MVP does

- Accepts an uploaded archive or single file through a web interface.
- Creates a background job with step-by-step progress.
- Supports launch presets such as balanced, deep audit, security focus, and fuzz sprint.
- Lets you filter saved jobs by query, status, mode, and preset.
- Supports rerunning an earlier job from the browser.
- Supports cancelling queued or running jobs.
- Adds an AI review layer: remote AI if configured, deterministic local fallback if not.
- Maintains a local mirror of official vulnerability intelligence feeds, including FSTEC BDU.
- Runs analysis outside the web process through worker processes, and can use a dedicated Docker worker service.
- Runs built-in checks for:
  - security smells
  - style issues
  - maintainability risks
  - redundancy such as commented-out code blocks and duplicate includes/imports
  - build and test readiness
  - fuzzing readiness
- Generates:
  - `report.html`
  - `report.pdf`
  - `report.json`
  - `ai_review.md`
  - `knowledge_base_matches.json`
  - optional fuzzing helper artifacts
- Keeps the job detail page live by polling the API instead of full page reloads.
- Extracts uploaded archives with traversal and size checks before analysis begins.
- Detects host CPU, RAM, and NVIDIA GPUs, then builds an adaptive execution plan aimed at using about 90% of the machine by default.
- Auto-sizes the worker pool for the detected host and distributes GPU visibility across concurrent jobs when GPUs are present.

## Main files

- `qa_portal/app.py` - FastAPI application and routes.
- `qa_portal/pipeline.py` - job execution pipeline.
- `qa_portal/analysis.py` - built-in analyzers and project discovery.
- `qa_portal/knowledge_base.py` - local feed sync, parsing, lookup, and report enrichment.
- `qa_portal/reporting.py` - HTML and PDF report generation.
- `run-server.sh` - local server launcher.
- `run-sync-kb.sh` - sync the local knowledge-base mirror from official sources.
- `run-tests.sh` - unit and shell test runner.

## Install Python dependencies

Create a local virtual environment and install the Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run the portal

```bash
./run-server.sh
```

Run a dedicated worker loop:

```bash
./run-worker.sh
```

Sync the local vulnerability knowledge base:

```bash
./run-sync-kb.sh --force
```

Open:

```text
http://127.0.0.1:8000
```

## Desktop launch without terminal

ScanForge can also be launched from a desktop shortcut without opening a terminal window.

Generate the shortcut:

```bash
./scripts/install-desktop-shortcut.sh
```

This creates `~/Desktop/ScanForge.desktop`. The shortcut launches `scripts/launch-scanforge-desktop.sh`, which:

- requests administrator rights through `pkexec`
- starts the web server and worker in the background
- opens the browser automatically after the health check succeeds

The privileged launcher stores runtime state in:

- `/var/lib/scanforge` for persistent data
- `/var/log/scanforge` for logs
- `/var/run/scanforge` for PID files

To stop the background instance manually, run:

```bash
pkexec ./scripts/stop-scanforge-admin.sh
```

## Run tests

```bash
./run-tests.sh
```

## Docker launch

Build and run the full web portal in Docker:

```bash
docker compose up --build
```

The container exposes:

```text
http://127.0.0.1:8000
```

Persistent job state is stored in the local `./data` folder and mounted into the container at `/app/data`.

The compose stack now runs two services:

- `qa-portal` for the web UI and API
- `qa-worker` for queued job execution

## AI review configuration

The portal supports an optional AI review backend through environment variables. If it is not configured, the system automatically falls back to a deterministic local review so reports still remain useful.

Example:

```bash
cp .env.example .env
```

Environment variables:

- `QA_PORTAL_AUTOSTART_WORKER`
- `QA_PORTAL_WORKER_POLL_SECONDS`
- `QA_PORTAL_KEEP_WORKSPACE`
- `QA_PORTAL_KEEP_UPLOADS`
- `QA_PORTAL_MAX_ARCHIVE_FILE_COUNT`
- `QA_PORTAL_MAX_ARCHIVE_TOTAL_BYTES`
- `QA_PORTAL_RESOURCE_TARGET_UTILIZATION_PERCENT`
- `QA_PORTAL_WORKER_PROCESSES`
- `QA_PORTAL_KB_AUTOSYNC`
- `QA_PORTAL_KB_WEEKLY_SYNC`
- `QA_PORTAL_KB_WEEKLY_SYNC_DAY`
- `QA_PORTAL_KB_WEEKLY_SYNC_HOUR`
- `QA_PORTAL_KB_WEEKLY_SYNC_MINUTE`
- `QA_PORTAL_KB_SYNC_TIMEOUT_SECONDS`
- `QA_PORTAL_KB_STALE_AFTER_SECONDS`
- `QA_PORTAL_KB_NVD_YEARLY_MIRROR`
- `QA_PORTAL_KB_NVD_YEAR_START`
- `QA_PORTAL_KB_NVD_YEAR_END`
- `AI_ANALYZER_ENABLED`
- `AI_ANALYZER_URL`
- `AI_ANALYZER_MODEL`
- `AI_ANALYZER_API_KEY`
- `AI_ANALYZER_PROVIDER`
- `AI_ANALYZER_TIMEOUT_SECONDS`

The expected endpoint contract is an OpenAI-compatible chat completion endpoint returning `choices[0].message.content`.

## Toolchain notes

The portal auto-detects external tools such as `cmake`, `clang++`, `cppcheck`, `clang-tidy`, `qmake6`, and `afl-fuzz`.

## Adaptive hardware usage

The portal now includes an adaptive hardware layer:

- It detects total CPU threads and RAM and targets about `90%` of them by default.
- It detects NVIDIA GPUs through `nvidia-smi` when available.
- It computes a per-job execution plan based on the number of currently running jobs.
- It scales build, test, `clang-tidy`, `cppcheck`, and file-scan parallelism from that plan.
- It auto-sizes the worker pool with `QA_PORTAL_WORKER_PROCESSES=auto`.
- If a single job is running on a multi-GPU host, the job can see all GPUs.
- If multiple jobs are running, GPU visibility is distributed between jobs so that one job can run on GPU 0 while another runs on GPU 1.

Important practical note: the current built-in analyzers are still mostly CPU-oriented tools. The adaptive layer now reserves and exposes GPUs and prepares the runtime for GPU-capable tasks, but the actual speedup depends on whether the invoked tool or uploaded project can use CUDA/NVIDIA devices.

The current machine now has:

- `cmake`
- `clang++`
- `clang-tidy`
- `cppcheck`
- `qmake6`
- `ctest`
- `valgrind`
- `afl-fuzz`

`wkhtmltopdf` is not installed from the default repository on this Ubuntu release, but the platform already generates PDF reports through `fpdf2`, so PDF export still works.

## Local knowledge base

The portal can mirror several official sources into `./data/knowledge_base` and then use them to enrich findings and reports:

- CISA Known Exploited Vulnerabilities
- MITRE CWE
- MITRE CAPEC
- NVD CVE modified feed
- NVD yearly CVE feeds across the configured year range
- FSTEC BDU vulnerability XML export
- FSTEC BDU threat XLSX export

During live sync in this environment, the local mirror successfully pulled all six sources, including FSTEC. The FSTEC host required an SSL-certificate fallback in this environment, and that fact is recorded in the sync metadata.

The portal now also supports a built-in weekly sync scheduler:

- enable it with `QA_PORTAL_KB_WEEKLY_SYNC=1`
- choose the weekday with `QA_PORTAL_KB_WEEKLY_SYNC_DAY` where `0=Monday` and `6=Sunday`
- choose the weekly window with `QA_PORTAL_KB_WEEKLY_SYNC_HOUR` and `QA_PORTAL_KB_WEEKLY_SYNC_MINUTE`
- control the full NVD yearly mirror with `QA_PORTAL_KB_NVD_YEARLY_MIRROR=1`
- set the mirrored range with `QA_PORTAL_KB_NVD_YEAR_START` and `QA_PORTAL_KB_NVD_YEAR_END`

When the yearly NVD mirror is enabled, the sync process downloads all configured yearly NVD feeds plus the `modified` feed and then overlays the modified entries on top of the yearly baseline in the local lookup.

## Web UX highlights

- Analysis presets auto-fill the enabled checks and reporting limits.
- The dashboard exposes queue history filters for large job lists.
- The dashboard shows whether the AI layer is running in remote or fallback mode.
- The dashboard now shows local knowledge-base health and source counts.
- The dashboard now shows adaptive host hardware, target utilization, detected GPUs, and the recommended worker count.
- The API exposes `/api/system` with toolchain, worker mode, AI backend state, queued job count, and knowledge-base status.
- The API exposes `/api/knowledge-base` for feed-level local mirror status.
- Job detail pages show:
  - executive summary with risk score and verdict
  - AI review with release decision, blockers, and quick wins
  - adaptive execution plan with CPU/RAM/GPU allocation
  - knowledge-base matches for findings and project references
  - recommended next actions
  - live step updates
  - HTML preview
  - one-click rerun
  - job cancellation while queued or running

## Legacy sample

The original Bash example remains in `123.sh` together with `tests/test_123.sh`.
