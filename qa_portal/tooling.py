from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def detect_toolchain() -> dict[str, str | None]:
    tools = {
        "cmake": shutil.which("cmake"),
        "ctest": shutil.which("ctest"),
        "ninja": shutil.which("ninja"),
        "make": shutil.which("make"),
        "clang": shutil.which("clang"),
        "clangxx": shutil.which("clang++"),
        "clang_tidy": shutil.which("clang-tidy"),
        "cppcheck": shutil.which("cppcheck"),
        "afl_fuzz": shutil.which("afl-fuzz"),
        "qmake": shutil.which("qmake") or shutil.which("qmake6"),
        "nvidia_smi": shutil.which("nvidia-smi"),
        "wkhtmltopdf": shutil.which("wkhtmltopdf"),
    }
    return tools


def run_command(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> CommandResult:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged_env,
        check=False,
    )
    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
