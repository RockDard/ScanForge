from __future__ import annotations

from dataclasses import asdict

from .i18n import translate
from .models import JobMode, JobOptions


PRESET_DEFINITIONS: dict[str, dict[str, object]] = {
    "balanced": {
        "label": "Balanced",
        "description": "Default end-to-end verification for build health, security, style, and maintainability.",
        "options": JobOptions(
            preset="balanced",
            run_functionality=True,
            run_security=True,
            run_style=True,
            run_quality=True,
            run_fuzzing=False,
            fuzz_duration_seconds=60,
            max_report_findings=200,
        ),
    },
    "deep": {
        "label": "Deep audit",
        "description": "Broader audit with longer fuzzing budget and a richer report for release readiness reviews.",
        "options": JobOptions(
            preset="deep",
            run_functionality=True,
            run_security=True,
            run_style=True,
            run_quality=True,
            run_fuzzing=True,
            fuzz_duration_seconds=300,
            max_report_findings=350,
        ),
    },
    "security": {
        "label": "Security focus",
        "description": "Prioritizes secure coding findings and quality risks while trimming non-essential checks.",
        "options": JobOptions(
            preset="security",
            run_functionality=True,
            run_security=True,
            run_style=False,
            run_quality=True,
            run_fuzzing=False,
            fuzz_duration_seconds=90,
            max_report_findings=250,
        ),
    },
    "fuzz": {
        "label": "Fuzz sprint",
        "description": "Time-boxed fuzz preparation with build validation and a report focused on attack surface.",
        "options": JobOptions(
            preset="fuzz",
            run_functionality=True,
            run_security=False,
            run_style=False,
            run_quality=False,
            run_fuzzing=True,
            fuzz_duration_seconds=300,
            max_report_findings=150,
        ),
    },
}


def normalize_preset_name(name: str | None) -> str:
    if not name:
        return "balanced"
    normalized = name.strip().lower()
    return normalized if normalized in PRESET_DEFINITIONS else "balanced"


def preset_options(name: str | None, mode: JobMode | str) -> JobOptions:
    preset_name = normalize_preset_name(name)
    options = JobOptions(**asdict(PRESET_DEFINITIONS[preset_name]["options"]))  # type: ignore[arg-type]
    if mode in {"fuzz_single", "fuzz_project"}:
        options.run_fuzzing = True
    return options


def list_presets(language: str = "en") -> list[dict[str, object]]:
    presets: list[dict[str, object]] = []
    for key, preset in PRESET_DEFINITIONS.items():
        options = preset["options"]
        assert isinstance(options, JobOptions)
        presets.append(
            {
                "key": key,
                "label": translate(language, str(preset["label"])),
                "description": translate(language, str(preset["description"])),
                "options": asdict(options),
            }
        )
    return presets
