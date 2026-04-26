import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import qa_portal.ai_review as ai_review_module
from qa_portal.ai_review import (
    ai_backend_status,
    build_ai_review_markdown,
    generate_ai_review,
    preferred_local_model,
    probe_ai_backend,
    select_active_playbooks,
)


def sample_report_data() -> dict:
    return {
        "job": {
            "name": "Qt release gate",
            "id": "job123",
            "mode": "full_scan",
            "original_filename": "project.zip",
        },
        "project": {
            "file_count": 12,
            "is_qt_project": True,
            "build_systems": ["cmake"],
            "has_tests": True,
        },
        "summary": {
            "risk_score": 48,
            "highest_severity": "high",
            "execution_verdict": "build-and-tests-ran",
            "total_findings": 6,
            "selected_checks": ["functionality", "security", "style"],
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 2,
                "info": 1,
            },
            "next_actions": [
                {
                    "severity": "high",
                    "title": "Potential buffer overflow",
                    "recommendation": "Replace strcpy with bounded operations.",
                },
                {
                    "severity": "low",
                    "title": "Tab indentation",
                    "recommendation": "Normalize formatting with spaces.",
                },
            ],
        },
        "findings": [
            {
                "severity": "high",
                "category": "security",
                "title": "Potential buffer overflow",
                "description": "Matched strcpy() in source.",
                "path": "src/main.cpp",
                "line": 14,
                "source": "built-in-security-rules",
                "recommendation": "Replace strcpy with bounded operations.",
            }
        ],
    }


class AiReviewTests(unittest.TestCase):
    def test_backend_status_defaults_to_local_fallback(self):
        with patch.dict(os.environ, {}, clear=False):
            status = ai_backend_status()
        self.assertFalse(status["enabled"])
        self.assertFalse(status["configured"])
        self.assertEqual(status["mode"], "local-fallback")
        self.assertIn("default_model", status)
        self.assertIn("local_models", status)

    def test_backend_status_exposes_local_model_download_progress(self):
        model_id = "qwen2.5-coder-3b-instruct"
        with patch("qa_portal.ai_review._detect_local_runner", return_value=None):
            with patch.dict(
                ai_review_module._MODEL_DOWNLOAD_STATE,
                {
                    model_id: {
                        "running": True,
                        "finished": False,
                        "downloaded_bytes": 512,
                        "total_bytes": 1024,
                        "progress_percent": 50,
                    }
                },
                clear=True,
            ):
                with patch.dict(ai_review_module._MODEL_DOWNLOAD_THREADS, {}, clear=True):
                    status = ai_backend_status()

        model = next(item for item in status["local_models"] if item["id"] == model_id)
        self.assertTrue(model["download_state"]["running"])
        self.assertEqual(model["download_state"]["downloaded_bytes"], 512)
        self.assertEqual(model["download_state"]["total_bytes"], 1024)
        self.assertEqual(model["download_state"]["progress_percent"], 50)
        self.assertEqual(status["downloads_running"], 1)

    def test_generate_ai_review_uses_local_fallback_when_disabled(self):
        with patch.dict(os.environ, {"AI_ANALYZER_ENABLED": "0"}, clear=False):
            review, logs = generate_ai_review(sample_report_data())
        self.assertEqual(review["source"], "local-fallback")
        self.assertIn("local fallback review", review["reason"].lower())
        self.assertIn("active_playbooks", review)
        self.assertIn("routing_reason", review)
        self.assertTrue(logs)

    def test_select_active_playbooks_uses_dependency_and_runtime_signals(self):
        report = sample_report_data()
        report["dependencies"] = {"component_count": 3}
        report["dependency_diff"] = {"new_vulnerable_count": 1}
        report["dynamic_analysis"] = {"sanitizer_tests_ran": True}
        report["service_runtime"] = {"verification_results": [{"path": "/health"}]}

        playbooks = select_active_playbooks(report)

        self.assertIn("triage", playbooks)
        self.assertIn("dependency-review", playbooks)
        self.assertIn("crash-troubleshooting", playbooks)
        self.assertIn("test-design", playbooks)

    def test_preferred_local_model_respects_operator_pin(self):
        fake_models = [
            {"id": "llama-3.2-3b-instruct", "label": "Llama", "role": "general-review", "installed": True, "default": False},
            {"id": "qwen2.5-coder-3b-instruct", "label": "Qwen", "role": "code-and-test-review", "installed": True, "default": True},
        ]

        with patch("qa_portal.ai_review._detect_local_runner", return_value="/usr/bin/llama-cli"):
            with patch("qa_portal.ai_review.list_local_models", return_value=fake_models):
                selected, reason = preferred_local_model(
                    settings={"preferred_local_model": "llama-3.2-3b-instruct"}
                )

        self.assertEqual(selected["id"], "llama-3.2-3b-instruct")
        self.assertIn("pinned", reason)

    def test_generate_ai_review_uses_remote_backend_when_available(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "overview": "The project is broadly healthy but needs security fixes.",
                                        "release_decision": "needs-fixes",
                                        "risk_narrative": "One high-severity issue should be resolved before release.",
                                        "blockers": ["Replace strcpy with a bounded copy primitive."],
                                        "quick_wins": ["Run formatting cleanup on the touched files."],
                                        "confidence": "high",
                                    }
                                )
                            }
                        }
                    ]
                }

        class FakeClient:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def post(self, url, headers=None, json=None):
                self.url = url
                self.headers = headers
                self.payload = json
                return FakeResponse()

        with patch.dict(
            os.environ,
            {
                "AI_ANALYZER_ENABLED": "1",
                "AI_ANALYZER_URL": "https://example.invalid/v1/chat/completions",
                "AI_ANALYZER_MODEL": "demo-model",
                "AI_ANALYZER_PROVIDER": "openai-compatible",
            },
            clear=False,
        ):
            with patch("qa_portal.ai_review.httpx.Client", FakeClient):
                review, _logs = generate_ai_review(sample_report_data())

        self.assertEqual(review["source"], "remote-ai")
        self.assertEqual(review["release_decision"], "needs-fixes")
        self.assertEqual(review["confidence"], "high")
        self.assertTrue(review["blockers"])
        self.assertIn("active_playbooks", review)

    def test_generate_ai_review_uses_local_llm_when_model_is_ready(self):
        class FakeCompletedProcess:
            returncode = 0
            stdout = json.dumps(
                {
                    "overview": "Local model reviewed the scan and found one release blocker.",
                    "release_decision": "needs-fixes",
                    "risk_narrative": "A local GGUF model flagged a security issue before release.",
                    "blockers": ["Fix the buffer overflow before release."],
                    "quick_wins": ["Re-run the focused tests after the patch."],
                    "confidence": "medium",
                }
            )
            stderr = ""

        with patch.dict(os.environ, {"AI_ANALYZER_ENABLED": "0"}, clear=False):
            with patch("qa_portal.ai_review.preferred_local_model", return_value=({"label": "Qwen", "path": "/tmp/model.gguf"}, "selected")):
                with patch("qa_portal.ai_review._detect_local_runner", return_value="/usr/bin/llama-cli"):
                    with patch("qa_portal.ai_review.subprocess.run", return_value=FakeCompletedProcess()):
                        review, logs = generate_ai_review(sample_report_data())

        self.assertEqual(review["source"], "local-llm")
        self.assertEqual(review["release_decision"], "needs-fixes")
        self.assertTrue(logs)

    def test_generate_ai_review_falls_back_from_remote_to_local_llm(self):
        class FailingClient:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def post(self, url, headers=None, json=None):
                raise ai_review_module.httpx.HTTPError("remote failed")

        class FakeCompletedProcess:
            returncode = 0
            stdout = json.dumps(
                {
                    "overview": "Local rescue review succeeded.",
                    "release_decision": "needs-fixes",
                    "risk_narrative": "Local model took over after remote failure.",
                    "blockers": ["Fix the buffer overflow before release."],
                    "quick_wins": ["Re-run the focused tests after the patch."],
                    "confidence": "medium",
                }
            )
            stderr = ""

        with patch.dict(
            os.environ,
            {
                "AI_ANALYZER_ENABLED": "1",
                "AI_ANALYZER_URL": "https://example.invalid/v1/chat/completions",
                "AI_ANALYZER_MODEL": "demo-model",
                "AI_ANALYZER_PROVIDER": "openai-compatible",
            },
            clear=False,
        ):
            with patch("qa_portal.ai_review.httpx.Client", FailingClient):
                with patch("qa_portal.ai_review.preferred_local_model", return_value=({"label": "Qwen", "path": "/tmp/model.gguf"}, "local ready")):
                    with patch("qa_portal.ai_review._detect_local_runner", return_value="/usr/bin/llama-cli"):
                        with patch("qa_portal.ai_review.subprocess.run", return_value=FakeCompletedProcess()):
                            review, logs = generate_ai_review(sample_report_data())

        self.assertEqual(review["source"], "local-llm")
        self.assertTrue(any("remote failed" in entry.lower() for entry in logs))

    def test_probe_ai_backend_reports_remote_success(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"choices": [{"message": {"content": "{}"}}]}

        class FakeClient:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def post(self, url, headers=None, json=None):
                return FakeResponse()

        with patch.dict(
            os.environ,
            {
                "AI_ANALYZER_ENABLED": "1",
                "AI_ANALYZER_URL": "https://example.invalid/v1/chat/completions",
                "AI_ANALYZER_MODEL": "demo-model",
                "AI_ANALYZER_PROVIDER": "openai-compatible",
            },
            clear=False,
        ):
            with patch("qa_portal.ai_review.httpx.Client", FakeClient):
                payload = probe_ai_backend()

        self.assertTrue(payload["remote"]["configured"])
        self.assertTrue(payload["remote"]["ok"])

    def test_build_ai_review_markdown_writes_artifact(self):
        review = {
            "source": "local-fallback",
            "provider": "openai-compatible",
            "confidence": "medium",
            "release_decision": "needs-fixes",
            "active_playbooks": ["Risk triage and release decision"],
            "routing_reason": "Routing selected the deterministic fallback.",
            "overview": "Overview text.",
            "risk_narrative": "Risk text.",
            "blockers": ["Blocker one."],
            "quick_wins": ["Quick win one."],
            "reason": "Generated locally.",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "ai_review.md"
            build_ai_review_markdown(review, output)
            content = output.read_text(encoding="utf-8")
        self.assertIn("# AI Review", content)
        self.assertIn("## Active Playbooks", content)
        self.assertIn("Release decision: needs-fixes", content)


if __name__ == "__main__":
    unittest.main()
