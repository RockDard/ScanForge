import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qa_portal.ai_review import (
    ai_backend_status,
    build_ai_review_markdown,
    generate_ai_review,
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

    def test_generate_ai_review_uses_local_fallback_when_disabled(self):
        with patch.dict(os.environ, {"AI_ANALYZER_ENABLED": "0"}, clear=False):
            review, logs = generate_ai_review(sample_report_data())
        self.assertEqual(review["source"], "local-fallback")
        self.assertIn("local fallback review", review["reason"].lower())
        self.assertTrue(logs)

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

    def test_build_ai_review_markdown_writes_artifact(self):
        review = {
            "source": "local-fallback",
            "provider": "openai-compatible",
            "confidence": "medium",
            "release_decision": "needs-fixes",
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
        self.assertIn("Release decision: needs-fixes", content)


if __name__ == "__main__":
    unittest.main()
