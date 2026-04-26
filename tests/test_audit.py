import json
import tempfile
import unittest
from pathlib import Path

from qa_portal.audit import (
    append_audit_event,
    audit_status,
    list_audit_events,
    sanitize_audit_details,
)


class AuditLogTests(unittest.TestCase):
    def test_sanitize_audit_details_redacts_nested_secrets(self):
        payload = {
            "username": "admin",
            "password": "secret",
            "nested": {
                "api_key": "key",
                "items": [{"auth_token": "token"}, {"safe": "value"}],
            },
        }

        sanitized = sanitize_audit_details(payload)

        self.assertEqual(sanitized["username"], "admin")
        self.assertEqual(sanitized["password"], "<redacted>")
        self.assertEqual(sanitized["nested"]["api_key"], "<redacted>")
        self.assertEqual(sanitized["nested"]["items"][0]["auth_token"], "<redacted>")
        self.assertEqual(sanitized["nested"]["items"][1]["safe"], "value")

    def test_append_and_list_audit_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "audit" / "events.jsonl"
            event = append_audit_event(
                "settings.update",
                actor={"username": "admin", "role": "admin", "client": "127.0.0.1"},
                resource_type="settings",
                resource_id="ai_backend",
                details={"api_key": "secret", "enabled": True},
                path=path,
            )
            events = list_audit_events(path=path)
            status = audit_status(path=path)

        self.assertEqual(event["action"], "settings.update")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["details"]["api_key"], "<redacted>")
        self.assertEqual(status["event_count"], 1)

    def test_list_audit_events_skips_invalid_json_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.jsonl"
            path.write_text(
                "not-json\n" + json.dumps({"action": "ok"}) + "\n",
                encoding="utf-8",
            )

            events = list_audit_events(path=path)

        self.assertEqual(events, [{"action": "ok"}])

    def test_list_audit_events_limit_counts_valid_events_not_raw_tail_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.jsonl"
            path.write_text(
                "\n".join(
                    [
                        json.dumps({"action": "first"}),
                        json.dumps({"action": "second"}),
                        "not-json",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            events = list_audit_events(limit=2, path=path)

        self.assertEqual(events, [{"action": "first"}, {"action": "second"}])


if __name__ == "__main__":
    unittest.main()
