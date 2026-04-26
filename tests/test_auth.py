import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qa_portal import auth


class _Request:
    def __init__(self, path: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> None:
        self.url = type("URL", (), {"path": path})()
        self.method = method
        self.headers = headers or {}


def _basic(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


class AuthBootstrapTests(unittest.TestCase):
    def test_network_host_enables_auto_auth_when_explicitly_requested(self):
        with patch.dict(
            os.environ,
            {
                "QA_PORTAL_HOST": "0.0.0.0",
                "QA_PORTAL_AUTH_AUTO_SETUP": "1",
                "QA_PORTAL_ADMIN_PASSWORD": "",
            },
            clear=True,
        ):
            self.assertTrue(auth.auth_enabled())
            status = auth.auth_status()

        self.assertTrue(status["network_bind_requested"])
        self.assertEqual(status["source"], "bootstrap-pending")

    def test_bootstrap_password_authenticates_admin(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = Path(temp_dir) / "settings" / "auth_bootstrap.json"
            with patch.dict(
                os.environ,
                {
                    "QA_PORTAL_AUTH_ENABLED": "1",
                    "QA_PORTAL_AUTH_BOOTSTRAP": "1",
                    "QA_PORTAL_ADMIN_USER": "admin",
                    "QA_PORTAL_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                with patch("qa_portal.auth.AUTH_BOOTSTRAP_PATH", auth_path):
                    challenge = auth.authenticate_request(_Request("/"))
                    payload = json.loads(auth_path.read_text(encoding="utf-8"))
                    admin = auth.authenticate_request(
                        _Request("/", headers={"authorization": _basic("admin", payload["admin_password"])})
                    )

        self.assertEqual(challenge.status_code, 401)
        self.assertEqual(admin.role, "admin")

    def test_bootstrap_admin_user_is_read_from_file_when_env_user_is_absent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = Path(temp_dir) / "settings" / "auth_bootstrap.json"
            auth_path.parent.mkdir(parents=True, exist_ok=True)
            auth_path.write_text(
                json.dumps({"admin_user": "operator", "admin_password": "generated-secret"}),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "QA_PORTAL_AUTH_ENABLED": "1",
                    "QA_PORTAL_AUTH_BOOTSTRAP": "1",
                    "QA_PORTAL_ADMIN_PASSWORD": "",
                },
                clear=True,
            ):
                with patch("qa_portal.auth.AUTH_BOOTSTRAP_PATH", auth_path):
                    rejected = auth.authenticate_request(
                        _Request("/", headers={"authorization": _basic("admin", "generated-secret")})
                    )
                    accepted = auth.authenticate_request(
                        _Request("/", headers={"authorization": _basic("operator", "generated-secret")})
                    )
                    status = auth.auth_status()

        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(accepted.role, "admin")
        self.assertEqual(status["admin_user"], "operator")

    def test_explicit_auth_without_password_still_reports_misconfiguration(self):
        with patch.dict(
            os.environ,
            {
                "QA_PORTAL_AUTH_ENABLED": "1",
                "QA_PORTAL_AUTH_BOOTSTRAP": "0",
                "QA_PORTAL_AUTH_AUTO_SETUP": "0",
                "QA_PORTAL_ADMIN_PASSWORD": "",
            },
            clear=True,
        ):
            response = auth.authenticate_request(_Request("/"))

        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
