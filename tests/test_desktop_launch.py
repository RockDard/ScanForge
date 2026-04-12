import os
import socket
import subprocess
import tempfile
import textwrap
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            payload = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A003
        return


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


class DesktopLaunchTests(unittest.TestCase):
    def _write_fake_pkexec(self, temp_dir: str) -> tuple[Path, Path]:
        bin_dir = Path(temp_dir) / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        mark_file = Path(temp_dir) / "pkexec.called"
        stub = bin_dir / "pkexec"
        stub.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                : "${FAKE_PKEXEC_MARK_FILE:?}"
                touch "$FAKE_PKEXEC_MARK_FILE"
                if [[ "${FAKE_PKEXEC_WRITE_STATE:-0}" == "1" ]]; then
                  : "${SCANFORGE_RUN_DIR:?}"
                  : "${FAKE_ENDPOINT_HOST:?}"
                  : "${FAKE_ENDPOINT_PORT:?}"
                  mkdir -p "$SCANFORGE_RUN_DIR"
                  cat >"$SCANFORGE_RUN_DIR/endpoint.env" <<EOF
                QA_PORTAL_HOST=$FAKE_ENDPOINT_HOST
                QA_PORTAL_PORT=$FAKE_ENDPOINT_PORT
                SCANFORGE_URL=http://$FAKE_ENDPOINT_HOST:$FAKE_ENDPOINT_PORT
                EOF
                  printf 'http://%s:%s\\n' "$FAKE_ENDPOINT_HOST" "$FAKE_ENDPOINT_PORT"
                fi
                """
            ),
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return bin_dir, mark_file

    def _start_health_server(self, port: int) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", port), _HealthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

    def test_install_shortcut_script_creates_non_terminal_desktop_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            desktop_dir = Path(temp_dir) / "Desktop"
            env = os.environ.copy()
            env["DESKTOP_DIR"] = str(desktop_dir)

            result = subprocess.run(
                ["bash", str(ROOT_DIR / "scripts" / "install-desktop-shortcut.sh")],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            desktop_file = desktop_dir / "ScanForge.desktop"
            self.assertEqual(result.stdout.strip(), str(desktop_file))
            self.assertTrue(desktop_file.exists())

            content = desktop_file.read_text(encoding="utf-8")
            self.assertIn("Name=ScanForge", content)
            self.assertIn("Terminal=false", content)
            self.assertIn("launch-scanforge-desktop.sh", content)
            self.assertIn("scanforge-icon.svg", content)

    def test_launch_reuses_alive_saved_endpoint_without_pkexec(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            port = _free_port()
            run_dir = Path(temp_dir) / "run"
            run_dir.mkdir(parents=True, exist_ok=True)
            endpoint_file = run_dir / "endpoint.env"
            endpoint_file.write_text(
                "\n".join(
                    [
                        "QA_PORTAL_HOST=127.0.0.1",
                        f"QA_PORTAL_PORT={port}",
                        f"SCANFORGE_URL=http://127.0.0.1:{port}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            self._start_health_server(port)
            bin_dir, mark_file = self._write_fake_pkexec(temp_dir)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SCANFORGE_RUN_DIR"] = str(run_dir)
            env["SCANFORGE_SKIP_BROWSER"] = "1"
            env["FAKE_PKEXEC_MARK_FILE"] = str(mark_file)

            result = subprocess.run(
                ["bash", str(ROOT_DIR / "scripts" / "launch-scanforge-desktop.sh")],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertFalse(mark_file.exists(), "pkexec не должен вызываться при живом сохраненном endpoint")

    def test_launch_starts_new_instance_when_saved_endpoint_is_stale(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            stale_port = _free_port()
            live_port = _free_port()
            run_dir = Path(temp_dir) / "run"
            run_dir.mkdir(parents=True, exist_ok=True)
            endpoint_file = run_dir / "endpoint.env"
            endpoint_file.write_text(
                "\n".join(
                    [
                        "QA_PORTAL_HOST=127.0.0.1",
                        f"QA_PORTAL_PORT={stale_port}",
                        f"SCANFORGE_URL=http://127.0.0.1:{stale_port}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            self._start_health_server(live_port)
            bin_dir, mark_file = self._write_fake_pkexec(temp_dir)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SCANFORGE_RUN_DIR"] = str(run_dir)
            env["SCANFORGE_SKIP_BROWSER"] = "1"
            env["FAKE_PKEXEC_MARK_FILE"] = str(mark_file)
            env["FAKE_PKEXEC_WRITE_STATE"] = "1"
            env["FAKE_ENDPOINT_HOST"] = "127.0.0.1"
            env["FAKE_ENDPOINT_PORT"] = str(live_port)

            result = subprocess.run(
                ["bash", str(ROOT_DIR / "scripts" / "launch-scanforge-desktop.sh")],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(mark_file.exists(), "pkexec должен вызываться для перезапуска при устаревшем endpoint")
            content = endpoint_file.read_text(encoding="utf-8")
            self.assertIn(f"QA_PORTAL_PORT={live_port}", content)
            self.assertIn(f"SCANFORGE_URL=http://127.0.0.1:{live_port}", content)
