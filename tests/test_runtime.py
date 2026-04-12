import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from qa_portal.runtime import choose_endpoint, healthcheck, load_endpoint_state, save_endpoint_state


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            payload = json.dumps({"status": "ok"}).encode("utf-8")
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


class RuntimeTests(unittest.TestCase):
    def test_choose_endpoint_uses_fallback_range_when_port_is_auto(self):
        fallback = _free_port()

        result = choose_endpoint("127.0.0.1", "auto", range_start=fallback, range_end=fallback + 2)

        self.assertEqual(result["port"], fallback)
        self.assertEqual(result["status"], "fallback-free")

    def test_choose_endpoint_prefers_free_desired_port(self):
        preferred = _free_port()
        result = choose_endpoint("127.0.0.1", str(preferred), range_start=preferred, range_end=preferred + 2)

        self.assertEqual(result["port"], preferred)
        self.assertEqual(result["status"], "preferred-free")

    def test_choose_endpoint_falls_back_when_preferred_port_is_foreign(self):
        preferred = _free_port()
        fallback = _free_port()
        range_start = min(preferred, fallback)
        range_end = max(preferred, fallback)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", preferred))
            sock.listen(1)

            result = choose_endpoint("127.0.0.1", str(preferred), range_start=range_start, range_end=range_end)

        self.assertNotEqual(result["port"], preferred)
        self.assertEqual(result["status"], "preferred-occupied-foreign")

    def test_choose_endpoint_detects_running_scanforge(self):
        port = _free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), _HealthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

        result = choose_endpoint("127.0.0.1", str(port), range_start=port, range_end=port + 1)

        self.assertEqual(result["port"], port)
        self.assertEqual(result["status"], "scanforge-running")
        self.assertTrue(healthcheck("127.0.0.1", port))

    def test_choose_endpoint_raises_when_no_free_ports_found(self):
        preferred = _free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", preferred))
            sock.listen(1)

            with self.assertRaises(RuntimeError):
                choose_endpoint("127.0.0.1", str(preferred), range_start=preferred, range_end=preferred)

    def test_endpoint_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "endpoint.env"
            save_endpoint_state(state_path, "127.0.0.1", 8010)
            payload = load_endpoint_state(state_path)

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload["host"], "127.0.0.1")
        self.assertEqual(payload["port"], 8010)
        self.assertEqual(payload["url"], "http://127.0.0.1:8010")


if __name__ == "__main__":
    unittest.main()
