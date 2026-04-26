import os
import unittest
from unittest.mock import patch

from qa_portal import network


class NetworkPolicyTests(unittest.TestCase):
    def test_empty_allowed_hosts_keeps_backward_compatible_open_host_policy(self):
        with patch.dict(os.environ, {"QA_PORTAL_ALLOWED_HOSTS": ""}):
            self.assertTrue(network.host_allowed("scanforge.example.test:8000"))
            self.assertTrue(network.host_allowed("192.168.1.50:8000"))

    def test_allowed_hosts_match_exact_hosts_ports_and_wildcards(self):
        with patch.dict(
            os.environ,
            {"QA_PORTAL_ALLOWED_HOSTS": "scanforge.example.test,192.168.1.20:8000,*.corp.test"},
        ):
            self.assertTrue(network.host_allowed("scanforge.example.test:9000"))
            self.assertTrue(network.host_allowed("192.168.1.20:8000"))
            self.assertTrue(network.host_allowed("qa.corp.test"))
            self.assertFalse(network.host_allowed("192.168.1.20:9000"))
            self.assertFalse(network.host_allowed("evil.example.test"))

    def test_cors_headers_are_emitted_only_for_configured_origins(self):
        with patch.dict(
            os.environ,
            {
                "QA_PORTAL_CORS_ORIGINS": "https://scanforge.example.test,http://localhost:8000",
                "QA_PORTAL_CORS_ALLOW_CREDENTIALS": "0",
            },
        ):
            headers = network.cors_headers("https://scanforge.example.test")

            self.assertEqual(headers["Access-Control-Allow-Origin"], "https://scanforge.example.test")
            self.assertIn("GET", headers["Access-Control-Allow-Methods"])
            self.assertEqual(network.cors_headers("https://evil.example.test"), {})

    def test_cors_wildcard_reflects_origin_when_credentials_are_enabled(self):
        with patch.dict(
            os.environ,
            {
                "QA_PORTAL_CORS_ORIGINS": "*",
                "QA_PORTAL_CORS_ALLOW_CREDENTIALS": "1",
            },
        ):
            headers = network.cors_headers("https://scanforge.example.test")

            self.assertEqual(headers["Access-Control-Allow-Origin"], "https://scanforge.example.test")
            self.assertEqual(headers["Access-Control-Allow-Credentials"], "true")

    def test_network_status_reports_lan_urls_and_open_host_warning(self):
        addresses = [
            {"address": "192.168.1.20", "family": "ipv4", "private": True, "link_local": False},
            {"address": "fe80::1", "family": "ipv6", "private": True, "link_local": True},
        ]
        with patch.dict(
            os.environ,
            {
                "QA_PORTAL_HOST": "0.0.0.0",
                "QA_PORTAL_PORT": "8020",
                "QA_PORTAL_ALLOWED_HOSTS": "",
                "QA_PORTAL_CORS_ORIGINS": "",
                "QA_PORTAL_CORS_ALLOW_CREDENTIALS": "0",
            },
        ), patch.object(network, "local_network_addresses", return_value=addresses):
            status = network.network_access_status()

        self.assertTrue(status["network_bind"])
        self.assertEqual(status["lan_urls"], ["http://192.168.1.20:8020"])
        self.assertIn("QA_PORTAL_ALLOWED_HOSTS", status["warnings"][0])


if __name__ == "__main__":
    unittest.main()
