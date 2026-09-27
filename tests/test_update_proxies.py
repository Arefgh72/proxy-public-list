import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "update_proxies.py"
SPEC = importlib.util.spec_from_file_location("update_proxies", SCRIPT)
update_proxies = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update_proxies)


class ProxyListTests(unittest.TestCase):
    def test_parser_accepts_formats_deduplicates_and_rejects_private(self):
        parsed = update_proxies.parse_candidates(
            "http://8.8.8.8:8080\n8.8.8.8:8080\n127.0.0.1:9000\nlocalhost:80\n"
        )
        self.assertEqual(parsed, ["8.8.8.8:8080"])

    def test_probe_requires_verified_tls_for_every_target(self):
        seen_hosts = []

        class FakeSocket:
            def settimeout(self, _timeout):
                pass

            def sendall(self, _data):
                pass

            def recv(self, _size):
                return b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n"

            def close(self):
                pass

        class FakeTLSSocket:
            def close(self):
                pass

        class FakeTLSContext:
            def set_alpn_protocols(self, _protocols):
                pass

            def wrap_socket(self, sock, server_hostname):
                seen_hosts.append(server_hostname)
                return FakeTLSSocket()

        with patch.object(update_proxies.socket, "create_connection", side_effect=lambda *_a, **_k: FakeSocket()), \\
             patch.object(update_proxies.ssl, "create_default_context", return_value=FakeTLSContext()):
            latency = update_proxies.probe_proxy("8.8.8.8:8080")

        self.assertIsNotNone(latency)
        self.assertEqual(seen_hosts, list(update_proxies.TEST_HOSTS))

    def test_probe_rejects_proxy_when_any_target_certificate_is_untrusted(self):
        seen_hosts = []

        class FakeSocket:
            def settimeout(self, _timeout):
                pass

            def sendall(self, _data):
                pass

            def recv(self, _size):
                return b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n"

            def close(self):
                pass

        class FakeTLSContext:
            def set_alpn_protocols(self, _protocols):
                pass

            def wrap_socket(self, sock, server_hostname):
                seen_hosts.append(server_hostname)
                if server_hostname == "browserleaks.com":
                    raise update_proxies.ssl.SSLCertVerificationError("untrusted certificate")
                return sock

        with patch.object(update_proxies.socket, "create_connection", side_effect=lambda *_a, **_k: FakeSocket()), \\
             patch.object(update_proxies.ssl, "create_default_context", return_value=FakeTLSContext()):
            latency = update_proxies.probe_proxy("8.8.8.8:8080")

        self.assertIsNone(latency)
        self.assertEqual(seen_hosts, ["example.com", "browserleaks.com"])

    def test_refresh_sorts_and_writes_only_fast_verified_proxies(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "proxies.txt"
            status = Path(tmp) / "status.json"
            count = update_proxies.refresh(
                [{"name": "test", "url": "unused"}], output, status,
                fetcher=lambda _: "8.8.8.8:8080\n1.1.1.1:80\n9.9.9.9:443\n",
                prober=lambda proxy: {"8.8.8.8:8080": 300, "1.1.1.1:80": 120, "9.9.9.9:443": 1000}[proxy],
            )
            self.assertEqual(count, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "1.1.1.1:80\n8.8.8.8:8080\n")
            self.assertIn('"working_count": 2', status.read_text(encoding="utf-8"))

    def test_failed_refresh_preserves_existing_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "proxies.txt"
            output.write_text("8.8.8.8:8080\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                update_proxies.refresh(
                    [{"name": "test", "url": "unused"}], output, Path(tmp) / "status.json",
                    fetcher=lambda _: "8.8.8.8:8080\n", prober=lambda _: None,
                )
            self.assertEqual(output.read_text(encoding="utf-8"), "8.8.8.8:8080\n")


if __name__ == "__main__":
    unittest.main()
