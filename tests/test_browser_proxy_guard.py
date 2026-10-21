"""Local-only browser egress guard tests."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from threading import Thread
import unittest

from hackbot.browser_proxy_guard import BrowserProxyGuard, BrowserProxyGuardError
from hackbot.target_scope import (HostRule, PathRule, ProgramScope,
                                  ScopeProvenance, ScopeSourceKind)


def scope(*, include_paths=()):
    return ProgramScope(
        package_id="fixture", include_hosts=(HostRule("mapped.fixture.test"),),
        provenance=ScopeProvenance(ScopeSourceKind.RESEARCHER, "fixture",
                                   datetime.now(timezone.utc)),
        include_paths=include_paths,
    )


class BrowserProxyGuardTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen

        class Capture(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(("GET", self.path))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"captured")

            def do_CONNECT(self):
                seen.append(("CONNECT", self.path))
                self.send_response(200, "Connection Established")
                self.end_headers()

            def log_message(self, _format, *_args):
                pass

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Capture)
        self.worker = Thread(target=self.upstream.serve_forever, daemon=True)
        self.worker.start()
        self.guard = BrowserProxyGuard(scope(), f"http://127.0.0.1:{self.upstream.server_port}")

    def tearDown(self):
        self.guard.close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.worker.join()

    def request(self, message):
        with socket.create_connection(("127.0.0.1", int(self.guard.proxy_url.rsplit(":", 1)[1])), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(message)
            return connection.recv(4096)

    def test_allowed_http_reaches_capture(self):
        response = self.request(b"GET http://mapped.fixture.test/page HTTP/1.1\r\n"
                                b"Host: mapped.fixture.test\r\nConnection: close\r\n\r\n")
        self.assertIn(b"200", response)
        self.assertEqual(self.seen, [("GET", "http://mapped.fixture.test/page")])
        self.assertEqual(self.guard.counts, (1, 0))

    def test_unrelated_and_host_confused_http_never_reach_capture(self):
        for target, host in (("outside.fixture.test", "outside.fixture.test"),
                             ("mapped.fixture.test", "outside.fixture.test")):
            response = self.request(f"GET http://{target}/page HTTP/1.1\r\n"
                                    f"Host: {host}\r\n\r\n".encode())
            self.assertIn(b"403", response)
        self.assertEqual(self.seen, [])
        self.assertEqual(self.guard.counts, (0, 2))

    def test_connect_requires_scoped_authority(self):
        denied = self.request(b"CONNECT accounts.google.com:443 HTTP/1.1\r\n"
                              b"Host: accounts.google.com:443\r\n\r\n")
        allowed = self.request(b"CONNECT mapped.fixture.test:443 HTTP/1.1\r\n"
                               b"Host: mapped.fixture.test:443\r\n\r\n")
        self.assertIn(b"403", denied)
        self.assertIn(b"200", allowed)
        self.assertEqual(self.seen, [("CONNECT", "mapped.fixture.test:443")])

    def test_rejects_path_restricted_scope_and_non_loopback_upstream(self):
        with self.assertRaises(BrowserProxyGuardError):
            BrowserProxyGuard(scope(include_paths=(PathRule("/only"),)),
                              f"http://127.0.0.1:{self.upstream.server_port}")
        with self.assertRaises(BrowserProxyGuardError):
            BrowserProxyGuard(scope(), "http://outside.fixture.test:8080")
