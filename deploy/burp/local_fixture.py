#!/usr/bin/env python3
"""Loopback-only HTTP/HTTPS fixture for operator Burp capture checks."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/identity/fixture_a":
            body = b'<html><title>Fixture A</title><span id="user">fixture-a</span><span id="tenant">local-fixture</span></html>'
        elif self.path == "/identity/fixture_b":
            body = b'<html><title>Fixture B</title><span id="user">fixture-b</span><span id="tenant">local-fixture</span></html>'
        elif self.path == "/anonymous":
            body = b"<html><title>Anonymous fixture</title><main>Local fixture</main></html>"
        elif self.path == "/ready":
            body = b"local fixture ready"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if self.path.startswith("/identity/"):
            self.send_header("Set-Cookie", "synthetic_session=local-fixture-cookie; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="bughunter-burp-fixture-") as directory:
        root = Path(directory)
        cert = root / "fixture.crt"
        key = root / "fixture.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        key.chmod(0o600)
        http = ThreadingHTTPServer(("127.0.0.1", 39800), Handler)
        https = ThreadingHTTPServer(("127.0.0.1", 39801), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        threads = [threading.Thread(target=server.serve_forever, daemon=True)
                   for server in (http, https)]
        for thread in threads:
            thread.start()
        print("Local fixture ready on 127.0.0.1:39800 and 127.0.0.1:39801", flush=True)
        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            pass
        finally:
            http.shutdown()
            https.shutdown()
            http.server_close()
            https.server_close()


if __name__ == "__main__":
    main()
