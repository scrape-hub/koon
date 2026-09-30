"""Shared fixtures for the koon Python binding test suite.

The offline tests run against a plain HTTP server on localhost, so they
never touch the network. Tests that do need real internet access are
marked `@pytest.mark.network` and deselected by default (see pyproject.toml
`addopts`).
"""

import base64
import gzip
import hashlib
import http.server
import json
import socket
import ssl
import struct
import threading
import time

import pytest


class EchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _send_json(self, status, payload, extra_headers=None):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _echo(self, body):
        payload = {
            "method": self.command,
            "path": self.path,
            "headers": list(self.headers.items()),
            "body": body.decode("utf-8", "replace"),
        }
        self._send_json(200, payload)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            # A client that times out or gives up mid-response closes the
            # socket; nothing left to do here.
            self.close_connection = True

    def _dispatch(self):
        body = self._read_body()
        path = self.path

        if path == "/echo":
            self._echo(body)
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/echo")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/redirect-loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/slow":
            time.sleep(1.5)
            self._echo(body)
        elif path == "/hang":
            time.sleep(5)
            self._echo(body)
        elif path == "/set-cookie":
            self._send_json(
                200,
                {"ok": True},
                extra_headers=[("Set-Cookie", "sid=abc123; Path=/")],
            )
        elif path == "/status/500":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/challenge":
            page = b"<html><head><title>Just a moment...</title></head></html>"
            self.send_response(403)
            self.send_header("cf-mitigated", "challenge")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch
    do_PATCH = _dispatch
    do_HEAD = _dispatch

    def log_message(self, format, *args):  # noqa: A002 - matches base signature
        pass


@pytest.fixture(scope="session")
def base_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


class AdapterHandler(EchoHandler):
    """The echo server plus what the streaming and adapter tests need: a
    gzip body, a body held back until the test opens a gate, an endless one
    that notices when the client drops it, a 307 and a redirect that sets a
    cookie."""

    def _chunk(self, data):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def _redirect(self, status, extra_headers=()):
        self.send_response(status)
        self.send_header("Location", "/echo")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch(self):
        path = self.path
        if path not in (
            "/gzip", "/br", "/bad-gzip", "/gated", "/drip", "/redirect-307", "/redirect-cookie", "/no-content",
        ):
            return super()._dispatch()
        self._read_body()
        if path in ("/gzip", "/br", "/bad-gzip"):
            coding = "br" if path == "/br" else "gzip"
            data = {"/gzip": gzip.compress(GZIP_TEXT), "/br": BR_BODY}.get(path, b"not gzip at all")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Encoding", coding)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/gated":
            # The first chunk goes out at once, the rest once the test opens
            # the gate: a client that buffers the body sees nothing before.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self._chunk(b"first;")
            self.server.gate.wait(5)
            self._chunk(b"second")
            self._chunk(b"")
        elif path == "/drip":
            # A chunk every 50 ms for 5 s; once the client drops the
            # connection, writing fails and `server.dripped` is set.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for _ in range(100):
                    self._chunk(b"drip;")
                    time.sleep(0.05)
                self._chunk(b"")
            except OSError:
                self.server.dripped.set()
                self.close_connection = True
        elif path == "/redirect-307":
            self._redirect(307)
        elif path == "/redirect-cookie":
            self._redirect(302, [("Set-Cookie", "hop=1; Path=/")])
        else:
            self.send_response(204)
            self.end_headers()

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch
    do_PATCH = _dispatch
    do_HEAD = _dispatch


# The body of /gzip and /br, as it is before compression.
GZIP_TEXT = b"koon decodes this body once. " * 200
# GZIP_TEXT compressed with brotli (the standard library has no brotli).
BR_BODY = base64.b64decode("G6cWAARacqQBpdJHv3UpCA63lVX2YboG00i+yAFALLUA")


@pytest.fixture(scope="session")
def adapter_server():
    """The adapter test server: `.url`, `.gate`, which releases the rest of
    /gated, and `.dripped`, set when a client drops /drip."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), AdapterHandler)
    server.daemon_threads = True
    server.gate = threading.Event()
    server.dripped = threading.Event()
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.gate.set()
        server.shutdown()
        server.server_close()


class ForwardProxyHandler(http.server.BaseHTTPRequestHandler):
    """A forward proxy for http:// URLs: it answers the absolute-form
    request itself and records the request line."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.lines.append(f"{self.command} {self.path}")
        body = b"proxied"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - matches base signature
        pass


@pytest.fixture
def forward_proxy():
    """A local forward proxy: `.url`, and `.lines`, the request lines it got."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ForwardProxyHandler)
    server.daemon_threads = True
    server.lines = []
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


class TlsOriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"secure"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - matches base signature
        pass


@pytest.fixture(scope="module")
def tls_origin(tmp_path_factory):
    """An https:// origin with a self-signed certificate, which koon
    rejects unless certificate checks are off. Yields its URL."""
    from test_https_proxy import PROXY_CERT, PROXY_KEY

    directory = tmp_path_factory.mktemp("origin-cert")
    (directory / "cert.pem").write_text(PROXY_CERT)
    (directory / "key.pem").write_text(PROXY_KEY)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TlsOriginHandler)
    # A failed handshake raises an OSError in accept, which the server ignores.
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def dropped(server):
    """Whether the client dropped /drip within 3 s: the stream was released."""
    return server.dripped.wait(3)


def free_port():
    """A local port nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _ws_frame(opcode, payload):
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, length)
    else:
        header = struct.pack("!BBH", 0x80 | opcode, 126, length)
    return header + payload


def _ws_echo(conn):
    """Minimal RFC 6455 server side: handshake, then echo text and binary
    frames back and answer a close frame. Enough to test the binding."""
    with conn, conn.makefile("rb") as f:
        key = None
        while (line := f.readline()) not in (b"\r\n", b""):
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"sec-websocket-key":
                key = value.strip()
        accept = base64.b64encode(
            hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        )
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        while len(head := f.read(2)) == 2:
            opcode, length = head[0] & 0x0F, head[1] & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", f.read(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", f.read(8))
            mask = f.read(4) if head[1] & 0x80 else b"\0\0\0\0"
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(f.read(length)))
            conn.sendall(_ws_frame(opcode, payload))
            if opcode == 0x8:
                return


@pytest.fixture(scope="session")
def ws_url():
    server = socket.create_server(("127.0.0.1", 0))

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=_ws_echo, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield f"ws://127.0.0.1:{server.getsockname()[1]}/"
    finally:
        server.close()
