"""Local HTTP test server for the koon R tests (see helper-server.R).

Serves on 127.0.0.1 at the port given as the first argument (0: a free one)
and prints "listening on PORT" once it accepts connections."""

import json
import struct
import sys
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def png_bytes():
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    raw = b"\x00\xff\x00\x00"  # one red pixel, filter byte 0
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


HITS = {"count": 0}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, status, body, content_type=None, extra=()):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def echo(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = {
            "method": self.command,
            "path": self.path,
            "headers": [[k, v] for k, v in self.headers.items()],
            "body": body.decode("latin-1"),
        }
        self.send(200, json.dumps(payload).encode(), "application/json")

    def route(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        path = url.path
        if path in ("/get", "/post", "/echo"):
            return self.echo()
        if path == "/png":
            return self.send(200, png_bytes(), "image/png")
        if path == "/nul-text":
            return self.send(200, b"a\x00b", "text/plain")
        if path == "/binary-noct":
            return self.send(200, b"\x01\x02\x00\x03")
        if path == "/latin1":
            return self.send(200, "Grüße aus Köln".encode("latin-1"), "text/plain; charset=iso-8859-1")
        if path == "/sjis":
            return self.send(200, "こんにちは".encode("shift_jis"), "text/html; charset=Shift_JIS")
        if path == "/slow":
            time.sleep(float(query.get("s", ["5"])[0]))
            return self.send(200, b"slow done", "text/plain")
        if path.startswith("/redirect/"):
            n = int(path.rsplit("/", 1)[1])
            if n > 0:
                return self.send(302, b"", extra=[("Location", f"/redirect/{n - 1}")])
            return self.send(200, b"arrived", "text/plain")
        if path == "/set-cookie":
            return self.send(
                200,
                b"ok",
                "text/plain",
                extra=[("Set-Cookie", "session=abc123; Path=/; HttpOnly"),
                       ("Set-Cookie", "theme=dark; Path=/; Max-Age=3600")],
            )
        if path == "/cookies":
            return self.send(200, (self.headers.get("Cookie") or "").encode(), "text/plain")
        if path == "/counted":
            HITS["count"] += 1
            return self.send(200, b"counted", "text/plain")
        if path == "/hits":
            return self.send(200, str(HITS["count"]).encode(), "text/plain")
        return self.send(404, b"not found", "text/plain")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = route


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"listening on {server.server_address[1]}", flush=True)
    server.serve_forever()
