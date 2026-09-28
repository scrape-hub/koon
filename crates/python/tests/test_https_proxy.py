"""https:// proxies: the proxy's certificate is verified, `proxy_ca_certs`
and `ignore_proxy_tls_errors` relax that for the proxy only, and a plain
HTTP proxy addressed as https:// gets a hint. Offline: a local TLS proxy
and a local plain HTTP server."""

import http.server
import socket
import ssl
import threading

import pytest

from koon import KoonError, KoonInvalidArgument, KoonSync

# A self-signed certificate for 127.0.0.1 and localhost (P-256, valid until
# 2126) for the local TLS proxy.
PROXY_CERT = """-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUTT+1Q/UeQCoCj9+GTVjktiVQ7NAwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPa29vbiB0ZXN0IHByb3h5MCAXDTI2MDkyMzIxMzAzNFoYDzIx
MjYwODMwMjEzMDM0WjAaMRgwFgYDVQQDDA9rb29uIHRlc3QgcHJveHkwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATPkRI3WI8c7+qaKXL70r52fX/rC1Rk9fVUzAww
YWSHRaT/Wd5KpkYuy8RPNNIt05FR6O0P09zHaeAv3+pyvvswo28wbTAdBgNVHQ4E
FgQUGwZLCfYZbin9FDavBNJSG5DnSbkwHwYDVR0jBBgwFoAUGwZLCfYZbin9FDav
BNJSG5DnSbkwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh
bGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIhALFwL3gr3T3UQeApA+A8k2xyqyaCtcMx
gq52rAWcGvWpAiBDGDHXckJ1xNL33TII0Ff6mUws376mH49GIX3eEQ0Lag==
-----END CERTIFICATE-----
"""
PROXY_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguMLKO1ivNEiVSl0C
Uy7cZMPy8VPlFlhacX4F8dvpAWuhRANCAATPkRI3WI8c7+qaKXL70r52fX/rC1Rk
9fVUzAwwYWSHRaT/Wd5KpkYuy8RPNNIt05FR6O0P09zHaeAv3+pyvvsw
-----END PRIVATE KEY-----
"""


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """koon sends http:// URLs to an HTTP(S) proxy in absolute form: the
    proxy answers them itself and records the request line."""

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


@pytest.fixture(scope="module")
def tls_proxy(tmp_path_factory):
    directory = tmp_path_factory.mktemp("proxy-cert")
    (directory / "cert.pem").write_text(PROXY_CERT)
    (directory / "key.pem").write_text(PROXY_KEY)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / "cert.pem", directory / "key.pem")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    # A failed handshake raises an OSError in accept, which the server ignores.
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.lines = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def proxy_url(server):
    return f"https://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def plain_http_proxy():
    """A plain HTTP server, as an HTTP proxy reacts to a ClientHello: it
    answers the first bytes with 400. Collects what each connection sent."""
    listener = socket.create_server(("127.0.0.1", 0))
    received = []

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                data = conn.recv(16384)
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                try:
                    while chunk := conn.recv(16384):
                        data += chunk
                except OSError:
                    pass
                received.append(data)

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield listener.getsockname()[1], received
    finally:
        listener.close()


def test_untrusted_proxy_certificate_is_rejected(tls_proxy):
    before = len(tls_proxy.lines)
    for client in (
        KoonSync(proxy=proxy_url(tls_proxy)),
        # Skipping origin verification does not cover the proxy.
        KoonSync(proxy=proxy_url(tls_proxy), ignore_tls_errors=True),
    ):
        with pytest.raises(KoonError) as exc_info:
            client.get("http://example.test/")
        assert exc_info.value.code == "PROXY_ERROR"
        assert "TLS to proxy failed" in str(exc_info.value)
    assert len(tls_proxy.lines) == before, "no request reached the proxy"


@pytest.mark.parametrize("pem", [PROXY_CERT, PROXY_CERT.encode()], ids=["str", "bytes"])
def test_proxy_ca_certs_trusts_the_proxy(tls_proxy, pem):
    client = KoonSync(proxy=proxy_url(tls_proxy), proxy_ca_certs=pem)
    resp = client.get("http://example.test/ca")
    assert resp.text == "proxied"
    assert tls_proxy.lines[-1] == "GET http://example.test/ca"


def test_ignore_proxy_tls_errors(tls_proxy):
    client = KoonSync(proxy=proxy_url(tls_proxy), ignore_proxy_tls_errors=True)
    resp = client.get("http://example.test/insecure")
    assert resp.text == "proxied"
    assert tls_proxy.lines[-1] == "GET http://example.test/insecure"


@pytest.mark.parametrize("pem", ["not a certificate", b""])
def test_invalid_proxy_ca_certs_raise(pem):
    with pytest.raises(KoonInvalidArgument):
        KoonSync(proxy_ca_certs=pem)


def test_plain_http_proxy_addressed_as_https_gets_a_hint(plain_http_proxy):
    port, received = plain_http_proxy
    client = KoonSync(proxy=f"https://user:pass@127.0.0.1:{port}")
    with pytest.raises(KoonError) as exc_info:
        client.get("https://example.test/secret")
    assert exc_info.value.code == "PROXY_ERROR"
    assert (
        f"proxy 127.0.0.1:{port} answered in plain HTTP; use http:// instead of https://"
        in str(exc_info.value)
    )
    # Only a ClientHello went out: no CONNECT, no target, no credentials.
    del client
    for _ in range(500):
        if received:
            break
        threading.Event().wait(0.01)
    assert len(received) == 1
    assert received[0][:1] == b"\x16"
    for plain in (b"CONNECT", b"example.test", b"Proxy-Authorization", b"dXNlcjpwYXNz"):
        assert plain not in received[0]
