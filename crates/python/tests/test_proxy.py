"""Tests for `KoonProxy` against local servers: its certificates under
strict verification and the options of its upstream client."""

import asyncio
import base64
import socket
import ssl
import threading

import pytest

from koon import KoonError, KoonProxy


def run(coro):
    return asyncio.run(coro)


def read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def test_certificates_pass_strict_verification(tmp_path):
    """Python 3.13+ verifies with VERIFY_X509_STRICT by default (httpx,
    aiohttp use that context): it rejects a CA without a
    subjectKeyIdentifier and a leaf without an authorityKeyIdentifier."""

    def handshake(port, ca_pem):
        context = ssl.create_default_context(cadata=ca_pem)
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            assert read_head(sock).startswith(b"HTTP/1.1 200")
            with context.wrap_socket(sock, server_hostname="example.com") as tls:
                return tls.getpeercert()

    async def go():
        proxy = await KoonProxy.start(ca_dir=str(tmp_path))
        try:
            ca_pem = proxy.ca_cert_pem().decode()
            return await asyncio.to_thread(handshake, proxy.port, ca_pem)
        finally:
            await proxy.shutdown()

    cert = run(go())
    assert ("DNS", "example.com") in cert["subjectAltName"]


def test_upstream_client_takes_the_connection_options(tmp_path):
    """The forwarded requests connect as a client with the same options
    would: here through an upstream proxy, with a locale."""
    listener = socket.create_server(("127.0.0.1", 0))
    seen = {}

    def upstream():
        # Answers the request in absolute form itself, as a forward proxy
        # does for http:// URLs.
        conn, _ = listener.accept()
        with conn:
            seen["head"] = read_head(conn).decode("latin-1")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    threading.Thread(target=upstream, daemon=True).start()

    def request(port):
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(
                b"GET http://example.test/through HTTP/1.1\r\nHost: example.test\r\n"
                b"Accept-Language: en-GB\r\nConnection: close\r\n\r\n"
            )
            return b"".join(iter(lambda: sock.recv(4096), b""))

    async def go():
        proxy = await KoonProxy.start(
            ca_dir=str(tmp_path),
            proxy=f"http://127.0.0.1:{listener.getsockname()[1]}",
            locale="de-DE",
            retries=1,
        )
        try:
            return await asyncio.to_thread(request, proxy.port)
        finally:
            await proxy.shutdown()

    try:
        response = run(go())
    finally:
        listener.close()
    assert response.startswith(b"HTTP/1.1 200")
    assert response.endswith(b"ok")
    head = seen["head"].lower()
    assert head.startswith("get http://example.test/through http/1.1\r\n"), head
    assert "\r\naccept-language: de-de,de;q=0.9," in head, head
    assert "en-gb" not in head


def test_non_loopback_listen_addr_is_refused_by_default_but_can_be_allowed(tmp_path):
    # 192.0.2.1 (TEST-NET-1) is no address of this machine: without the opt-in the
    # refusal comes before any bind, with it the bind itself fails. Nothing listens
    # on a reachable interface.
    async def start(allow_non_loopback):
        await KoonProxy.start(
            ca_dir=str(tmp_path),
            listen_addr="192.0.2.1:0",
            allow_non_loopback=allow_non_loopback,
        )

    with pytest.raises(KoonError) as exc_info:
        run(start(False))
    assert exc_info.value.code == "PROXY_ERROR"
    assert "loopback" in str(exc_info.value).lower()

    with pytest.raises(KoonError) as exc_info:
        run(start(True))
    assert exc_info.value.code == "IO_ERROR"


def test_auth_requires_proxy_authorization(tmp_path):
    # No upstream `proxy=` configured: the koon proxy forwards absolute-form
    # requests directly to their target, here the `origin` listener itself.
    origin = socket.create_server(("127.0.0.1", 0))
    origin_port = origin.getsockname()[1]

    def serve_one():
        conn, _ = origin.accept()
        with conn:
            read_head(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def request(port, headers=b""):
        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.sendall(
                f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n".encode()
                + f"Host: 127.0.0.1:{origin_port}\r\n".encode()
                + headers
                + b"Connection: close\r\n\r\n"
            )
            return read_head(sock)

    def basic(user, password):
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return f"Proxy-Authorization: Basic {token}\r\n".encode()

    async def go():
        proxy = await KoonProxy.start(
            ca_dir=str(tmp_path), auth=("user", "pass"), max_connections=5
        )
        try:
            no_creds = await asyncio.to_thread(request, proxy.port)
            wrong_creds = await asyncio.to_thread(
                request, proxy.port, basic("user", "wrong")
            )
            threading.Thread(target=serve_one, daemon=True).start()
            correct_creds = await asyncio.to_thread(
                request, proxy.port, basic("user", "pass")
            )
            return no_creds, wrong_creds, correct_creds
        finally:
            await proxy.shutdown()

    try:
        no_creds, wrong_creds, correct_creds = run(go())
    finally:
        origin.close()
    assert no_creds.startswith(b"HTTP/1.1 407")
    assert wrong_creds.startswith(b"HTTP/1.1 407")
    assert correct_creds.startswith(b"HTTP/1.1 200")
