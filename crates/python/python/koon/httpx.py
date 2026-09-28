"""httpx transports that send requests through koon.

    import httpx
    from koon.httpx import KoonTransport

    with httpx.Client(transport=KoonTransport("chrome")) as client:
        r = client.get("https://example.com")

``AsyncKoonTransport`` is the same for ``httpx.AsyncClient`` (asyncio).
httpx keeps its part (redirects, cookies, auth, event hooks, timeouts), and
koon sends every request with the browser's TLS, HTTP/2 and header
fingerprint. The full rules are in ``httpx.pyi``.
"""

from __future__ import annotations

try:
    import httpx
except ImportError as e:  # pragma: no cover - depends on the environment
    raise ImportError("koon.httpx needs httpx: pip install koon[httpx]") from e

from koon import Koon, KoonError, KoonSync
from koon._adapter import (
    browser_multipart,
    caller_headers,
    http_version,
    response_headers,
    unescape_httpx,
)
from koon._adapter import client_options as _client_options

__all__ = ["KoonTransport", "AsyncKoonTransport"]

# Options of httpx's own HTTPTransport that koon has no counterpart for.
_UNSUPPORTED = {
    "cert": "client certificates are not supported",
    "http1": "koon picks HTTP/1.1, HTTP/2 or HTTP/3 as the browser does",
    "http2": "koon picks HTTP/1.1, HTTP/2 or HTTP/3 as the browser does",
    "limits": "koon pools connections as the browser does",
    "uds": "Unix domain sockets are not supported",
    "socket_options": "socket options are not supported",
    "trust_env": "pass the proxy with proxy=",
}


def _default_headers() -> dict[str, str]:
    """The headers every httpx client starts with (User-Agent python-httpx,
    Accept, Accept-Encoding, Connection), lowercase name to value."""
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as c:
        return dict(c.headers.items())


_DEFAULT_HEADERS = _default_headers()


def _options(verify: bool, options: dict) -> dict:
    if verify is not True and verify is not False:
        raise TypeError(
            "verify must be True or False: koon verifies certificates against its "
            "own roots (Mozilla's and the Chrome Root Store); an SSLContext or a CA "
            "bundle is not supported"
        )
    options = _client_options("httpx", options, _UNSUPPORTED)
    if not verify:
        options["ignore_tls_errors"] = True
    return options


def _timeout(request: httpx.Request) -> float | None:
    """koon has one timeout: until the response head arrives, then for each
    wait for body data. It gets the longest of httpx's connect, read and
    write timeouts; if one of them is None, there is none (0)."""
    timeouts = request.extensions.get("timeout")
    if not timeouts:
        return None  # the koon client's timeout
    values = [timeouts.get(phase) for phase in ("connect", "read", "write")]
    return 0.0 if None in values else max(values)


def _request_args(client, request: httpx.Request, body: bytes) -> tuple:
    """The body and the options of koon's request for ``request``."""
    url = str(request.url)
    encoding = request.headers.encoding
    headers = caller_headers(
        ((name.decode(encoding), value.decode(encoding)) for name, value in request.headers.raw),
        _DEFAULT_HEADERS,
        url,
    )
    headers, body = browser_multipart(headers, body or None, client._encode_multipart, unescape_httpx)
    return body, {"headers": headers, "timeout": _timeout(request)}


def _error(err: KoonError, request: httpx.Request, reading: bool = False):
    """The httpx exception for a koon error, or None to raise it as is (an
    invalid argument)."""
    code = err.code
    if code == "INVALID_ARGUMENT":
        return None
    if code == "TIMEOUT":
        cls = httpx.ReadTimeout
    elif code in ("HTTP2_ERROR", "HTTP3_ERROR", "QUIC_ERROR", "PROTOCOL_ERROR"):
        cls = httpx.RemoteProtocolError
    elif reading:
        cls = httpx.ReadError
    elif code in ("CONNECTION_FAILED", "DNS_ERROR", "TLS_ERROR"):
        cls = httpx.ConnectError
    elif code == "PROXY_ERROR":
        cls = httpx.ProxyError
    elif code == "INVALID_URL":
        cls = httpx.UnsupportedProtocol
    elif code == "INVALID_HEADER":
        cls = httpx.LocalProtocolError
    elif code == "BODY_ERROR":
        cls = httpx.WriteError
    else:
        cls = httpx.ReadError
    return cls(str(err), request=request)


def _response(resp, stream) -> httpx.Response:
    decoded = resp._decode_content()
    headers = [
        (name.encode(), value.encode()) for name, value in response_headers(resp.headers, decoded)
    ]
    return httpx.Response(
        resp.status,
        headers=headers,
        stream=stream,
        extensions={"http_version": http_version(resp.version).encode("ascii")},
    )


class _SyncStream(httpx.SyncByteStream):
    def __init__(self, resp, request: httpx.Request) -> None:
        self._resp = resp
        self._request = request

    def __iter__(self):
        while True:
            try:
                chunk = self._resp.next_chunk()
            except KoonError as err:
                mapped = _error(err, self._request, reading=True)
                if mapped is None:
                    raise
                raise mapped from err
            if chunk is None:
                return
            yield chunk

    def close(self) -> None:
        self._resp.close()


class _AsyncStream(httpx.AsyncByteStream):
    def __init__(self, resp, request: httpx.Request) -> None:
        self._resp = resp
        self._request = request

    async def __aiter__(self):
        while True:
            try:
                chunk = await self._resp.next_chunk()
            except KoonError as err:
                mapped = _error(err, self._request, reading=True)
                if mapped is None:
                    raise
                raise mapped from err
            if chunk is None:
                return
            yield chunk

    async def aclose(self) -> None:
        self._resp.close()


class KoonTransport(httpx.BaseTransport):
    """An ``httpx.Client`` transport that sends requests through koon."""

    def __init__(self, browser: str = "chrome", *, verify: bool = True, **client_options) -> None:
        self._client = KoonSync(browser, **_options(verify, client_options))

    @property
    def client(self) -> KoonSync:
        """The koon client that sends the requests."""
        return self._client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body, options = _request_args(self._client, request, request.read())
        try:
            resp = self._client.request_streaming(
                request.method, str(request.url), body, decode=False, **options
            )
        except KoonError as err:
            mapped = _error(err, request)
            if mapped is None:
                raise
            raise mapped from err
        return _response(resp, _SyncStream(resp, request))

    def close(self) -> None:
        self._client.shutdown()


class AsyncKoonTransport(httpx.AsyncBaseTransport):
    """An ``httpx.AsyncClient`` transport that sends requests through koon
    (asyncio only)."""

    def __init__(self, browser: str = "chrome", *, verify: bool = True, **client_options) -> None:
        self._client = Koon(browser, **_options(verify, client_options))

    @property
    def client(self) -> Koon:
        """The koon client that sends the requests."""
        return self._client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body, options = _request_args(self._client, request, await request.aread())
        try:
            resp = await self._client.request_streaming(
                request.method, str(request.url), body, decode=False, **options
            )
        except KoonError as err:
            mapped = _error(err, request)
            if mapped is None:
                raise
            raise mapped from err
        return _response(resp, _AsyncStream(resp, request))

    async def aclose(self) -> None:
        await self._client.shutdown()
