"""A requests transport adapter that sends requests through koon.

    import requests
    from koon.requests import KoonAdapter

    session = requests.Session()
    adapter = KoonAdapter("chrome")
    session.mount("https://", adapter)
    session.mount("http://", adapter)

``koon.requests.Session("chrome")`` is a ``requests.Session`` with the
adapter mounted. requests keeps its part (redirects, cookies, auth, hooks,
proxies from the environment), and koon sends every request with the
browser's TLS, HTTP/2 and header fingerprint. The full rules are in
``requests.pyi``.
"""

from __future__ import annotations

import http.client
import io
import threading

try:
    import requests
except ImportError as e:  # pragma: no cover - depends on the environment
    raise ImportError("koon.requests needs requests: pip install koon[requests]") from e

from requests import exceptions
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict
from requests.utils import (
    default_headers,
    get_encoding_from_headers,
    prepend_scheme_if_needed,
    select_proxy,
)

from koon import KoonError, KoonSync
from koon._adapter import browser_multipart, caller_headers, response_headers, unescape_urllib3
from koon._adapter import client_options as _client_options

__all__ = ["KoonAdapter", "Session"]

# Options of requests' own HTTPAdapter that koon has no counterpart for.
_UNSUPPORTED = {
    "pool_connections": "koon pools connections as the browser does",
    "pool_maxsize": "koon pools connections as the browser does",
    "pool_block": "koon pools connections as the browser does",
    "max_retries": "use retries= (retries on transport errors)",
}


def _timeout(timeout) -> float:
    """requests' timeout for koon, which has one timeout: until the response
    head arrives, then for each wait for body data. None (requests' default)
    waits forever (0); of a (connect, read) pair the longer counts, and a
    pair with a None waits forever too."""
    if timeout is None:
        return 0.0
    if isinstance(timeout, tuple):
        try:
            connect, read = timeout
        except ValueError:
            raise ValueError(
                f"Invalid timeout {timeout}. Pass a (connect, read) timeout tuple, "
                "or a single float to set both timeouts to the same value."
            ) from None
        return 0.0 if connect is None or read is None else max(connect, read)
    if isinstance(timeout, (int, float)):
        return timeout
    raise ValueError(f"Invalid timeout {timeout!r}: pass a number or a (connect, read) tuple")


def _body(body) -> bytes | None:
    """The prepared body as bytes; koon sends it with its length. A file or
    an iterator (a chunked upload in requests) is read into memory."""
    if body is None:
        return None
    if hasattr(body, "read"):
        body = body.read()
    elif not isinstance(body, (str, bytes, bytearray, memoryview)):
        body = b"".join(c.encode("utf-8") if isinstance(c, str) else bytes(c) for c in body)
    if isinstance(body, str):
        body = body.encode("utf-8")
    return bytes(body) or None


def _error(err: KoonError, request):
    """The requests exception for a koon error before the response head
    arrived, or None to raise it as is (an invalid argument)."""
    cls = {
        "TIMEOUT": exceptions.ReadTimeout,
        "TLS_ERROR": exceptions.SSLError,
        "PROXY_ERROR": exceptions.ProxyError,
        "INVALID_URL": exceptions.InvalidURL,
        "INVALID_HEADER": exceptions.InvalidHeader,
        "INVALID_ARGUMENT": None,
    }.get(err.code, exceptions.ConnectionError)
    return cls and cls(err, request=request)


def _wire_value(value: str) -> str:
    """A header value as http.client (and so urllib3) gives it: the bytes
    as Latin-1. koon decodes them as UTF-8; requests re-decodes a Location
    from Latin-1 to UTF-8 itself."""
    return value.encode("utf-8").decode("latin-1")


class _OriginalResponse:
    """What requests reads Set-Cookie headers from (``raw._original_response.msg``)."""

    def __init__(self, msg: http.client.HTTPMessage) -> None:
        self.msg = msg


class _KoonRaw(io.RawIOBase):
    """``response.raw``: the body read from koon as it arrives, already
    decoded. ``stream()`` is what requests' ``iter_content()`` reads."""

    def __init__(self, resp, request, headers: list[tuple[str, str]]) -> None:
        super().__init__()
        self._resp = resp
        self._request = request
        self._pending = memoryview(b"")
        self._done = False
        self.status = resp.status
        self.reason = http.client.responses.get(resp.status, "")
        self.headers = CaseInsensitiveDict(_joined(headers))
        msg = http.client.HTTPMessage()
        for name, value in headers:
            msg[name] = value  # adds another header, as for Set-Cookie
        self._original_response = _OriginalResponse(msg)

    def _next_chunk(self) -> bytes | None:
        while not self._done:
            try:
                chunk = self._resp.next_chunk()
            except KoonError as err:
                # As requests raises it for urllib3's errors in iter_content().
                cls = exceptions.ConnectionError if err.code == "TIMEOUT" else exceptions.ChunkedEncodingError
                raise cls(err, request=self._request) from err
            if chunk is None:
                self._done = True
                self._resp.close()
            elif chunk:
                return chunk
        return None

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        if not self._pending:
            chunk = self._next_chunk()
            if chunk is None:
                return 0
            self._pending = memoryview(chunk)
        n = min(len(buffer), len(self._pending))
        buffer[:n] = self._pending[:n]
        self._pending = self._pending[n:]
        return n

    def read(self, amt: int | None = None, decode_content: bool | None = None) -> bytes:
        """Up to ``amt`` bytes as soon as some are there, or the rest of the
        body. The body is always decoded; ``decode_content`` is accepted
        for urllib3 compatibility."""
        return super().read(-1 if amt is None else amt)

    def stream(self, amt: int | None = 2**16, decode_content: bool | None = None):
        """The body in pieces of up to ``amt`` bytes, or as it arrives with
        ``amt=None``."""
        while True:
            if amt:
                data = self.read(amt)
            elif self._pending:
                data, self._pending = bytes(self._pending), memoryview(b"")
            else:
                data = self._next_chunk()
            if not data:
                return
            yield data

    def close(self) -> None:
        if not self.closed:
            self._resp.close()
        super().close()


def _joined(headers: list[tuple[str, str]]) -> dict[str, str]:
    """Headers as one value per name, repeated ones joined with ``, ``, as
    urllib3 gives them to requests."""
    joined: dict[str, tuple[str, str]] = {}
    for name, value in headers:
        lower = name.lower()
        if lower in joined:
            first, previous = joined[lower]
            joined[lower] = (first, f"{previous}, {value}")
        else:
            joined[lower] = (name, value)
    return dict(joined.values())


class KoonAdapter(BaseAdapter):
    """A requests transport adapter that sends requests through koon."""

    def __init__(self, browser: str = "chrome", **client_options) -> None:
        super().__init__()
        self._browser = browser
        self._options = _client_options("requests", client_options, _UNSUPPORTED)
        self._verifying = KoonSync(browser, **self._options)
        self._insecure: KoonSync | None = None
        self._lock = threading.Lock()
        self._defaults = {name.lower(): value for name, value in default_headers().items()}

    @property
    def client(self) -> KoonSync:
        """The koon client that sends the requests (with ``verify=True``)."""
        return self._verifying

    def _client(self, verify) -> KoonSync:
        if verify is True:
            return self._verifying
        if verify is False:
            # koon verifies per client: a second one, made when first needed.
            with self._lock:
                if self._insecure is None:
                    self._insecure = KoonSync(self._browser, ignore_tls_errors=True, **self._options)
                return self._insecure
        raise ValueError(
            f"verify={verify!r}: koon verifies certificates against its own roots "
            "(Mozilla's and the Chrome Root Store); a CA bundle is not supported. "
            "Use verify=True or verify=False. (requests takes the bundle from "
            "REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE when one of them is set.)"
        )

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
    ) -> requests.Response:
        """Send a prepared request. ``stream`` needs no handling here: the
        body is always read from koon as the response is read."""
        if cert is not None:
            raise ValueError("cert=: client certificates are not supported by koon")
        client = self._client(verify)
        url = request.url if isinstance(request.url, str) else request.url.decode("utf-8")
        headers = caller_headers(
            ((name, value.decode("latin-1") if isinstance(value, bytes) else value)
             for name, value in request.headers.items()),
            self._defaults,
            url,
        )
        headers, body = browser_multipart(
            headers, _body(request.body), client._encode_multipart, unescape_urllib3
        )
        options = {"headers": headers, "timeout": _timeout(timeout)}
        proxy = select_proxy(url, proxies or {})
        if proxy:
            options["proxy"] = prepend_scheme_if_needed(proxy, "http")
        try:
            resp = client.request_streaming(request.method, url, body, decode=False, **options)
        except KoonError as err:
            mapped = _error(err, request)
            if mapped is None:
                raise
            raise mapped from err
        return self._build_response(request, url, resp)

    def _build_response(self, request, url: str, resp) -> requests.Response:
        decoded = resp._decode_content()
        headers = [(name, _wire_value(value)) for name, value in response_headers(resp.headers, decoded)]
        raw = _KoonRaw(resp, request, headers)
        response = requests.Response()
        response.status_code = resp.status
        response.headers = CaseInsensitiveDict(_joined(headers))
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = raw
        response.reason = raw.reason
        response.url = url
        extract_cookies_to_jar(response.cookies, request, raw)
        response.request = request
        response.connection = self
        return response

    def close(self) -> None:
        """Shut the koon clients down (``KoonSync.shutdown()``)."""
        self._verifying.shutdown()
        if self._insecure is not None:
            self._insecure.shutdown()


class Session(requests.Session):
    """A ``requests.Session`` that sends through koon: a ``KoonAdapter``
    mounted for ``https://`` and ``http://``. Its ``headers`` start empty,
    since the browser's are sent anyway: they hold what the session adds."""

    def __init__(self, browser: str = "chrome", **client_options) -> None:
        super().__init__()
        self.headers.clear()
        adapter = KoonAdapter(browser, **client_options)
        self.mount("https://", adapter)
        self.mount("http://", adapter)
