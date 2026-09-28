from ipaddress import IPv4Address, IPv6Address
from types import TracebackType
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

# `Unpack`/`TypedDict` need `typing_extensions` rather than stdlib `typing`:
# `requires-python` is 3.9, and `Unpack` (PEP 692) only reached `typing` in
# 3.11. Type-checking only; a `.pyi` is never imported at runtime.
from typing_extensions import TypedDict, Unpack

# Headers may be given as any mapping (a dict, httpx.Headers, requests'
# CaseInsensitiveDict, MappingProxyType, ...), read in its iteration order,
# or as a sequence of (name, value) pairs. They are sent in that order. A
# name given more than once is sent once, with the last value, at the
# position of its first occurrence.
HeaderInput = Union[Mapping[str, str], Sequence[Tuple[str, str]]]

# A local IP address to bind to: a string or an ipaddress object.
LocalAddress = Union[str, IPv4Address, IPv6Address]

# A Playwright/CDP-style cookie dict. Recognized keys (others are ignored):
#   name, value: str (required; a missing one raises KoonInvalidArgument)
#   domain: str — a leading dot makes a domain cookie (also sent to
#       subdomains), none a host-only cookie
#   path: str (default "/")
#   url: str — instead of domain/path (not together with either): a host-only
#       cookie for the URL's host, with the URL path up to its last "/" as
#       path, and secure set by the scheme (https)
#   expires: float (unix seconds up to 253402300799; -1 or omitted/None
#       means a session cookie; any other value skips the cookie)
#   httpOnly, secure: bool
#   sameSite: "Strict" | "Lax" | "None" (case-insensitive; default "Lax")
#   hostOnly: bool (overrides what domain/url imply)
#   partitionKey: a cookie whose partitionKey is present and not None is
#       skipped — browsers send partitioned (CHIPS) cookies only in a
#       third-party context, never with top-level requests.
#   partitionKeyOpaque: bool — CDP's flag for an opaque partition key; True
#       skips the cookie like a partitionKey.
# The dicts returned by `cookies()` have name, value, domain (with a leading
# dot for domain cookies), path, expires, httpOnly, secure, sameSite and
# hostOnly, and feed straight back into `set_cookies()`.
CookieDict = Dict[str, Any]

# A cookie `set_cookies()` did not import: {"index": int (its position in
# the list given, 0-based), "name": str, "reason": str}.
SkippedCookie = Dict[str, Any]

class RequestOptions(TypedDict, total=False):
    """Per-request keyword options every verb (``get`` through
    ``request_streaming``) accepts; unset ones fall back to the client's.
    See ``Koon.__init__`` for what each one does."""

    headers: Optional[HeaderInput]
    timeout: Optional[float]
    proxy: Optional[str]
    follow_redirects: Optional[bool]
    max_redirects: Optional[int]
    on_request: Optional[Callable[[str, str], None]]
    on_response: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], None]]
    on_redirect: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], Optional[bool]]]

def browsers() -> List[str]:
    """Every built-in browser profile name, one per profile: every browser
    version on every OS it has a profile for, e.g. ``"chrome154-windows"``,
    ``"safari266-ios"`` or ``"okhttp5"``. Names without a version select the
    latest one (``"chrome-macos"``); without an OS, desktop profiles
    impersonate Windows, Safari macOS (``"firefox154"``)."""
    ...

def verify(browser: str = "chrome", proxy: Optional[str] = None) -> Dict[str, Any]:
    """Check that the installed koon still produces the real browser's
    fingerprint for the profile ``browser`` (blocking).

    Connects to tls.browserleaks.com (tls.peet.ws as fallback) and, where a
    QUIC reference exists, over HTTP/3 to quic.browserleaks.com, and compares
    JA4, JA3N, JA3, the Akamai HTTP/2 fingerprint and the QUIC JA4 with the
    values captured from the real browser. ``proxy`` routes the check through
    a proxy (HTTP/3 is then not used).

    Returns the report: ``profile`` (e.g. ``"chrome154-windows"``),
    ``koon_version``, ``outcome`` (``"match"``, ``"mismatch"``,
    ``"no_reference"`` or ``"unreachable"``), ``references`` (``id``,
    ``source``), ``service``, ``http3_service``, ``fields`` (one dict per
    field: ``field``, ``status`` ``"match"`` with ``value``, ``"mismatch"``
    with ``expected`` and ``actual``, or ``"not_checked"`` with ``reason``
    and the seen ``actual``) and ``errors`` (services that failed:
    ``service``, ``code``, ``message``). An unknown profile raises
    ``KoonInvalidArgument``; unreachable services are part of the report."""
    ...

class Koon:
    """Browser impersonation HTTP client with TLS/HTTP2 fingerprint spoofing.

    Request methods are coroutines. Per-request options override the
    client's for one call; ``timeout`` is in seconds (``0`` = no timeout;
    a negative, NaN or infinite value raises ``KoonInvalidArgument``).

    Hooks (``on_request``, ``on_response``, ``on_redirect``, on the client
    or per request) run on a tokio worker thread, not on the thread of the
    asyncio event loop. An exception a hook raises fails the request: the
    request call raises that very exception, like an httpx event hook. A
    raising ``on_request`` sends nothing; a raising ``on_response`` drops
    the response; a raising ``on_redirect`` does not follow.

    ``async with Koon(...) as client:`` shuts the client down
    (``shutdown()``) when the block is left.
    """

    def __init__(
        self,
        browser: str = "chrome",
        *,
        profile_json: Optional[str] = None,
        proxy: Optional[str] = None,
        proxies: Optional[list[str]] = None,
        timeout: Optional[float] = 30,
        ignore_tls_errors: bool = False,
        proxy_ca_certs: Optional[Union[str, bytes]] = None,
        ignore_proxy_tls_errors: bool = False,
        headers: Optional[HeaderInput] = None,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        cookie_jar: bool = True,
        session_resumption: bool = True,
        doh: Optional[str] = None,
        local_address: Optional[LocalAddress] = None,
        on_request: Optional[Callable[[str, str], None]] = None,
        on_response: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], None]] = None,
        on_redirect: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], Optional[bool]]] = None,
        retries: int = 0,
        locale: Optional[str] = None,
        proxy_headers: Optional[HeaderInput] = None,
        ip_version: Optional[int] = None,
        resolve: Optional[Sequence[str]] = None,
        max_response_body: Optional[int] = None,
        server_padding: Optional[str] = None,
    ) -> None:
        """Create a new Koon HTTP client with browser fingerprint impersonation.

        Invalid option values (an unknown browser or version, ``ip_version``,
        ``doh`` provider, a negative ``timeout``, ``max_redirects`` or
        ``retries``, an invalid ``local_address`` or ``resolve`` entry) raise
        ``KoonInvalidArgument``; a value of the wrong type raises
        ``TypeError``.

        Args:
            browser: Browser to impersonate (e.g. "chrome", "firefox154", "safari266",
                "chrome-mobile152", "safari-mobile266", "firefox-mobile154", "brave",
                "edge-mobile153", "samsung", "opera-mobile", "okhttp5").
            profile_json: Custom browser profile as JSON string (overrides ``browser``).
            proxy: Proxy URL (``http://``, ``https://``, ``socks5://``). An ``https://``
                proxy is reached over TLS and its certificate is verified (see
                ``proxy_ca_certs``).
            proxies: List of proxy URLs for round-robin rotation. Takes priority over ``proxy``.
            timeout: Request timeout in seconds, fractions allowed. ``0`` means no
                timeout; ``None`` keeps the default of 30 seconds.
            ignore_tls_errors: Skip TLS certificate verification of origins. ``https://``
                proxies are still verified (see ``ignore_proxy_tls_errors``).
            proxy_ca_certs: Certificates (PEM, one or more, as ``str`` or ``bytes``)
                trusted for the TLS connection to ``https://`` proxies, in addition to
                the built-in roots, like curl's ``--proxy-cacert``: for a proxy with a
                self-signed certificate or one from a private CA. Origins are still
                verified against the built-in roots only. Invalid PEM raises
                ``KoonInvalidArgument``.
            ignore_proxy_tls_errors: Skip certificate verification of ``https://``
                proxies, like curl's ``--proxy-insecure``. The connection stays
                encrypted, but anyone on the way to the proxy can pose as it and read
                the proxy credentials and the hosts requested. Origins are still
                verified. Prefer ``proxy_ca_certs``.
            headers: Additional headers, as a dict (insertion order) or a list of
                ``(name, value)`` tuples.
            follow_redirects: Automatically follow HTTP redirects.
            max_redirects: Maximum number of redirects to follow.
            cookie_jar: Enable automatic cookie storage.
            session_resumption: Enable TLS session resumption.
            doh: DNS-over-HTTPS provider (``"cloudflare"`` or ``"google"``, any case).
            local_address: Bind outgoing connections to a specific local IP address
                (a string or an ``ipaddress`` object).
            on_request: Hook called before each HTTP request (including redirects).
                Receives (method, url). An exception it raises fails the request
                before it is sent.
            on_response: Hook called after each HTTP response (including redirects).
                Receives (status, url, headers) with headers as a list of (name, value)
                tuples. An exception it raises fails the request.
            on_redirect: Hook called before following a redirect. Receives (status, url, headers).
                Return ``False`` to stop redirecting; any other return value (including
                ``None``) continues. An exception it raises fails the request.
            retries: Number of automatic retries on transport errors. With proxy rotation, each retry uses the next proxy.
            locale: Locale for Accept-Language header generation (e.g. ``"fr-FR"``, ``"de"``).
            proxy_headers: Custom headers for the HTTP CONNECT tunnel request (e.g. session IDs, geo-targeting).
            ip_version: Restrict DNS resolution to IPv4 (4) or IPv6 (6).
            resolve: Entries in curl's ``--resolve`` format,
                ``"host:port:address[,address...]"`` (IPv6 in brackets): requests to
                that host and port connect to the address instead of resolving the
                host; TLS name, Host header and cookies stay the host's.
            max_response_body: Maximum response body size in bytes, decompressed:
                past it, a response fails with ``KoonError`` (code ``BODY_ERROR``)
                instead of growing the buffer further (also covers a compressed body
                that decodes past the cap). Reading a streaming response chunk by
                chunk without decoding it is not capped. ``0`` disables it; ``None``
                keeps the default of 100 MiB.
            server_padding: Pins Chrome/Edge/Opera 151+'s ``PqcBandwidthExperiment``
                server-padding field trial group instead of drawing one when the
                client is built: ``"none"`` (not in the study, like 94% of real
                Chrome) or the bytes of padding the group asks for (e.g.
                ``"6000"``). No effect on a profile that does not run the trial.
                ``None`` keeps drawing one per client.
        """
        ...
    @property
    def user_agent(self) -> Optional[str]:
        """The User-Agent string from the browser profile."""
        ...
    def export_profile(self) -> str:
        """Export the current browser profile as a JSON string."""
        ...
    def save_session(self) -> str:
        """Save the current session (cookies + TLS sessions) as a JSON string."""
        ...
    def load_session(self, json: str) -> None:
        """Load a session (cookies + TLS sessions) from a JSON string."""
        ...
    def save_session_to_file(self, path: str) -> None:
        """Save the current session to a file."""
        ...
    def load_session_from_file(self, path: str) -> None:
        """Load a session from a file."""
        ...
    def total_bytes_sent(self) -> int:
        """Get the total number of bytes sent across all requests."""
        ...
    def total_bytes_received(self) -> int:
        """Get the total number of bytes received across all requests."""
        ...
    def reset_counters(self) -> None:
        """Reset both cumulative byte counters to zero."""
        ...
    def clear_cookies(self) -> None:
        """Clear all cookies from the cookie jar. Keeps TLS sessions and connection pool."""
        ...
    def set_cookies(self, cookies: Sequence[CookieDict]) -> List[SkippedCookie]:
        """Insert or replace cookies from a Playwright/CDP-style list of dicts.

        Every valid cookie is imported. The others (an invalid name, value,
        domain, path or ``expires``, a ``url`` together with ``domain``, a
        partitioned cookie, ...) are skipped and returned as dicts with
        ``index`` (position in ``cookies``, 0-based), ``name`` and
        ``reason``, so one odd cookie does not cost a whole browser export;
        an empty list means all were imported. Raises ``KoonError`` with code
        ``COOKIE_JAR_DISABLED`` for a client created with
        ``cookie_jar=False``, and ``KoonInvalidArgument`` for an element that
        is not a cookie dict (e.g. one without ``name``).
        """
        ...
    def cookies(self) -> List[CookieDict]:
        """Return every cookie currently stored in the jar.

        The result is a list of Playwright/CDP-style dicts that feeds
        straight back into ``set_cookies()``.
        """
        ...
    def close(self) -> None:
        """Close all pooled connections and release resources, without
        waiting. The client can still be used afterward — new connections open
        as needed. Idle HTTP/3 connections end as the browser ends them at
        shutdown; one with a response still being read ends as when the pool
        drops it once the response is done: Chrome-family profiles discard it
        without sending anything, as Chromium does; Firefox profiles close it
        with H3_NO_ERROR. ``shutdown()`` ends everything at once.
        """
        ...
    async def shutdown(self) -> None:
        """Shut the client down as a browser does, e.g. before the program exits.

        Every HTTP/3 connection ends at once with the browser's close, and the
        call returns once the closes have been sent (at most 300 ms), so they
        are not lost when the process exits right after. HTTP/3 responses still
        being read fail, as browsers abort them at shutdown; HTTP/1.1 and HTTP/2
        responses still being read are not affected. The client can still be
        used afterward.
        """
        ...
    async def __aenter__(self) -> "Koon":
        """Support ``async with`` — returns the client."""
        ...
    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Support ``async with`` — shuts the client down (``shutdown()``)."""
        ...
    async def get(
        self, url: str, **options: Unpack[RequestOptions]
    ) -> "KoonResponse":
        """Perform an HTTP GET request."""
        ...
    async def post(
        self,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> "KoonResponse":
        """Perform an HTTP POST request."""
        ...
    async def put(
        self,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> "KoonResponse":
        """Perform an HTTP PUT request."""
        ...
    async def delete(
        self, url: str, **options: Unpack[RequestOptions]
    ) -> "KoonResponse":
        """Perform an HTTP DELETE request."""
        ...
    async def patch(
        self,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> "KoonResponse":
        """Perform an HTTP PATCH request."""
        ...
    async def head(
        self, url: str, **options: Unpack[RequestOptions]
    ) -> "KoonResponse":
        """Perform an HTTP HEAD request."""
        ...
    async def request(
        self,
        method: str,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> "KoonResponse":
        """Perform an HTTP request with a custom method. Lowercase methods are uppercased."""
        ...
    async def post_multipart(
        self,
        url: str,
        fields: list[dict[str, Any]],
        **options: Unpack[RequestOptions],
    ) -> "KoonResponse":
        """Perform an HTTP POST request with multipart/form-data body.

        Each field is a dict with ``name`` (required), plus either ``value`` (text)
        or ``file_data`` (bytes) + optional ``filename`` and ``content_type``.
        A field without them raises ``KoonInvalidArgument``.
        """
        ...
    async def request_streaming(
        self,
        method: str,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        *,
        decode: bool = True,
        **options: Unpack[RequestOptions],
    ) -> "KoonStreamingResponse":
        """Perform a streaming HTTP request.

        The body is decoded as it is read (gzip, deflate, br, zstd; the
        Content-Encoding koon does not know arrives as it is); ``decode=False``
        gives the bytes as sent. The headers stay as received either way,
        Content-Encoding and Content-Length included. Redirects are followed
        the same way as for buffered requests
        (``follow_redirects``/``max_redirects``/``on_redirect`` apply).
        """
        ...
    async def websocket(
        self, url: str, headers: Optional[HeaderInput] = None
    ) -> "KoonWebSocket":
        """Open a WebSocket connection to a ws:// or wss:// URL."""
        ...

class KoonResponse:
    """HTTP response from a koon request."""

    @property
    def status(self) -> int:
        """HTTP status code (e.g. 200, 404)."""
        ...
    @property
    def status_code(self) -> int:
        """Alias for ``status`` (compatibility with requests/httpx conventions)."""
        ...
    @property
    def ok(self) -> bool:
        """Whether the response status is 2xx (success)."""
        ...
    @property
    def headers(self) -> list[tuple[str, str]]:
        """Response headers as a list of (name, value) tuples, in wire order.
        The same list on every access."""
        ...
    @property
    def request_headers(self) -> list[tuple[str, str]]:
        """Headers of the final request as sent, in wire order and casing.
        HTTP/2 and HTTP/3 pseudo-headers come first. The same list on every
        access."""
        ...
    @property
    def body(self) -> bytes:
        """Response body as bytes."""
        ...
    @property
    def content_type(self) -> Optional[str]:
        """Content-Type header value (e.g. "text/html; charset=utf-8"), or None if absent."""
        ...
    @property
    def text(self) -> str:
        """Response body decoded as text, respecting the charset from the Content-Type header."""
        ...
    @property
    def version(self) -> str:
        """HTTP version used (e.g. "h2", "HTTP/1.1", "h3")."""
        ...
    @property
    def url(self) -> str:
        """The final URL after redirects."""
        ...
    @property
    def bytes_sent(self) -> int:
        """Approximate bytes sent for this request (headers + body)."""
        ...
    @property
    def bytes_received(self) -> int:
        """Approximate bytes received for this response (headers + body, pre-decompression)."""
        ...
    @property
    def tls_resumed(self) -> bool:
        """Whether TLS session resumption was used for this connection."""
        ...
    @property
    def connection_reused(self) -> bool:
        """Whether an existing pooled connection was reused."""
        ...
    @property
    def remote_address(self) -> Optional[str]:
        """Remote IP address of the peer (e.g. "1.2.3.4" or "::1"; the proxy when one is used)."""
        ...
    def json(self) -> object:
        """Parse response body as JSON (delegates to ``json.loads``)."""
        ...
    def header(self, name: str) -> Optional[str]:
        """Look up a response header by name (case-insensitive). Returns the first match or None."""
        ...

class KoonStreamingResponse:
    """A streaming HTTP response that delivers the body in chunks, from
    ``Koon.request_streaming()``.

    The body is read from the connection as it is consumed, and decoded
    (Content-Encoding) unless the request asked for ``decode=False``; data
    that does not decode, or a compressed body that is cut off, raises
    ``KoonError`` with code ``IO_ERROR``. ``close()`` (also ``aclose()``, leaving
    ``async with``) drops the rest of it. Breaking out of ``async for``
    does not close the response: use ``async with`` for that.
    """

    @property
    def status(self) -> int:
        """HTTP status code (e.g. 200, 404)."""
        ...
    @property
    def status_code(self) -> int:
        """Alias for ``status`` (compatibility with requests/httpx conventions)."""
        ...
    @property
    def headers(self) -> list[tuple[str, str]]:
        """Response headers as a list of (name, value) tuples, in wire order.
        The same list on every access."""
        ...
    @property
    def request_headers(self) -> list[tuple[str, str]]:
        """Headers of the final request as sent, in wire order and casing.
        The same list on every access."""
        ...
    @property
    def version(self) -> str:
        """HTTP version used (e.g. "h2", "HTTP/1.1", "h3")."""
        ...
    @property
    def url(self) -> str:
        """The final URL after redirects."""
        ...
    @property
    def bytes_sent(self) -> int:
        """Approximate bytes sent for this request."""
        ...
    @property
    def bytes_received(self) -> int:
        """Approximate bytes received so far (headers + body chunks consumed)."""
        ...
    @property
    def tls_resumed(self) -> bool:
        """Whether TLS session resumption was used for this connection."""
        ...
    @property
    def connection_reused(self) -> bool:
        """Whether an existing pooled connection was reused."""
        ...
    @property
    def remote_address(self) -> Optional[str]:
        """Remote IP address of the peer (the proxy when one is used)."""
        ...
    async def next_chunk(self) -> Optional[bytes]:
        """Get the next body chunk. Returns None when the body is complete."""
        ...
    async def collect(self) -> bytes:
        """Collect the entire remaining body into bytes. Consumes the stream:
        reading it again (``collect()``, ``next_chunk()``, ``async for``) raises
        ``KoonError`` with code ``BODY_ERROR``."""
        ...
    def __aiter__(self) -> AsyncIterator[bytes]:
        """Support ``async for chunk in response:``."""
        ...
    async def __anext__(self) -> bytes:
        """Async iterator next — returns bytes or raises StopAsyncIteration."""
        ...
    def close(self) -> None:
        """Drop the rest of the body without reading it: the stream is closed
        (HTTP/1.1) or reset (HTTP/2, HTTP/3) at once. A read still pending and
        every later one raise ``KoonError`` with code ``BODY_ERROR``. Closing
        again does nothing."""
        ...
    async def aclose(self) -> None:
        """``close()`` as a coroutine (``contextlib.aclosing()``)."""
        ...
    async def __aenter__(self) -> "KoonStreamingResponse":
        """Support ``async with await client.request_streaming(...) as r:``."""
        ...
    async def __aexit__(
        self, exc_type: object, exc_val: object, exc_tb: object
    ) -> bool:
        """Support ``async with`` — closes the response (``close()``)."""
        ...

class KoonSyncStreamingResponse:
    """A streaming HTTP response read blocking, from
    ``KoonSync.request_streaming()``: the same as ``KoonStreamingResponse``,
    with blocking reads that release the GIL (Ctrl+C interrupts them).

    ``with client.request_streaming(...) as r:`` closes the response when
    the block is left; ``for chunk in r:`` iterates over the body.
    """

    @property
    def status(self) -> int:
        """HTTP status code (e.g. 200, 404)."""
        ...
    @property
    def status_code(self) -> int:
        """Alias for ``status`` (compatibility with requests/httpx conventions)."""
        ...
    @property
    def headers(self) -> list[tuple[str, str]]:
        """Response headers as a list of (name, value) tuples, in wire order.
        The same list on every access."""
        ...
    @property
    def request_headers(self) -> list[tuple[str, str]]:
        """Headers of the final request as sent, in wire order and casing.
        The same list on every access."""
        ...
    @property
    def version(self) -> str:
        """HTTP version used (e.g. "h2", "HTTP/1.1", "h3")."""
        ...
    @property
    def url(self) -> str:
        """The final URL after redirects."""
        ...
    @property
    def bytes_sent(self) -> int:
        """Approximate bytes sent for this request."""
        ...
    @property
    def bytes_received(self) -> int:
        """Approximate bytes received so far (headers + body chunks consumed)."""
        ...
    @property
    def tls_resumed(self) -> bool:
        """Whether TLS session resumption was used for this connection."""
        ...
    @property
    def connection_reused(self) -> bool:
        """Whether an existing pooled connection was reused."""
        ...
    @property
    def remote_address(self) -> Optional[str]:
        """Remote IP address of the peer (the proxy when one is used)."""
        ...
    def next_chunk(self) -> Optional[bytes]:
        """Get the next body chunk. Returns None when the body is complete."""
        ...
    def collect(self) -> bytes:
        """Collect the entire remaining body into bytes. Consumes the stream:
        reading it again raises ``KoonError`` with code ``BODY_ERROR``."""
        ...
    def __iter__(self) -> Iterator[bytes]:
        """Support ``for chunk in response:``."""
        ...
    def __next__(self) -> bytes:
        """Iterator next — returns bytes or raises StopIteration."""
        ...
    def close(self) -> None:
        """Drop the rest of the body without reading it, as
        ``KoonStreamingResponse.close()`` does."""
        ...
    def __enter__(self) -> "KoonSyncStreamingResponse":
        """Support ``with`` — returns the response."""
        ...
    def __exit__(
        self, exc_type: object, exc_val: object, exc_tb: object
    ) -> bool:
        """Support ``with`` — closes the response (``close()``)."""
        ...

class KoonWebSocket:
    """A WebSocket connection with browser-fingerprinted TLS.

    Send, receive and close can run concurrently — a pending ``receive()``
    never blocks a ``send()``.
    """

    async def send(self, data: Union[str, bytes]) -> None:
        """Send a text (str) or binary (bytes) message."""
        ...
    async def receive(self) -> Optional[dict[str, Union[str, bytes]]]:
        """Receive the next message. Returns dict with 'type' and 'data', or None if closed."""
        ...
    async def close(
        self, code: Optional[int] = None, reason: Optional[str] = None
    ) -> None:
        """Close the WebSocket connection with an optional close code
        (0-65535, else ``KoonInvalidArgument``) and reason."""
        ...
    async def __aenter__(self) -> "KoonWebSocket":
        """Support ``async with`` — returns self."""
        ...
    async def __aexit__(
        self, exc_type: object, exc_val: object, exc_tb: object
    ) -> bool:
        """Support ``async with`` — closes the connection on exit."""
        ...

class KoonProxy:
    """A local MITM proxy server with browser fingerprinting."""

    @property
    def port(self) -> int:
        """The port the proxy server is listening on."""
        ...
    @property
    def url(self) -> str:
        """The proxy URL (e.g. "http://127.0.0.1:8080")."""
        ...
    @property
    def ca_cert_path(self) -> str:
        """Path to the generated CA certificate file."""
        ...
    @staticmethod
    async def start(
        *,
        browser: str = "chrome",
        profile_json: Optional[str] = None,
        listen_addr: Optional[str] = None,
        header_mode: Optional[str] = None,
        ca_dir: Optional[str] = None,
        timeout: Optional[float] = 30,
        allow_non_loopback: bool = False,
        auth: Optional[Tuple[str, str]] = None,
        max_connections: Optional[int] = None,
        proxy: Optional[str] = None,
        proxies: Optional[list[str]] = None,
        ignore_tls_errors: bool = False,
        proxy_ca_certs: Optional[Union[str, bytes]] = None,
        ignore_proxy_tls_errors: bool = False,
        session_resumption: bool = True,
        doh: Optional[str] = None,
        local_address: Optional[LocalAddress] = None,
        retries: int = 0,
        locale: Optional[str] = None,
        proxy_headers: Optional[HeaderInput] = None,
        ip_version: Optional[int] = None,
        resolve: Optional[Sequence[str]] = None,
        max_response_body: Optional[int] = None,
        server_padding: Optional[str] = None,
    ) -> "KoonProxy":
        """Start a new MITM proxy server.

        The forwarded requests connect as a ``Koon`` client with the same
        options would (``proxy`` through ``ip_version`` below, see
        ``Koon.__init__``), e.g. through an upstream (residential) proxy. The
        proxy does not follow redirects and keeps no cookies: the proxied
        client gets each redirect and keeps its own cookies.

        Args:
            browser: Browser to impersonate (e.g. "chrome", "firefox154").
            profile_json: Custom browser profile as JSON string (overrides ``browser``).
            listen_addr: Address to listen on (default: "127.0.0.1:0" for random port).
            header_mode: Header mode — "impersonate" (default) or "passthrough"
                (any case; anything else raises ``KoonInvalidArgument``).
            ca_dir: Directory for CA certificate storage.
            timeout: Timeout in seconds, fractions allowed, for a forwarded
                request's response head and each wait for its body. ``0`` means no
                timeout; ``None`` keeps the default of 30 seconds.
            allow_non_loopback: Allow ``listen_addr`` to bind a non-loopback
                address. Without it, the proxy relays through koon's fingerprinted
                TLS/HTTP2 stack with no transport encryption of its own between it
                and its client, so on a reachable interface it would otherwise be
                an open relay for anyone who can reach the port unless ``auth`` is
                also set.
            auth: ``(username, password)`` required as HTTP Basic
                ``Proxy-Authorization`` from every client.
            max_connections: Connections accepted at once; further ones wait for
                a slot to free up. ``None`` keeps the core's default (512).
            proxy: Upstream proxy URL (``http://``, ``https://``, ``socks5://``).
            proxies: Upstream proxy URLs for round-robin rotation. Take priority over ``proxy``.
            ignore_tls_errors: Skip TLS certificate verification of origins.
            proxy_ca_certs: Certificates trusted for an ``https://`` upstream proxy.
            ignore_proxy_tls_errors: Skip certificate verification of an ``https://`` upstream proxy.
            session_resumption: Enable TLS session resumption to origins.
            doh: DNS-over-HTTPS provider (``"cloudflare"`` or ``"google"``, any case).
            local_address: Bind outgoing connections to a specific local IP address.
            retries: Automatic retries of forwarded requests on transport errors.
            locale: Locale for the Accept-Language header the profile sends
                (e.g. ``"de-DE"``); in impersonate mode the client's own is dropped.
            proxy_headers: Headers for the CONNECT request to the upstream proxy.
            ip_version: Restrict DNS resolution to IPv4 (4) or IPv6 (6).
            resolve: Entries in curl's ``--resolve`` format, see ``Koon.__init__``.
            max_response_body: Maximum forwarded response body size in bytes,
                decompressed, see ``Koon.__init__``.
            server_padding: Pins the forwarded requests' server-padding field
                trial group, see ``Koon.__init__``.
        """
        ...
    def ca_cert_pem(self) -> bytes:
        """CA certificate as PEM bytes."""
        ...
    async def shutdown(self) -> None:
        """Stop accepting and close every open connection. Calling it again
        does nothing."""
        ...

class KoonError(RuntimeError):
    """Structured error from koon with a machine-readable error code.

    Error codes: TLS_ERROR, HTTP2_ERROR, QUIC_ERROR, HTTP3_ERROR, IO_ERROR,
    INVALID_URL, PROXY_ERROR, INVALID_HEADER, BODY_ERROR, CONNECTION_FAILED,
    PROTOCOL_ERROR, JSON_ERROR, WEBSOCKET_ERROR, DNS_ERROR, CONFIG_ERROR,
    TIMEOUT, TOO_MANY_REDIRECTS, COOKIE_JAR_DISABLED, INVALID_COOKIE,
    INVALID_ARGUMENT. BODY_ERROR also covers reading a streaming response
    again after ``collect()``. A hook that raises fails its request with its
    own exception, not a ``KoonError``.

    The message format is ``[CODE] description``, e.g. ``[TIMEOUT] Request timed out``.
    The code is also available directly as ``err.code``. Errors can be
    pickled (e.g. from ``multiprocessing`` workers) and keep their code.
    ``INVALID_ARGUMENT`` is raised as ``KoonInvalidArgument``.
    """

    code: str

class KoonInvalidArgument(KoonError, ValueError):
    """An invalid argument value: a ``KoonError`` with code
    ``INVALID_ARGUMENT`` that is also a ``ValueError``.

    Raised for an unknown browser, version, ``ip_version``, ``doh`` provider,
    HTTP method or proxy ``header_mode``; a negative, NaN or infinite
    ``timeout``; a negative or too large ``max_redirects``, ``retries`` or
    WebSocket close code; an invalid ``local_address`` or ``resolve``
    entry; a cookie dict without ``name`` or ``value``; a multipart field
    without ``name``, or without ``value`` or ``file_data``.
    """

class KoonSync:
    """Synchronous wrapper around the Koon client.

    Implemented natively: it blocks on the shared tokio runtime with the GIL
    released, so it is safe to call from many threads at once, and from
    inside a running asyncio event loop (e.g. Jupyter). Ctrl+C (or a Jupyter
    kernel interrupt) aborts a running request with ``KeyboardInterrupt``.
    Options, hooks and errors work as for ``Koon``; hooks may run on a
    tokio worker thread. ``with KoonSync(...) as client:`` shuts the client
    down (``shutdown()``) when the block is left.

    Usage::

        from koon import KoonSync
        with KoonSync("chrome") as client:
            resp = client.get("https://httpbin.org/get")
            print(resp.status)
    """

    def __init__(
        self,
        browser: str = "chrome",
        *,
        profile_json: Optional[str] = None,
        proxy: Optional[str] = None,
        proxies: Optional[list[str]] = None,
        timeout: Optional[float] = 30,
        ignore_tls_errors: bool = False,
        proxy_ca_certs: Optional[Union[str, bytes]] = None,
        ignore_proxy_tls_errors: bool = False,
        headers: Optional[HeaderInput] = None,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        cookie_jar: bool = True,
        session_resumption: bool = True,
        doh: Optional[str] = None,
        local_address: Optional[LocalAddress] = None,
        on_request: Optional[Callable[[str, str], None]] = None,
        on_response: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], None]] = None,
        on_redirect: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], Optional[bool]]] = None,
        retries: int = 0,
        locale: Optional[str] = None,
        proxy_headers: Optional[HeaderInput] = None,
        ip_version: Optional[int] = None,
        resolve: Optional[Sequence[str]] = None,
        max_response_body: Optional[int] = None,
        server_padding: Optional[str] = None,
    ) -> None: ...
    @property
    def user_agent(self) -> Optional[str]: ...
    def export_profile(self) -> str: ...
    def save_session(self) -> str: ...
    def load_session(self, json: str) -> None: ...
    def save_session_to_file(self, path: str) -> None: ...
    def load_session_from_file(self, path: str) -> None: ...
    def total_bytes_sent(self) -> int: ...
    def total_bytes_received(self) -> int: ...
    def reset_counters(self) -> None: ...
    def clear_cookies(self) -> None: ...
    def set_cookies(self, cookies: Sequence[CookieDict]) -> List[SkippedCookie]:
        """Insert or replace cookies from a Playwright/CDP-style list of dicts;
        returns the skipped ones, as ``Koon.set_cookies()`` does."""
        ...
    def cookies(self) -> List[CookieDict]:
        """Return every cookie currently stored in the jar, as dicts that feed
        straight back into ``set_cookies()``."""
        ...
    def close(self) -> None:
        """Close all pooled connections without waiting, as
        ``Koon.close()`` does. The client can still be used afterward — new
        connections open as needed. ``shutdown()`` ends everything at once."""
        ...
    def shutdown(self) -> None:
        """Shut the client down as a browser does, e.g. before the program exits.

        Every HTTP/3 connection ends at once with the browser's close, and the
        call returns once the closes have been sent (at most 300 ms), so they
        are not lost when the process exits right after. HTTP/3 responses still
        being read fail, as browsers abort them at shutdown; HTTP/1.1 and HTTP/2
        responses still being read are not affected. The client can still be
        used afterward.
        """
        ...
    def __enter__(self) -> "KoonSync":
        """Support ``with`` — returns the client."""
        ...
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Support ``with`` — shuts the client down (``shutdown()``)."""
        ...
    def get(self, url: str, **options: Unpack[RequestOptions]) -> KoonResponse:
        """Perform a blocking HTTP GET request."""
        ...
    def post(
        self,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> KoonResponse:
        """Perform a blocking HTTP POST request."""
        ...
    def put(
        self,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> KoonResponse:
        """Perform a blocking HTTP PUT request."""
        ...
    def delete(self, url: str, **options: Unpack[RequestOptions]) -> KoonResponse:
        """Perform a blocking HTTP DELETE request."""
        ...
    def patch(
        self,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> KoonResponse:
        """Perform a blocking HTTP PATCH request."""
        ...
    def head(self, url: str, **options: Unpack[RequestOptions]) -> KoonResponse:
        """Perform a blocking HTTP HEAD request."""
        ...
    def request(
        self,
        method: str,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        **options: Unpack[RequestOptions],
    ) -> KoonResponse:
        """Perform a blocking HTTP request with a custom method. Lowercase methods are uppercased."""
        ...
    def post_multipart(
        self,
        url: str,
        fields: list[dict[str, Any]],
        **options: Unpack[RequestOptions],
    ) -> KoonResponse:
        """Perform a blocking HTTP POST with multipart/form-data body."""
        ...
    def request_streaming(
        self,
        method: str,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        *,
        decode: bool = True,
        **options: Unpack[RequestOptions],
    ) -> KoonSyncStreamingResponse:
        """Perform a blocking streaming HTTP request: returns once the
        response head has arrived. The body is decoded as for
        ``Koon.request_streaming()`` unless ``decode=False``. Redirects are
        followed as for buffered requests; the timeout covers the response
        head and then each wait for a body chunk."""
        ...
