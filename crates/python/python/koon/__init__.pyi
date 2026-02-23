from typing import Any, AsyncIterator, Callable, Optional, Sequence, Tuple, Union

class Koon:
    """Browser impersonation HTTP client with TLS/HTTP2 fingerprint spoofing."""

    def __init__(
        self,
        browser: str = "chrome",
        *,
        profile_json: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = 30000,
        ignore_tls_errors: bool = False,
        headers: Optional[dict[str, str]] = None,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        cookie_jar: bool = True,
        randomize: bool = False,
        session_resumption: bool = True,
        doh: Optional[str] = None,
        local_address: Optional[str] = None,
        on_request: Optional[Callable[[str, str], None]] = None,
        on_response: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], None]] = None,
        on_redirect: Optional[Callable[[int, str, Sequence[Tuple[str, str]]], bool]] = None,
        retries: int = 0,
        locale: Optional[str] = None,
    ) -> None:
        """Create a new Koon HTTP client with browser fingerprint impersonation.

        Args:
            browser: Browser to impersonate (e.g. "chrome", "firefox147", "safari18.3").
            profile_json: Custom browser profile as JSON string (overrides ``browser``).
            proxy: Proxy URL (``http://``, ``https://``, ``socks5://``).
            timeout: Request timeout in milliseconds.
            ignore_tls_errors: Skip TLS certificate verification.
            headers: Additional headers as ``{name: value}`` dict.
            follow_redirects: Automatically follow HTTP redirects.
            max_redirects: Maximum number of redirects to follow.
            cookie_jar: Enable automatic cookie storage.
            randomize: Randomize UA build number, accept-language q-values, and H2 window sizes.
            session_resumption: Enable TLS session resumption.
            doh: DNS-over-HTTPS provider (``"cloudflare"`` or ``"google"``).
            local_address: Bind outgoing connections to a specific local IP address.
            on_request: Observe-only hook called before each HTTP request (including redirects). Receives (method, url).
            on_response: Observe-only hook called after each HTTP response (including redirects). Receives (status, url, headers).
            on_redirect: Hook called before following a redirect. Receives (status, url, headers). Return False to stop redirecting.
            retries: Number of automatic retries on transport errors. With proxy rotation, each retry uses the next proxy.
            locale: Locale for Accept-Language header generation (e.g. ``"fr-FR"``, ``"de"``).
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
    async def get(self, url: str) -> KoonResponse:
        """Perform an HTTP GET request."""
        ...
    async def post(self, url: str, body: Optional[Union[str, bytes]] = None) -> KoonResponse:
        """Perform an HTTP POST request."""
        ...
    async def put(self, url: str, body: Optional[Union[str, bytes]] = None) -> KoonResponse:
        """Perform an HTTP PUT request."""
        ...
    async def delete(self, url: str) -> KoonResponse:
        """Perform an HTTP DELETE request."""
        ...
    async def patch(self, url: str, body: Optional[Union[str, bytes]] = None) -> KoonResponse:
        """Perform an HTTP PATCH request."""
        ...
    async def head(self, url: str) -> KoonResponse:
        """Perform an HTTP HEAD request."""
        ...
    async def request(
        self, method: str, url: str, body: Optional[Union[str, bytes]] = None
    ) -> KoonResponse:
        """Perform an HTTP request with a custom method."""
        ...
    async def post_multipart(
        self, url: str, fields: list[dict[str, Any]]
    ) -> KoonResponse:
        """Perform an HTTP POST request with multipart/form-data body.

        Each field is a dict with ``name`` (required), plus either ``value`` (text)
        or ``file_data`` (bytes) + optional ``filename`` and ``content_type``.
        """
        ...
    async def request_streaming(
        self, method: str, url: str, body: Optional[bytes] = None
    ) -> KoonStreamingResponse:
        """Perform a streaming HTTP request. Does NOT follow redirects."""
        ...
    async def websocket(
        self, url: str, headers: Optional[dict[str, str]] = None
    ) -> KoonWebSocket:
        """Open a WebSocket connection to a wss:// URL."""
        ...

class KoonResponse:
    """HTTP response from a koon request."""

    @property
    def status(self) -> int:
        """HTTP status code (e.g. 200, 404)."""
        ...
    @property
    def headers(self) -> list[tuple[str, str]]:
        """Response headers as a list of (name, value) tuples."""
        ...
    @property
    def body(self) -> bytes:
        """Response body as bytes."""
        ...
    @property
    def text(self) -> str:
        """Response body decoded as UTF-8 text."""
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
    def json(self) -> object:
        """Parse response body as JSON (delegates to ``json.loads``)."""
        ...

class KoonStreamingResponse:
    """A streaming HTTP response that delivers the body in chunks."""

    @property
    def status(self) -> int:
        """HTTP status code (e.g. 200, 404)."""
        ...
    @property
    def headers(self) -> list[tuple[str, str]]:
        """Response headers as a list of (name, value) tuples."""
        ...
    @property
    def version(self) -> str:
        """HTTP version used (e.g. "h2", "HTTP/1.1", "h3")."""
        ...
    @property
    def url(self) -> str:
        """The request URL."""
        ...
    @property
    def bytes_sent(self) -> int:
        """Approximate bytes sent for this request."""
        ...
    @property
    def bytes_received(self) -> int:
        """Approximate bytes received so far (headers + body chunks consumed)."""
        ...
    async def next_chunk(self) -> Optional[bytes]:
        """Get the next body chunk. Returns None when the body is complete."""
        ...
    async def collect(self) -> bytes:
        """Collect the entire remaining body into bytes."""
        ...
    def __aiter__(self) -> AsyncIterator[bytes]:
        """Support ``async for chunk in response:``."""
        ...
    async def __anext__(self) -> bytes:
        """Async iterator next — returns bytes or raises StopAsyncIteration."""
        ...

class KoonWebSocket:
    """A WebSocket connection with browser-fingerprinted TLS."""

    async def send(self, data: Union[str, bytes]) -> None:
        """Send a text (str) or binary (bytes) message."""
        ...
    async def receive(self) -> Optional[dict[str, Union[str, bytes]]]:
        """Receive the next message. Returns dict with 'type' and 'data', or None if closed."""
        ...
    async def close(
        self, code: Optional[int] = None, reason: Optional[str] = None
    ) -> None:
        """Close the WebSocket connection."""
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
        timeout: int = 30000,
        randomize: bool = False,
    ) -> "KoonProxy":
        """Start a new MITM proxy server.

        Args:
            browser: Browser to impersonate (e.g. "chrome", "firefox147").
            profile_json: Custom browser profile as JSON string (overrides ``browser``).
            listen_addr: Address to listen on (default: "127.0.0.1:0" for random port).
            header_mode: Header mode — "impersonate" (default) or "passthrough".
            ca_dir: Directory for CA certificate storage.
            timeout: Request timeout in milliseconds.
            randomize: Randomize fingerprint details.
        """
        ...
    def ca_cert_pem(self) -> bytes:
        """CA certificate as PEM bytes."""
        ...
    async def shutdown(self) -> None:
        """Shut down the proxy server."""
        ...

class KoonError(RuntimeError):
    """Structured error from koon with machine-readable error code prefix.

    Error codes: TLS_ERROR, HTTP2_ERROR, QUIC_ERROR, HTTP3_ERROR, IO_ERROR,
    INVALID_URL, PROXY_ERROR, INVALID_HEADER, CONNECTION_FAILED, JSON_ERROR,
    WEBSOCKET_ERROR, DNS_ERROR, TIMEOUT, TOO_MANY_REDIRECTS.

    The message format is ``[CODE] description``, e.g. ``[TIMEOUT] Request timed out``.
    """
    ...
