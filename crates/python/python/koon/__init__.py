"""koon: an HTTP client that impersonates browsers (TLS, HTTP/2, HTTP/3).

``Koon`` (async) and ``KoonSync`` (blocking) share the native ``_Client``;
their verbs only choose the method and how the call returns. The full API is
documented in ``__init__.pyi``.
"""

import json as _json

from koon._native import (
    KoonError,
    KoonProxy,
    KoonResponse,
    KoonStreamingResponse,
    KoonSyncStreamingResponse,
    KoonWebSocket,
    _Client,
    _Mode,
    _verify,
    browsers,
)

__all__ = [
    "Koon",
    "KoonSync",
    "KoonResponse",
    "KoonStreamingResponse",
    "KoonSyncStreamingResponse",
    "KoonWebSocket",
    "KoonProxy",
    "KoonError",
    "KoonInvalidArgument",
    "browsers",
    "verify",
]


class KoonInvalidArgument(KoonError, ValueError):
    """An invalid argument value: a ``KoonError`` with code
    ``INVALID_ARGUMENT`` that is also a ``ValueError``."""


def verify(browser="chrome", proxy=None):
    """Check that koon still produces the real browser's fingerprint for the
    profile ``browser``; returns the report as a dict (blocking)."""
    return _json.loads(_verify(browser, proxy))


# The verbs forward their keyword arguments to `_request`, whose
# mode/method/url/body/form are positional-only: passing one of those, or
# anything else that is not a request option, by keyword is a TypeError.


class Koon(_Client):
    """Async HTTP client with browser fingerprint impersonation.

    Hooks (``on_request``, ``on_response``, ``on_redirect``) run on a tokio
    worker thread, not on the thread of the asyncio event loop.
    """

    __slots__ = ()

    async def get(self, url, **options):
        """Perform an HTTP GET request."""
        return await self._request(_Mode.Await, "GET", url, **options)

    async def post(self, url, body=None, **options):
        """Perform an HTTP POST request."""
        return await self._request(_Mode.Await, "POST", url, body, **options)

    async def put(self, url, body=None, **options):
        """Perform an HTTP PUT request."""
        return await self._request(_Mode.Await, "PUT", url, body, **options)

    async def delete(self, url, **options):
        """Perform an HTTP DELETE request."""
        return await self._request(_Mode.Await, "DELETE", url, **options)

    async def patch(self, url, body=None, **options):
        """Perform an HTTP PATCH request."""
        return await self._request(_Mode.Await, "PATCH", url, body, **options)

    async def head(self, url, **options):
        """Perform an HTTP HEAD request."""
        return await self._request(_Mode.Await, "HEAD", url, **options)

    async def request(self, method, url, body=None, **options):
        """Perform an HTTP request with any method (lowercase is uppercased)."""
        return await self._request(_Mode.Await, method, url, body, **options)

    async def post_multipart(self, url, fields, **options):
        """Perform an HTTP POST request with a multipart/form-data body."""
        return await self._request(_Mode.Await, "POST", url, None, fields, **options)

    async def request_streaming(self, method, url, body=None, *, decode=True, **options):
        """Perform an HTTP request and return a KoonStreamingResponse; its
        body is decoded (Content-Encoding) unless ``decode=False``."""
        response = await self._request(_Mode.Stream, method, url, body, **options)
        if decode:
            response._decode_content()
        return response

    async def websocket(self, url, headers=None):
        """Open a WebSocket connection to a ws:// or wss:// URL."""
        return await self._websocket(url, headers)

    async def shutdown(self):
        """Shut the client down as a browser does, e.g. before the program
        exits: every HTTP/3 connection ends at once with the browser's close,
        and the call returns once the closes have been sent (at most 300 ms)."""
        await self._shutdown(_Mode.Await)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Leaving ``async with`` shuts the client down (``shutdown()``)."""
        await self.shutdown()


class KoonSync(_Client):
    """Blocking HTTP client with browser fingerprint impersonation.

    Blocks on koon's own runtime with the GIL released, so it is safe to use
    from many threads at once and from inside a running asyncio event loop
    (e.g. Jupyter). Ctrl+C interrupts a request.
    """

    __slots__ = ()

    def get(self, url, **options):
        """Perform a blocking HTTP GET request."""
        return self._request(_Mode.Block, "GET", url, **options)

    def post(self, url, body=None, **options):
        """Perform a blocking HTTP POST request."""
        return self._request(_Mode.Block, "POST", url, body, **options)

    def put(self, url, body=None, **options):
        """Perform a blocking HTTP PUT request."""
        return self._request(_Mode.Block, "PUT", url, body, **options)

    def delete(self, url, **options):
        """Perform a blocking HTTP DELETE request."""
        return self._request(_Mode.Block, "DELETE", url, **options)

    def patch(self, url, body=None, **options):
        """Perform a blocking HTTP PATCH request."""
        return self._request(_Mode.Block, "PATCH", url, body, **options)

    def head(self, url, **options):
        """Perform a blocking HTTP HEAD request."""
        return self._request(_Mode.Block, "HEAD", url, **options)

    def request(self, method, url, body=None, **options):
        """Perform a blocking HTTP request with any method (lowercase is uppercased)."""
        return self._request(_Mode.Block, method, url, body, **options)

    def post_multipart(self, url, fields, **options):
        """Perform a blocking HTTP POST request with a multipart/form-data body."""
        return self._request(_Mode.Block, "POST", url, None, fields, **options)

    def request_streaming(self, method, url, body=None, *, decode=True, **options):
        """Perform a blocking HTTP request and return a
        KoonSyncStreamingResponse once the response head has arrived; its body
        is decoded (Content-Encoding) unless ``decode=False``."""
        response = self._request(_Mode.BlockStream, method, url, body, **options)
        if decode:
            response._decode_content()
        return response

    def shutdown(self):
        """Shut the client down as a browser does, e.g. before the program
        exits: every HTTP/3 connection ends at once with the browser's close,
        and the call returns once the closes have been sent (at most 300 ms)."""
        self._shutdown(_Mode.Block)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Leaving ``with`` shuts the client down (``shutdown()``)."""
        self.shutdown()
