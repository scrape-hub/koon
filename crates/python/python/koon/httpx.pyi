"""httpx transports that send requests through koon (``pip install koon[httpx]``).

    import httpx
    from koon.httpx import KoonTransport

    with httpx.Client(transport=KoonTransport("chrome")) as client:
        r = client.get("https://example.com")

httpx keeps its part and koon sends each request with the browser's TLS,
HTTP/2 and header fingerprint:

- Headers: httpx's own defaults (``User-Agent: python-httpx/…``,
  ``Accept: */*``, ``Accept-Encoding``, ``Connection: keep-alive``) are
  dropped by name and value, so the browser's go out, in the browser's
  order. Any other header (the client's ``headers=``, the request's,
  ``Cookie`` from the cookie jar, ``Authorization`` from ``auth=``,
  ``Content-Type``) is the caller's: it replaces the browser's header of the
  same name in place, or goes where the browser puts it. A default set to
  another value, e.g. your own User-Agent, is sent. koon sends Host,
  Content-Length and Transfer-Encoding itself; a Host other than the URL's
  raises ValueError. A plain GET looks like a navigation, as with koon's
  own ``get()``; an ``Accept`` without ``text/html`` or a ``Content-Type``
  makes it a fetch().
- Redirects and cookies: httpx follows redirects and keeps cookies (its
  cookie jar); the koon client does neither, so ``client.cookies`` is the
  only jar and each redirect comes back to httpx.
- Bodies: request bodies are read into memory and sent with their length.
  An upload of ``files=`` is encoded again as the profile's browser encodes
  multipart/form-data (its boundary, its escaping of names and filenames;
  a file keeps its Content-Type, other part headers are dropped); a
  multipart body with a boundary you chose in Content-Type is sent as it
  is. koon decodes the response body (gzip, deflate, br, zstd); the
  response then has no Content-Encoding and Content-Length, so httpx does
  not decode it again. ``client.stream()`` reads the body from koon as it
  arrives, and closing the response (leaving the ``with`` block) drops
  the rest of it at once.
- Timeouts: koon has one timeout, until the response head arrives and then
  for each wait for body data. It gets the longest of httpx's connect, read
  and write timeouts; a None among them means no timeout. A timeout raises
  ``httpx.ReadTimeout``.
- Proxy: pass it to the transport (``proxy=``, ``proxies=``); a proxy given
  to ``httpx.Client(proxy=...)`` is served by httpx's own transport and
  loses the fingerprint. ``mounts=`` works as with any transport.
- Errors are httpx's (``ConnectError``, ``ReadTimeout``, ``ProxyError``,
  ``RemoteProtocolError``, ...), with the ``KoonError`` as ``__cause__``.
"""

from typing import Any

import httpx

from koon import Koon, KoonSync

class KoonTransport(httpx.BaseTransport):
    """An ``httpx.Client`` transport that sends requests through koon."""

    def __init__(self, browser: str = "chrome", *, verify: bool = True, **client_options: Any) -> None:
        """Create the transport and its ``KoonSync`` client.

        Args:
            browser: Browser profile to impersonate (see ``koon.browsers()``).
            verify: ``False`` skips certificate verification of origins
                (koon's ``ignore_tls_errors``). An ``SSLContext`` or a CA
                bundle raises TypeError: koon verifies against its own roots.
            **client_options: Options of ``KoonSync`` (``proxy``, ``proxies``,
                ``headers``, ``retries``, ``locale``, ``resolve``, ...).
                ``follow_redirects``, ``max_redirects``, ``on_redirect``,
                ``cookie_jar``, ``timeout`` and ``ignore_tls_errors`` belong to
                httpx, and httpx transport options koon has no counterpart
                for (``http2``, ``limits``, ``cert``, ...) raise TypeError.
        """
        ...
    @property
    def client(self) -> KoonSync:
        """The koon client that sends the requests (``user_agent``, byte
        counters, ``save_session()`` for its TLS sessions, ...)."""
        ...
    def handle_request(self, request: httpx.Request) -> httpx.Response: ...
    def close(self) -> None:
        """Shut the koon client down (``KoonSync.shutdown()``); httpx calls
        it when the client closes."""
        ...

class AsyncKoonTransport(httpx.AsyncBaseTransport):
    """An ``httpx.AsyncClient`` transport that sends requests through koon
    (asyncio only). Options as for ``KoonTransport``."""

    def __init__(self, browser: str = "chrome", *, verify: bool = True, **client_options: Any) -> None: ...
    @property
    def client(self) -> Koon:
        """The koon client that sends the requests."""
        ...
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response: ...
    async def aclose(self) -> None:
        """Shut the koon client down (``Koon.shutdown()``)."""
        ...
