"""A requests transport adapter that sends requests through koon
(``pip install koon[requests]``).

    from koon.requests import Session

    with Session("chrome") as s:
        r = s.get("https://example.com")

or mount ``KoonAdapter("chrome")`` on a ``requests.Session`` for
``https://`` and ``http://``. requests keeps its part and koon sends each
request with the browser's TLS, HTTP/2 and header fingerprint:

- Headers: requests' own defaults (``requests.utils.default_headers()``:
  ``User-Agent: python-requests/…``, ``Accept: */*``, ``Accept-Encoding``,
  ``Connection: keep-alive``) are dropped by name and value, so the
  browser's go out, in the browser's order. Any other header (the
  session's, the request's, ``Cookie`` from the cookie jar,
  ``Authorization``, ``Content-Type``) is the caller's: it replaces the
  browser's header of the same name in place, or goes where the browser
  puts it. koon sends Host, Content-Length and Transfer-Encoding itself; a
  Host other than the URL's raises ValueError. A plain GET looks like a
  navigation, as with koon's own ``get()``.
- Redirects and cookies: requests follows redirects and keeps cookies (the
  session's jar); the koon client does neither.
- Bodies: request bodies (also files and generators) are read into memory
  and sent with their length. An upload of ``files=`` is encoded again as
  the profile's browser encodes multipart/form-data (its boundary, its
  escaping of names and filenames; a file keeps its Content-Type, other
  part headers are dropped); a multipart body with a boundary you chose in
  Content-Type is sent as it is. koon decodes the response body (gzip,
  deflate, br, zstd); the response then has no Content-Encoding and
  Content-Length. ``stream=True`` reads the body from koon as it arrives
  (``iter_content()``, ``iter_lines()``, ``raw.read()``), and
  ``response.close()`` drops the rest of it at once.
- Timeouts: koon has one timeout, until the response head arrives and then
  for each wait for body data. A number is used as is; of a
  ``(connect, read)`` pair the longer one; ``None`` (requests' default, and
  a None in the pair) waits forever. A timeout raises ``ReadTimeout``
  (``ConnectionError`` while reading the body, as requests does).
- Proxies: requests' proxies (per request, the session's, or from the
  environment) are passed to koon per request, in place of the adapter's
  ``proxy=``.
- ``verify=False`` sends through a second koon client that skips
  certificate verification of origins; a CA bundle path raises ValueError
  (koon verifies against its own roots), and so does ``cert=``.
- Errors are requests' (``ConnectionError``, ``SSLError``, ``ProxyError``,
  ``ReadTimeout``, ``ChunkedEncodingError``, ...), with the ``KoonError`` as
  ``__cause__``.
"""

from typing import Any, Mapping, Optional, Tuple, Union

import requests
from requests.adapters import BaseAdapter

from koon import KoonSync

class KoonAdapter(BaseAdapter):
    """A requests transport adapter that sends requests through koon."""

    def __init__(self, browser: str = "chrome", **client_options: Any) -> None:
        """Create the adapter and its ``KoonSync`` client.

        Args:
            browser: Browser profile to impersonate (see ``koon.browsers()``).
            **client_options: Options of ``KoonSync`` (``proxy``, ``proxies``,
                ``headers``, ``retries``, ``locale``, ``resolve``, ...).
                ``follow_redirects``, ``max_redirects``, ``on_redirect``,
                ``cookie_jar``, ``timeout`` and ``ignore_tls_errors`` belong to
                requests, and ``HTTPAdapter`` options koon has no counterpart
                for (``pool_connections``, ``pool_maxsize``, ``pool_block``,
                ``max_retries``) raise TypeError.
        """
        ...
    @property
    def client(self) -> KoonSync:
        """The koon client that sends the requests with ``verify=True``."""
        ...
    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Union[None, float, Tuple[Optional[float], Optional[float]]] = None,
        verify: Union[bool, str] = True,
        cert: Any = None,
        proxies: Optional[Mapping[str, str]] = None,
    ) -> requests.Response: ...
    def close(self) -> None:
        """Shut the koon clients down (``KoonSync.shutdown()``)."""
        ...

class Session(requests.Session):
    """A ``requests.Session`` with a ``KoonAdapter`` mounted for
    ``https://`` and ``http://``. Its ``headers`` start empty: the browser's
    are sent anyway, so they hold what the session adds."""

    def __init__(self, browser: str = "chrome", **client_options: Any) -> None: ...
