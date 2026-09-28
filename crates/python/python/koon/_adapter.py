"""What the httpx transport (``koon.httpx``) and the requests adapter
(``koon.requests``) share: which of a request's headers reach koon, which
response headers the library gets, and the koon client options they own.

The rule for request headers: the library's own default headers (a header
with the name *and* value of one of them) are dropped, so koon sends the
browser's instead, in the browser's order. Every other header is the
caller's and goes to koon as a per-request header, which replaces the
browser's header of the same name in place or joins the browser's order
where the browser puts it. Host, Content-Length and Transfer-Encoding come
from koon itself.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

# koon sets these from the request itself; a caller's value is not sent.
_SET_BY_KOON = frozenset({"host", "content-length", "transfer-encoding"})

# Client options the adapters set themselves, because the library does that
# job: why each one is not an adapter option.
_OWNED_OPTIONS = {
    "follow_redirects": "{library} follows redirects",
    "max_redirects": "{library} follows redirects",
    "on_redirect": "{library} follows redirects",
    "cookie_jar": "cookies are kept in {library}'s cookie jar",
    "timeout": "timeouts are set through {library}",
    "ignore_tls_errors": "certificate verification is set with verify=",
}

_HTTP_VERSIONS = {"h2": "HTTP/2", "h3": "HTTP/3"}


def client_options(
    library: str,
    options: Mapping[str, object],
    unsupported: Mapping[str, str] | None = None,
) -> dict:
    """The koon client options of an adapter: the caller's, with redirects
    and the cookie jar off. An option the library owns, or one of
    ``unsupported`` (options of the library's own transport koon has no
    counterpart for), raises TypeError instead of being ignored."""
    for name in options:
        reason = _OWNED_OPTIONS.get(name) or (unsupported or {}).get(name)
        if reason:
            raise TypeError(
                f"{name}= is not an option of koon's {library} adapter: "
                + reason.format(library=library)
            )
    return {**options, "follow_redirects": False, "cookie_jar": False}


def authority(url: str) -> str:
    """The Host header koon sends for ``url``: the host, with the port
    unless it is the scheme's default."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    return host if parts.port in (None, default) else f"{host}:{parts.port}"


def caller_headers(
    headers: Iterable[tuple[str, str]], defaults: Mapping[str, str], url: str
) -> list[tuple[str, str]]:
    """The headers the caller set, in their order: ``headers`` without the
    library's ``defaults`` (lowercase name to value) and without the ones
    koon sets itself. A name given more than once is sent once, with its
    values joined (Cookie with ``; ``, others with ``, ``). A Host other
    than the URL's raises ValueError: koon always sends the URL's."""
    merged: dict[str, tuple[str, str]] = {}
    for name, value in headers:
        lower = name.lower()
        if defaults.get(lower) == value:
            continue
        if lower == "host" and value.lower() != authority(url):
            raise ValueError(
                f"koon sends the Host of the URL ({authority(url)}), not {value!r}; "
                "to connect to another address, use the client option resolve="
            )
        if lower in _SET_BY_KOON:
            continue
        if lower in merged:
            first, joined = merged[lower]
            separator = "; " if lower == "cookie" else ", "
            merged[lower] = (first, joined + separator + value)
        else:
            merged[lower] = (name, value)
    return list(merged.values())


def response_headers(
    headers: Iterable[tuple[str, str]], decoded: bool
) -> list[tuple[str, str]]:
    """The response headers for the library. koon decodes the body; when it
    did, Content-Encoding and Content-Length (which describe the encoded
    body) are left out, so the library does not decode the body again."""
    if not decoded:
        return list(headers)
    return [
        (name, value)
        for name, value in headers
        if name.lower() not in ("content-encoding", "content-length")
    ]


def http_version(version: str) -> str:
    """koon's HTTP version ("HTTP/1.1", "h2", "h3") as the libraries name it."""
    return _HTTP_VERSIONS.get(version, version)


# The boundary httpx and urllib3 (requests) generate: 16 random bytes in hex.
_LIBRARY_BOUNDARY = re.compile(r"multipart/form-data;\s*boundary=([0-9a-f]{32})", re.IGNORECASE)
_DISPOSITION_PARAM = re.compile(r';\s*([A-Za-z*]+)="([^"]*)"')

# How the libraries escape a name or filename in Content-Disposition, undone.
# urllib3 escapes as browsers do: CR, LF and the double quote as %0D, %0A and
# %22. httpx escapes every control character but ESC the same way, and a
# backslash as two.
_URLLIB3_ESCAPE = re.compile(r"%(0A|0D|22)")
_HTTPX_ESCAPE = re.compile(r"%(0[0-9A-F]|1[0-9A-F]|22)|\\\\")


def unescape_urllib3(value: str) -> str:
    return _URLLIB3_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)


def unescape_httpx(value: str) -> str:
    return _HTTPX_ESCAPE.sub(
        lambda m: "\\" if m.group(0) == "\\\\" else chr(int(m.group(1), 16)), value
    )


def _form_fields(body: bytes, boundary: str, unescape: Callable[[str], str]) -> list | None:
    """The fields of a multipart/form-data body the library encoded, as
    ``_encode_multipart`` takes them, or None if it is not one."""
    delimiter = b"\r\n--" + boundary.encode("ascii")
    sections = (b"\r\n" + body).split(delimiter)
    if sections[0] != b"" or not sections[-1].startswith(b"--"):
        return None
    fields = []
    for section in sections[1:-1]:
        head, found, content = section.partition(b"\r\n\r\n")
        if not found or not head.startswith(b"\r\n"):
            return None
        headers = {}
        for line in head[2:].split(b"\r\n"):
            name, _, value = line.partition(b":")
            headers[name.strip().lower()] = value.strip().decode("utf-8")
        params = {
            key.lower(): unescape(value)
            for key, value in _DISPOSITION_PARAM.findall(headers.get(b"content-disposition", ""))
        }
        if "name" not in params or "filename*" in params:
            return None
        if "filename" in params:
            fields.append(
                {
                    "name": params["name"],
                    "file_data": content,
                    "filename": params["filename"],
                    "content_type": headers.get(b"content-type", "application/octet-stream"),
                }
            )
        else:
            fields.append({"name": params["name"], "value": content.decode("utf-8")})
    return fields


def browser_multipart(
    headers: list[tuple[str, str]],
    body: bytes | None,
    encode: Callable[[list], tuple[bytes, str]],
    unescape: Callable[[str], str],
) -> tuple[list[tuple[str, str]], bytes | None]:
    """A multipart/form-data body the library encoded for ``files=`` (its
    boundary is 32 hex digits), encoded again as the profile's browser does
    (``encode``, the koon client's ``_encode_multipart``): its boundary, its
    escaping of names and filenames. Part headers other than
    Content-Disposition and a file's Content-Type are not kept. Any other
    body, including a multipart one with a boundary the caller chose, is
    sent as it is."""
    index = next((i for i, (n, _) in enumerate(headers) if n.lower() == "content-type"), None)
    if index is None or body is None:
        return headers, body
    match = _LIBRARY_BOUNDARY.fullmatch(headers[index][1].strip())
    if not match:
        return headers, body
    try:
        fields = _form_fields(body, match.group(1), unescape)
    except UnicodeDecodeError:
        fields = None  # a text field that is not UTF-8: sent as it is
    if not fields:
        return headers, body
    encoded, content_type = encode(fields)
    headers = list(headers)
    headers[index] = (headers[index][0], content_type)
    return headers, encoded
