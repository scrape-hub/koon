"""koon.requests: the requests adapter, offline against local servers. It
must keep the fingerprint: requests' default headers never reach the wire,
and the browser's headers go out in the browser's order, exactly as koon
sends them itself."""

import json
import re

import pytest

requests = pytest.importorskip("requests")

from conftest import GZIP_TEXT, dropped, free_port  # noqa: E402

from koon import KoonError, KoonSync  # noqa: E402
from koon.requests import KoonAdapter, Session  # noqa: E402


def received(response):
    """The headers the echo server received, in wire order."""
    return [tuple(pair) for pair in response.json()["headers"]]


def value(headers, name):
    return next((v for n, v in headers if n.lower() == name), None)


def native_headers(url, **options):
    """The headers koon itself sends for the same request."""
    with KoonSync("chrome") as client:
        return [tuple(pair) for pair in json.loads(client.get(url, **options).text)["headers"]]


@pytest.fixture
def session():
    with Session("chrome") as s:
        yield s


def test_mounted_on_a_plain_session_sends_koons_headers(adapter_server):
    url = adapter_server.url + "/echo"
    with requests.Session() as s:
        adapter = KoonAdapter("chrome")
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        r = s.get(url)
    assert r.status_code == 200
    headers = received(r)
    assert not [v for _, v in headers if "python-requests" in v]
    assert headers == native_headers(url)


def test_session_starts_without_headers_of_its_own(session, adapter_server):
    assert dict(session.headers) == {}
    url = adapter_server.url + "/echo"
    assert received(session.get(url)) == native_headers(url)


def test_caller_headers_take_the_browsers_place(session, adapter_server):
    url = adapter_server.url + "/echo"
    session.headers["X-Session"] = "s"
    r = session.get(url, headers={"Accept": "application/json", "X-Request": "r"})
    headers = received(r)
    assert value(headers, "accept") == "application/json"
    expected = native_headers(
        url, headers=[("X-Session", "s"), ("Accept", "application/json"), ("X-Request", "r")]
    )
    assert headers == expected


def test_post_form_json_and_files(session, adapter_server):
    url = adapter_server.url + "/echo"
    r = session.post(url, data={"k": "v"})
    assert r.json()["body"] == "k=v"
    assert value(received(r), "content-type") == "application/x-www-form-urlencoded"
    r = session.post(url, json={"a": 1})
    assert json.loads(r.json()["body"]) == {"a": 1}
    r = session.post(url, data={"field": "value"}, files={"upload": ('a"b\nc.txt', b"file content")})
    content_type = value(received(r), "content-type")
    boundary = re.fullmatch(
        r"multipart/form-data; boundary=(----WebKitFormBoundary[A-Za-z0-9]{16})", content_type
    )
    assert boundary, content_type
    assert r.json()["body"] == (
        f"--{boundary.group(1)}\r\n"
        'Content-Disposition: form-data; name="field"\r\n\r\nvalue\r\n'
        f"--{boundary.group(1)}\r\n"
        'Content-Disposition: form-data; name="upload"; filename="a%22b%0Ac.txt"\r\n'
        "Content-Type: application/octet-stream\r\n\r\nfile content\r\n"
        f"--{boundary.group(1)}--\r\n"
    )
    # A generator body (a chunked upload in requests) goes out with its length.
    r = session.post(url, data=(part for part in [b"ab", b"cd"]))
    assert r.json()["body"] == "abcd"
    assert value(received(r), "content-length") == "4"
    assert value(received(r), "transfer-encoding") is None


def test_requests_follows_the_redirects(session, adapter_server):
    r = session.get(adapter_server.url + "/redirect")
    assert r.status_code == 200
    assert [h.status_code for h in r.history] == [302]
    assert r.url == adapter_server.url + "/echo"
    r = session.get(adapter_server.url + "/redirect", allow_redirects=False)
    assert r.status_code == 302 and r.headers["Location"] == "/echo"
    r = session.post(adapter_server.url + "/redirect-307", data=b"payload")
    assert r.json()["method"] == "POST" and r.json()["body"] == "payload"


def test_cookies_live_in_the_requests_jar(session, adapter_server):
    r = session.get(adapter_server.url + "/set-cookie")
    assert r.cookies.get("sid") == "abc123"
    assert session.cookies.get("sid") == "abc123"
    r = session.get(adapter_server.url + "/echo")
    assert value(received(r), "cookie") == "sid=abc123"
    assert session.get_adapter("http://").client.cookies() == []  # koon's own jar is off
    session.cookies.clear()
    assert value(received(session.get(adapter_server.url + "/echo")), "cookie") is None
    r = session.get(adapter_server.url + "/redirect-cookie")
    assert value(received(r), "cookie") == "hop=1"


@pytest.mark.parametrize("coding", ["gzip", "br"])
def test_a_compressed_body_is_decoded_once(session, adapter_server, coding):
    r = session.get(adapter_server.url + "/" + coding)
    assert r.content == GZIP_TEXT
    assert "Content-Encoding" not in r.headers and "Content-Length" not in r.headers
    r = session.get(adapter_server.url + "/" + coding, stream=True)
    assert r.raw.read() == GZIP_TEXT


def test_stream_reads_the_body_as_it_arrives(session, adapter_server):
    adapter_server.gate.clear()
    r = session.get(adapter_server.url + "/gated", stream=True)
    chunks = r.iter_content(chunk_size=None)
    first = b""
    while len(first) < len(b"first;"):
        first += next(chunks)
    # Read while the server still holds the rest back.
    assert first == b"first;"
    adapter_server.gate.set()
    assert b"".join(chunks) == b"second"
    r.close()


def test_iter_content_with_a_chunk_size_and_iter_lines(session, adapter_server):
    r = session.get(adapter_server.url + "/gzip", stream=True)
    pieces = list(r.iter_content(chunk_size=1000))
    assert b"".join(pieces) == GZIP_TEXT
    assert max(len(p) for p in pieces) <= 1000
    adapter_server.gate.set()
    r = session.get(adapter_server.url + "/gated", stream=True)
    assert list(r.iter_lines()) == [b"first;second"]


def test_closing_a_streamed_response_early_releases_it(session, adapter_server):
    adapter_server.dripped.clear()
    r = session.get(adapter_server.url + "/drip", stream=True)
    next(r.iter_content(chunk_size=None))
    r.close()
    # requests closed the response: koon dropped the connection.
    assert dropped(adapter_server)
    assert session.get(adapter_server.url + "/echo").status_code == 200


def test_firefox_multipart(adapter_server):
    with Session("firefox") as s:
        r = s.post(adapter_server.url + "/echo", files={"upload": ("a.txt", b"x")})
    assert re.fullmatch(
        r"multipart/form-data; boundary=----geckoformboundary[0-9a-f]+", value(received(r), "content-type")
    )


def test_timeouts(session, adapter_server):
    with pytest.raises(requests.exceptions.ReadTimeout) as info:
        session.get(adapter_server.url + "/hang", timeout=0.5)
    assert isinstance(info.value.__cause__, KoonError)
    # (connect, read) with read=None: no timeout.
    assert session.get(adapter_server.url + "/slow", timeout=(0.5, None)).status_code == 200


def test_connection_refused_raises_connection_error(session):
    with pytest.raises(requests.exceptions.ConnectionError) as info:
        session.get(f"http://127.0.0.1:{free_port()}/")
    assert isinstance(info.value.__cause__, KoonError)


def test_verify(session, tls_origin):
    with pytest.raises(requests.exceptions.SSLError) as info:
        session.get(tls_origin + "/")
    assert info.value.__cause__.code == "TLS_ERROR"
    assert session.get(tls_origin + "/", verify=False).text == "secure"
    # The verifying client stays in use for verify=True.
    with pytest.raises(requests.exceptions.SSLError):
        session.get(tls_origin + "/")
    with pytest.raises(ValueError, match="CA bundle"):
        session.get(tls_origin + "/", verify="/etc/ssl/certs/ca-certificates.crt")
    with pytest.raises(ValueError, match="cert="):
        session.get(tls_origin + "/", cert="client.pem")


def test_proxies_reach_koon(session, forward_proxy, monkeypatch):
    r = session.get("http://example.test/through", proxies={"http": forward_proxy.url})
    assert r.text == "proxied"
    # From the environment too, as requests reads it.
    monkeypatch.setenv("HTTP_PROXY", forward_proxy.url)
    assert session.get("http://example.test/env").text == "proxied"
    assert forward_proxy.lines == ["GET http://example.test/through", "GET http://example.test/env"]


@pytest.mark.parametrize(
    "option", ["follow_redirects", "cookie_jar", "timeout", "ignore_tls_errors", "max_retries"]
)
def test_options_requests_owns_or_koon_lacks_raise(option):
    with pytest.raises(TypeError, match=f"{option}="):
        KoonAdapter("chrome", **{option: True})


def test_a_host_other_than_the_urls_raises(session, adapter_server):
    with pytest.raises(ValueError, match="Host"):
        session.get(adapter_server.url + "/echo", headers={"Host": "example.com"})
