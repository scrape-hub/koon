"""koon.httpx: the httpx transports, offline against local servers. They
must keep the fingerprint: httpx's default headers never reach the wire,
and the browser's headers go out in the browser's order, exactly as koon
sends them itself."""

import asyncio
import json
import re

import pytest

httpx = pytest.importorskip("httpx")

from conftest import GZIP_TEXT, dropped, free_port  # noqa: E402

from koon import KoonError, KoonSync  # noqa: E402
from koon.httpx import AsyncKoonTransport, KoonTransport  # noqa: E402


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
def client():
    with httpx.Client(transport=KoonTransport("chrome")) as c:
        yield c


def test_sends_koons_headers_not_httpxs(client, adapter_server):
    url = adapter_server.url + "/echo"
    r = client.get(url)
    assert r.status_code == 200
    headers = received(r)
    assert not [v for _, v in headers if "python-httpx" in v]
    assert value(headers, "accept") != "*/*"
    # What koon sends for the same request, in the same order.
    assert headers == native_headers(url)


def test_caller_headers_take_the_browsers_place(adapter_server):
    url = adapter_server.url + "/echo"
    with httpx.Client(transport=KoonTransport(), headers={"X-Client": "c"}) as client:
        r = client.get(url, headers={"Accept": "application/json", "X-Request": "r"})
    headers = received(r)
    assert value(headers, "accept") == "application/json"
    assert value(headers, "x-client") == "c" and value(headers, "x-request") == "r"
    expected = native_headers(
        url, headers=[("X-Client", "c"), ("Accept", "application/json"), ("X-Request", "r")]
    )
    assert headers == expected


def test_a_user_agent_the_caller_sets_is_sent(client, adapter_server):
    r = client.get(adapter_server.url + "/echo", headers={"User-Agent": "custom/1"})
    assert value(received(r), "user-agent") == "custom/1"


def test_post_json(client, adapter_server):
    r = client.post(adapter_server.url + "/echo", json={"a": 1})
    data = r.json()
    assert data["method"] == "POST"
    assert json.loads(data["body"]) == {"a": 1}
    headers = received(r)
    assert value(headers, "content-type") == "application/json"
    assert [n.lower() for n, _ in headers].count("content-length") == 1
    assert value(headers, "content-length") == str(len(data["body"]))


def test_head_and_no_content(client, adapter_server):
    assert client.head(adapter_server.url + "/echo").content == b""
    r = client.get(adapter_server.url + "/no-content")
    assert r.status_code == 204 and r.content == b""


def test_httpx_follows_the_redirects(client, adapter_server):
    r = client.get(adapter_server.url + "/redirect")
    assert r.status_code == 302 and r.headers["location"] == "/echo"
    assert r.next_request is not None
    r = client.get(adapter_server.url + "/redirect", follow_redirects=True)
    assert r.status_code == 200
    assert [h.status_code for h in r.history] == [302]
    assert str(r.url) == adapter_server.url + "/echo"


def test_307_keeps_method_and_body(client, adapter_server):
    r = client.post(adapter_server.url + "/redirect-307", content=b"payload", follow_redirects=True)
    assert r.json()["method"] == "POST" and r.json()["body"] == "payload"


def test_cookies_live_in_the_httpx_jar(adapter_server):
    transport = KoonTransport("chrome")
    with httpx.Client(transport=transport) as client:
        client.get(adapter_server.url + "/set-cookie")
        assert client.cookies.get("sid") == "abc123"
        r = client.get(adapter_server.url + "/echo")
        assert value(received(r), "cookie") == "sid=abc123"
        assert transport.client.cookies() == []  # koon's own jar is off
        client.cookies.clear()
        r = client.get(adapter_server.url + "/echo")
        assert value(received(r), "cookie") is None


def test_a_cookie_set_by_a_redirect_is_sent_on(client, adapter_server):
    r = client.get(adapter_server.url + "/redirect-cookie", follow_redirects=True)
    assert value(received(r), "cookie") == "hop=1"


@pytest.mark.parametrize("coding", ["gzip", "br"])
def test_a_compressed_body_is_decoded_once(client, adapter_server, coding):
    r = client.get(adapter_server.url + "/" + coding)
    assert r.content == GZIP_TEXT
    assert "content-encoding" not in r.headers and "content-length" not in r.headers


def test_stream_reads_the_body_as_it_arrives(client, adapter_server):
    adapter_server.gate.clear()
    with client.stream("GET", adapter_server.url + "/gated") as r:
        chunks = r.iter_bytes()
        first = b""
        while len(first) < len(b"first;"):
            first += next(chunks)
        # Read while the server still holds the rest back.
        assert first == b"first;"
        adapter_server.gate.set()
        assert b"".join(chunks) == b"second"


def test_closing_a_stream_early_releases_it(client, adapter_server):
    adapter_server.dripped.clear()
    with client.stream("GET", adapter_server.url + "/drip") as r:
        next(r.iter_bytes())
    # httpx closed the response: koon dropped the connection.
    assert dropped(adapter_server)
    assert client.get(adapter_server.url + "/echo").status_code == 200


def test_files_go_as_the_browsers_multipart(adapter_server):
    url = adapter_server.url + "/echo"
    files = {"upload": ('a"b\\c\nd.txt', b"file content", "text/plain")}
    with httpx.Client(transport=KoonTransport("chrome")) as client:
        r = client.post(url, data={"field": "value"}, files=files)
    content_type = value(received(r), "content-type")
    boundary = re.fullmatch(
        r"multipart/form-data; boundary=(----WebKitFormBoundary[A-Za-z0-9]{16})", content_type
    )
    assert boundary, content_type
    body = r.json()["body"]
    # Chrome's layout and escaping: the double quote and the line feed
    # percent-encoded, the backslash as it is (httpx doubles it).
    assert body == (
        f"--{boundary.group(1)}\r\n"
        'Content-Disposition: form-data; name="field"\r\n\r\nvalue\r\n'
        f"--{boundary.group(1)}\r\n"
        'Content-Disposition: form-data; name="upload"; filename="a%22b\\c%0Ad.txt"\r\n'
        "Content-Type: text/plain\r\n\r\nfile content\r\n"
        f"--{boundary.group(1)}--\r\n"
    )
    assert value(received(r), "content-length") == str(len(body))

    with httpx.Client(transport=KoonTransport("firefox")) as client:
        r = client.post(url, files={"upload": ("a.txt", b"x")})
    assert re.fullmatch(
        r"multipart/form-data; boundary=----geckoformboundary[0-9a-f]+", value(received(r), "content-type")
    )


def test_a_boundary_the_caller_chose_is_kept(client, adapter_server):
    r = client.post(
        adapter_server.url + "/echo",
        files={"upload": ("a.txt", b"x")},
        headers={"Content-Type": "multipart/form-data; boundary=my-own-boundary"},
    )
    assert value(received(r), "content-type") == "multipart/form-data; boundary=my-own-boundary"
    assert r.json()["body"].startswith("--my-own-boundary\r\n")


def test_http_version(client, adapter_server):
    assert client.get(adapter_server.url + "/echo").http_version == "HTTP/1.1"


def test_timeout_raises_read_timeout(adapter_server):
    with httpx.Client(transport=KoonTransport(), timeout=0.5) as client:
        with pytest.raises(httpx.ReadTimeout) as info:
            client.get(adapter_server.url + "/hang")
    assert isinstance(info.value.__cause__, KoonError)
    assert info.value.__cause__.code == "TIMEOUT"


def test_no_read_timeout_means_no_timeout(adapter_server):
    # /slow answers after 1.5 s; read=None lifts the 0.5 s of the others.
    with httpx.Client(transport=KoonTransport(), timeout=httpx.Timeout(0.5, read=None)) as client:
        assert client.get(adapter_server.url + "/slow").status_code == 200


def test_connection_refused_raises_connect_error(client):
    with pytest.raises(httpx.ConnectError) as info:
        client.get(f"http://127.0.0.1:{free_port()}/")
    assert isinstance(info.value.__cause__, KoonError)


def test_verify(tls_origin):
    with httpx.Client(transport=KoonTransport()) as client:
        with pytest.raises(httpx.ConnectError) as info:
            client.get(tls_origin + "/")
        assert info.value.__cause__.code == "TLS_ERROR"
    with httpx.Client(transport=KoonTransport(verify=False)) as client:
        assert client.get(tls_origin + "/").text == "secure"


def test_proxy_option_reaches_koon(forward_proxy):
    with httpx.Client(transport=KoonTransport(proxy=forward_proxy.url)) as client:
        r = client.get("http://example.test/through")
    assert r.text == "proxied"
    assert forward_proxy.lines == ["GET http://example.test/through"]


@pytest.mark.parametrize(
    "option",
    ["follow_redirects", "max_redirects", "cookie_jar", "timeout", "ignore_tls_errors", "http2", "cert"],
)
def test_options_httpx_owns_or_koon_lacks_raise(option):
    with pytest.raises(TypeError, match=f"{option}="):
        KoonTransport("chrome", **{option: True})


def test_verify_takes_only_booleans():
    with pytest.raises(TypeError, match="verify"):
        KoonTransport(verify="/etc/ssl/certs/ca-certificates.crt")


def test_a_host_other_than_the_urls_raises(client, adapter_server):
    with pytest.raises(ValueError, match="Host"):
        client.get(adapter_server.url + "/echo", headers={"Host": "example.com"})


def test_async_transport(adapter_server):
    url = adapter_server.url

    async def go():
        async with httpx.AsyncClient(transport=AsyncKoonTransport("chrome")) as client:
            r = await client.get(url + "/echo")
            assert received(r) == native_headers(url + "/echo")

            r = await client.post(url + "/redirect-307", content=b"x", follow_redirects=True)
            assert r.json()["method"] == "POST" and r.json()["body"] == "x"

            await client.get(url + "/set-cookie")
            r = await client.get(url + "/echo")
            assert value(received(r), "cookie") == "sid=abc123"

            r = await client.get(url + "/gzip")
            assert r.content == GZIP_TEXT and "content-encoding" not in r.headers

            adapter_server.gate.clear()
            async with client.stream("GET", url + "/gated") as r:
                chunks = r.aiter_bytes()
                first = b""
                while len(first) < len(b"first;"):
                    first += await chunks.__anext__()
                assert first == b"first;"
                adapter_server.gate.set()
                assert b"".join([c async for c in chunks]) == b"second"

            with pytest.raises(httpx.ReadTimeout):
                await client.get(url + "/hang", timeout=0.5)
            with pytest.raises(httpx.ConnectError):
                await client.get(f"http://127.0.0.1:{free_port()}/")

    asyncio.run(go())
