"""Streaming responses: `KoonSync.request_streaming()` (blocking) and
`Koon.request_streaming()` (async), and releasing their body with
`close()`, `aclose()`, `with` and `async with`. Offline, against the
adapter test server."""

import asyncio
import contextlib
import gzip

import pytest
from conftest import BR_BODY, GZIP_TEXT, dropped

from koon import (
    Koon,
    KoonError,
    KoonStreamingResponse,
    KoonSync,
    KoonSyncStreamingResponse,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------
# KoonSync.request_streaming
# ---------------------------------------------------------------------


def test_sync_streaming_reads_the_body_as_it_arrives(adapter_server):
    adapter_server.gate.clear()
    with KoonSync() as client, client.request_streaming("GET", adapter_server.url + "/gated") as r:
        assert isinstance(r, KoonSyncStreamingResponse)
        assert r.status == 200 and r.status_code == 200
        assert r.version == "HTTP/1.1" and r.url == adapter_server.url + "/gated"
        assert ("content-type", "text/plain") in r.headers
        assert r.headers is r.headers
        assert repr(r).startswith("<KoonSyncStreamingResponse status=200")
        first = b""
        while len(first) < len(b"first;"):
            first += r.next_chunk()
        # Read while the server still holds the rest back.
        assert first == b"first;"
        adapter_server.gate.set()
        assert b"".join(r) == b"second"
        assert r.next_chunk() is None
        assert r.bytes_received > 0


def header(response, name):
    return next((v for n, v in response.headers if n.lower() == name), None)


def is_encoded(raw, coding):
    """Whether `raw` is GZIP_TEXT as the server encoded it."""
    return gzip.decompress(raw) == GZIP_TEXT if coding == "gzip" else raw == BR_BODY


@pytest.mark.parametrize("coding", ["gzip", "br"])
def test_sync_streaming_decodes_the_body(adapter_server, coding):
    url = adapter_server.url + "/" + coding
    with KoonSync() as client:
        with client.request_streaming("GET", url) as r:
            chunks = list(r)
        assert chunks and all(isinstance(c, bytes) for c in chunks)
        assert b"".join(chunks) == GZIP_TEXT
        # The headers stay as received: they describe the bytes on the wire.
        assert header(r, "content-encoding") == coding
        with client.request_streaming("GET", url, decode=False) as r:
            raw = r.collect()
    assert is_encoded(raw, coding)
    assert header(r, "content-length") == str(len(raw))


@pytest.mark.parametrize("coding", ["gzip", "br"])
def test_async_streaming_decodes_the_body(adapter_server, coding):
    url = adapter_server.url + "/" + coding

    async def go():
        async with Koon() as client:
            async with await client.request_streaming("GET", url) as r:
                decoded = b"".join([chunk async for chunk in r])
            async with await client.request_streaming("GET", url, decode=False) as raw:
                return r, decoded, await raw.collect()

    r, decoded, raw = run(go())
    assert decoded == GZIP_TEXT
    assert header(r, "content-encoding") == coding
    assert is_encoded(raw, coding)


def test_a_body_that_does_not_decode_fails_the_read(adapter_server):
    # /bad-gzip says gzip but is not: reading it raises IO_ERROR.
    with KoonSync() as client:
        r = client.request_streaming("GET", adapter_server.url + "/bad-gzip")
        with pytest.raises(KoonError) as info:
            r.collect()
    assert info.value.code == "IO_ERROR"


def test_sync_collect_consumes_the_stream(adapter_server):
    with KoonSync() as client:
        r = client.request_streaming("POST", adapter_server.url + "/echo", "payload")
        assert b'"body": "payload"' in r.collect()
        with pytest.raises(KoonError) as info:
            r.next_chunk()
        assert info.value.code == "BODY_ERROR"
        with pytest.raises(KoonError):
            r.collect()


def test_leaving_with_releases_the_stream(adapter_server):
    adapter_server.dripped.clear()
    with KoonSync() as client:
        with client.request_streaming("GET", adapter_server.url + "/drip") as r:
            assert r.next_chunk()
        assert dropped(adapter_server)
        with pytest.raises(KoonError) as info:
            r.next_chunk()
        assert info.value.code == "BODY_ERROR"
        # The client goes on.
        assert client.get(adapter_server.url + "/echo").status == 200


def test_sync_close_releases_the_stream(adapter_server):
    adapter_server.dripped.clear()
    with KoonSync() as client:
        r = client.request_streaming("GET", adapter_server.url + "/drip")
        r.next_chunk()
        r.close()
        r.close()  # again: nothing happens
        assert dropped(adapter_server)
        with pytest.raises(KoonError):
            list(r)


def test_sync_streaming_timeout(adapter_server):
    with KoonSync() as client:
        with pytest.raises(KoonError) as info:
            client.request_streaming("GET", adapter_server.url + "/hang", timeout=0.5)
    assert info.value.code == "TIMEOUT"


# ---------------------------------------------------------------------
# Koon.request_streaming: closing
# ---------------------------------------------------------------------


def test_leaving_async_with_releases_the_stream(adapter_server):
    adapter_server.dripped.clear()

    async def go():
        async with Koon() as client:
            async with await client.request_streaming("GET", adapter_server.url + "/drip") as r:
                assert isinstance(r, KoonStreamingResponse)
                async for chunk in r:
                    assert chunk
                    break
            with pytest.raises(KoonError):
                await r.next_chunk()

    run(go())
    assert dropped(adapter_server)


def test_aclose_releases_the_stream(adapter_server):
    adapter_server.dripped.clear()

    async def go():
        async with Koon() as client:
            r = await client.request_streaming("GET", adapter_server.url + "/drip")
            async with contextlib.aclosing(r):
                await r.next_chunk()
            with pytest.raises(KoonError):
                await r.next_chunk()

    run(go())
    assert dropped(adapter_server)


def test_close_ends_a_pending_read(adapter_server):
    adapter_server.gate.clear()

    async def go():
        async with Koon() as client:
            r = await client.request_streaming("GET", adapter_server.url + "/gated")
            first = b""
            while len(first) < len(b"first;"):
                first += await r.next_chunk()
            pending = asyncio.ensure_future(r.next_chunk())
            # Yield to the event loop a few times instead of sleeping a
            # fixed duration: enough ticks for the read to actually start
            # waiting on the socket (the server holds the rest for up to 5 s
            # regardless, so there is nothing to race against wall-clock).
            for _ in range(10):
                await asyncio.sleep(0)
            assert not pending.done()  # waiting for the rest
            r.close()
            with pytest.raises(KoonError) as info:
                await asyncio.wait_for(pending, 2)
            assert info.value.code == "BODY_ERROR"

    try:
        run(go())
    finally:
        adapter_server.gate.set()
