"""Real-network sanity tests. Deselected by default (see pyproject.toml
`addopts = "-m 'not network'"`); run explicitly with `pytest -m network`.
"""

import asyncio

import pytest

from koon import Koon, KoonSync

pytestmark = pytest.mark.network


def test_https_get_real_site():
    async def go():
        client = Koon("chrome")
        return await client.get("https://httpbin.org/get")

    resp = asyncio.run(go())
    assert resp.status == 200
    assert resp.tls_resumed is False or resp.tls_resumed is True  # just must not raise


def test_koonsync_https_get_real_site():
    client = KoonSync("chrome")
    resp = client.get("https://httpbin.org/get")
    assert resp.status == 200
    client.close()


def test_shutdown_after_http3():
    """The first response advertises HTTP/3; once the HTTP/2 connection is
    closed, the next request goes over HTTP/3, and shutdown() ends it."""
    url = "https://www.google.com/generate_204"

    async def go():
        client = Koon("chrome")
        await client.get(url)
        client.close()
        resp = await client.get(url)
        await client.shutdown()
        return resp

    assert asyncio.run(go()).version == "h3"
    client = KoonSync("firefox")
    client.get(url)
    client.close()
    assert client.get(url).version == "h3"
    client.shutdown()


def test_websocket_send_does_not_block_on_pending_receive():
    """A pending receive() does not block send(): the core locks each
    direction on its own, and the binding must not wrap the whole WebSocket
    in one lock."""

    async def go():
        client = Koon("chrome")
        ws = await client.websocket("wss://ws.postman-echo.com/raw")
        try:
            receive_task = asyncio.ensure_future(ws.receive())
            # Let receive() start waiting on the socket, so send() runs while
            # it is pending: yield to the event loop a few times instead of
            # a fixed sleep, since one tick is enough for it to reach its
            # own await point and further ticks cost nothing but time.
            for _ in range(10):
                await asyncio.sleep(0)
            await asyncio.wait_for(ws.send("concurrent-hello"), timeout=5)
            msg = await asyncio.wait_for(receive_task, timeout=5)
            assert msg == {"type": "text", "data": "concurrent-hello"}
        finally:
            await ws.close()

    asyncio.run(go())
