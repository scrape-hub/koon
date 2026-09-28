"""Tests for the native `KoonSync` client: thread-safety, usability from
inside a running asyncio event loop, and interruption with Ctrl+C."""

import asyncio
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from koon import KoonError, KoonSync


def test_koonsync_basic_request(base_url):
    client = KoonSync("chrome")
    resp = client.get(base_url + "/echo")
    assert resp.status == 200
    assert resp.ok
    client.close()


def test_koonsync_threads_each_get_their_own_response(base_url):
    """One client shared by many threads works, and each thread gets the
    response to its own request."""
    client = KoonSync("chrome")

    def worker(i):
        resp = client.post(base_url + "/echo", body=f"payload-{i}")
        return i, resp.status, json.loads(resp.text)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(20)))

    assert len(results) == 20
    for i, status, payload in results:
        assert status == 200
        assert payload["body"] == f"payload-{i}"
    client.close()


def test_koonsync_inside_running_asyncio_loop(base_url):
    """KoonSync works from inside a running asyncio event loop (e.g.
    Jupyter), where run_until_complete would raise: it blocks on koon's own
    runtime."""

    async def inner():
        client = KoonSync("chrome")
        resp = client.get(base_url + "/echo")
        assert resp.status == 200
        client.close()
        return resp.status

    status = asyncio.run(inner())
    assert status == 200


def test_koonsync_close_closes_pool(base_url):
    client = KoonSync("chrome")
    resp = client.get(base_url + "/echo")
    assert resp.status == 200
    client.close()
    # The client remains usable after close() — new connections open lazily.
    resp2 = client.get(base_url + "/echo")
    assert resp2.status == 200


def test_koonsync_lowercase_method_uppercased(base_url):
    client = KoonSync("chrome")
    resp = client.request("post", base_url + "/echo", body="x")
    assert json.loads(resp.text)["method"] == "POST"
    client.close()


def test_koonsync_on_redirect_none_continues(base_url):
    client = KoonSync("chrome")
    resp = client.get(base_url + "/redirect", on_redirect=lambda s, u, h: None)
    assert resp.status == 200
    client.close()


def test_koonsync_on_redirect_false_stops(base_url):
    client = KoonSync("chrome")
    resp = client.get(base_url + "/redirect", on_redirect=lambda s, u, h: False)
    assert resp.status == 302
    client.close()


def test_koonsync_timeout_raises_koon_error(base_url):
    client = KoonSync("chrome")
    with pytest.raises(KoonError) as exc_info:
        client.get(base_url + "/slow", timeout=0.2)
    assert exc_info.value.code == "TIMEOUT"
    client.close()


def test_koonsync_post_multipart_with_kwargs(base_url):
    client = KoonSync("chrome")
    resp = client.post_multipart(
        base_url + "/echo",
        [{"name": "field", "value": "hello"}],
        headers={"X-Multipart": "1"},
        timeout=5,
    )
    assert resp.status == 200
    assert any(n.lower() == "x-multipart" for n, _ in resp.request_headers)
    payload = json.loads(resp.text)
    assert "hello" in payload["body"]
    client.close()


INTERRUPT_SCRIPT = r"""
import _thread, sys, threading, time
from koon import KoonSync

client = KoonSync("chrome", timeout=0)
threading.Timer(0.3, _thread.interrupt_main).start()
start = time.monotonic()
try:
    client.get(sys.argv[1])
except KeyboardInterrupt:
    print("interrupted", round(time.monotonic() - start, 2))
else:
    print("completed", round(time.monotonic() - start, 2))
"""


def test_koonsync_request_is_interrupted_by_ctrl_c(base_url):
    """A blocking request must not swallow Ctrl+C (or a Jupyter kernel
    interrupt, which is `_thread.interrupt_main` on Windows): it raises
    KeyboardInterrupt within ~100 ms instead of waiting for the response.
    Runs in a subprocess so a stray interrupt cannot hit pytest itself."""
    result = subprocess.run(
        [sys.executable, "-c", INTERRUPT_SCRIPT, base_url + "/hang"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    outcome, elapsed = result.stdout.split()
    assert outcome == "interrupted"
    assert float(elapsed) < 2.0  # /hang answers after 5 s
