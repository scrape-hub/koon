"""Offline tests for the async `Koon` client, against the local echo server."""

import asyncio
import collections.abc
import http.server
import json
import pickle
import socket
import threading
import time
import types

import pytest

import koon
from koon import Koon, KoonError, KoonInvalidArgument, KoonProxy, KoonSync


def run(coro):
    return asyncio.run(coro)


def header_names(headers):
    return [name.lower() for name, _ in headers]


def find(headers, name):
    """Index of the first header matching `name` (case-insensitive), or -1."""
    name = name.lower()
    for i, (n, _) in enumerate(headers):
        if n.lower() == name:
            return i
    return -1


# ---------------------------------------------------------------------
# Header order
# ---------------------------------------------------------------------


def test_dict_headers_preserve_insertion_order(base_url):
    async def go():
        client = Koon("chrome")
        resp = await client.get(
            base_url + "/echo",
            headers={"X-Zeta": "1", "X-Alpha": "2", "X-Mid": "3"},
        )
        return resp

    resp = run(go())
    assert resp.status == 200
    sent = resp.request_headers
    zeta, alpha, mid = find(sent, "x-zeta"), find(sent, "x-alpha"), find(sent, "x-mid")
    assert zeta != -1 and alpha != -1 and mid != -1
    assert zeta < alpha < mid

    # The server actually received them too, not just what koon claims.
    payload = json.loads(resp.text)
    received = header_names(payload["headers"])
    assert "x-zeta" in received
    assert "x-alpha" in received
    assert "x-mid" in received


def test_list_of_tuples_headers_keep_order(base_url):
    async def go():
        client = Koon("chrome")
        return await client.get(
            base_url + "/echo",
            headers=[("X-First", "a"), ("X-Second", "b"), ("X-Third", "c")],
        )

    resp = run(go())
    assert resp.status == 200
    sent = resp.request_headers
    first, second, third = find(sent, "x-first"), find(sent, "x-second"), find(sent, "x-third")
    assert first != -1 and second != -1 and third != -1
    assert first < second < third


def test_list_of_tuples_with_repeated_name_last_value_wins(base_url):
    """A list of tuples may name a header twice (a dict cannot); the request
    builder merges same-named headers, last one wins, before they reach the
    wire."""

    async def go():
        client = Koon("chrome")
        return await client.get(
            base_url + "/echo",
            headers=[("X-Multi", "a"), ("X-Multi", "b")],
        )

    resp = run(go())
    assert resp.status == 200
    sent = resp.request_headers
    multi_values = [v for n, v in sent if n.lower() == "x-multi"]
    assert multi_values == ["b"]


def test_request_headers_reflects_final_request(base_url):
    async def go():
        client = Koon("chrome")
        return await client.post(base_url + "/echo", body="hello", headers={"X-Test": "yes"})

    resp = run(go())
    assert resp.status == 200
    assert any(n.lower() == "x-test" and v == "yes" for n, v in resp.request_headers)
    payload = json.loads(resp.text)
    assert payload["body"] == "hello"


# ---------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------


def test_follow_redirects_default_follows(base_url):
    async def go():
        client = Koon("chrome")
        return await client.get(base_url + "/redirect")

    resp = run(go())
    assert resp.status == 200
    assert json.loads(resp.text)["path"] == "/echo"


def test_follow_redirects_false_stops_at_redirect(base_url):
    async def go():
        client = Koon("chrome")
        return await client.get(base_url + "/redirect", follow_redirects=False)

    resp = run(go())
    assert resp.status == 302


def test_on_redirect_explicit_false_stops(base_url):
    async def go():
        client = Koon("chrome")
        return await client.get(
            base_url + "/redirect", on_redirect=lambda status, url, headers: False
        )

    resp = run(go())
    assert resp.status == 302


def test_on_redirect_none_continues(base_url):
    """Returning None follows the redirect: only an explicit False stops
    it."""

    async def go():
        client = Koon("chrome")
        return await client.get(
            base_url + "/redirect", on_redirect=lambda status, url, headers: None
        )

    resp = run(go())
    assert resp.status == 200
    assert json.loads(resp.text)["path"] == "/echo"


def test_on_redirect_truthy_non_bool_continues(base_url):
    async def go():
        client = Koon("chrome")
        return await client.get(
            base_url + "/redirect", on_redirect=lambda status, url, headers: "no"
        )

    resp = run(go())
    assert resp.status == 200


def test_max_redirects_per_request_override(base_url):
    async def go():
        client = Koon("chrome", max_redirects=10)
        return await client.get(base_url + "/redirect-loop", max_redirects=1)

    with pytest.raises(KoonError) as exc_info:
        run(go())
    assert exc_info.value.code == "TOO_MANY_REDIRECTS"


# ---------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------


def test_per_request_timeout_raises(base_url):
    async def go():
        client = Koon("chrome")
        return await client.get(base_url + "/slow", timeout=0.2)

    with pytest.raises(KoonError) as exc_info:
        run(go())
    assert exc_info.value.code == "TIMEOUT"


def test_per_request_timeout_zero_overrides_short_client_timeout(base_url):
    """timeout=0 means "no timeout", overriding a short client-level default —
    the core handles this, the binding must not add its own wrapper on top."""

    async def go():
        client = Koon("chrome", timeout=1)
        return await client.get(base_url + "/slow", timeout=0)

    resp = run(go())
    assert resp.status == 200


# ---------------------------------------------------------------------
# Methods and bodies
# ---------------------------------------------------------------------


def test_lowercase_method_is_uppercased_on_the_wire(base_url):
    async def go():
        client = Koon("chrome")
        return await client.request("get", base_url + "/echo")

    resp = run(go())
    assert resp.status == 200
    assert json.loads(resp.text)["method"] == "GET"


def test_request_streaming_accepts_str_body(base_url):
    async def go():
        client = Koon("chrome")
        stream = await client.request_streaming("POST", base_url + "/echo", body="hello streaming")
        return await stream.collect()

    body = run(go())
    payload = json.loads(body.decode())
    assert payload["body"] == "hello streaming"


def test_request_streaming_response_fields(base_url):
    async def go():
        client = Koon("chrome")
        stream = await client.request_streaming("GET", base_url + "/echo")
        total = 0
        while True:
            chunk = await stream.next_chunk()
            if chunk is None:
                break
            total += len(chunk)
        return stream, total

    stream, total = run(go())
    assert stream.status == 200
    assert stream.status_code == 200
    assert isinstance(stream.tls_resumed, bool)
    assert isinstance(stream.connection_reused, bool)
    assert isinstance(stream.request_headers, list)
    assert len(stream.request_headers) > 0
    assert total > 0
    # bytes_received tracks progress per response and stays available after
    # the body is fully read via next_chunk() (unlike after collect(), which
    # consumes the stream).
    assert stream.bytes_received >= total


def test_request_streaming_follows_redirects(base_url):
    async def go():
        client = Koon("chrome")
        stream = await client.request_streaming("GET", base_url + "/redirect")
        body = await stream.collect()
        return stream, body

    stream, body = run(go())
    assert stream.status == 200
    assert json.loads(body.decode())["path"] == "/echo"


# ---------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------


def test_connection_error_is_koon_error(base_url):
    async def go():
        client = Koon("chrome", timeout=2)
        # Nothing listens here (port 1 is a reserved/unused low port).
        return await client.get("http://127.0.0.1:1/")

    with pytest.raises(KoonError) as exc_info:
        run(go())
    err = exc_info.value
    assert isinstance(err.code, str) and err.code
    assert f"[{err.code}]" in str(err)


def test_stream_consumed_twice_raises_koon_error(base_url):
    async def go():
        client = Koon("chrome")
        stream = await client.request_streaming("GET", base_url + "/echo")
        await stream.collect()
        await stream.collect()

    with pytest.raises(KoonError) as exc_info:
        run(go())
    assert exc_info.value.code == "BODY_ERROR"


def test_stream_read_after_collect_is_body_error(base_url):
    async def go():
        stream = await Koon("chrome").request_streaming("GET", base_url + "/echo")
        await stream.collect()
        await stream.next_chunk()

    with pytest.raises(KoonError) as exc_info:
        run(go())
    assert exc_info.value.code == "BODY_ERROR"


def test_max_response_body_caps_the_response(base_url):
    body = "x" * 2000

    async def over_the_cap():
        return await Koon("chrome", max_response_body=100).post(base_url + "/echo", body)

    with pytest.raises(KoonError) as exc_info:
        run(over_the_cap())
    assert exc_info.value.code == "BODY_ERROR"
    assert "100 bytes" in str(exc_info.value)

    async def default_cap():
        return await Koon("chrome").post(base_url + "/echo", body)

    assert run(default_cap()).status == 200

    async def disabled():
        return await Koon("chrome", max_response_body=0).post(base_url + "/echo", body)

    assert run(disabled()).status == 200


def test_max_response_body_rejects_negative_values():
    with pytest.raises(KoonInvalidArgument):
        Koon("chrome", max_response_body=-1)


def test_server_padding_rejects_bad_values():
    with pytest.raises(KoonInvalidArgument):
        Koon("chrome", server_padding="bogus")
    assert isinstance(Koon("chrome", server_padding="none"), Koon)
    assert isinstance(Koon("chrome", server_padding="9000"), Koon)


def _client_hello_extension_types(record: bytes) -> list[int]:
    """The extension types (in order) of a raw TLS 1.3 ClientHello record."""
    p = 5 + 4 + 2 + 32  # record header, handshake header, legacy_version, random
    p += 1 + record[p]  # session_id
    p += 2 + int.from_bytes(record[p : p + 2], "big")  # cipher_suites
    p += 1 + record[p]  # compression_methods
    end = p + 2 + int.from_bytes(record[p : p + 2], "big")
    p += 2
    types = []
    while p < end:
        types.append(int.from_bytes(record[p : p + 2], "big"))
        length = int.from_bytes(record[p + 2 : p + 4], "big")
        p += 4 + length
    return types


def _capture_client_hello(**options) -> list[int]:
    """The extension types of the first TLS record koon sends when told to connect to a
    plain TCP listener (no real TLS): no handshake response ever arrives, so the request
    itself always fails -- only the raw bytes it sent are of interest."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    try:

        async def go():
            client = Koon(ignore_tls_errors=True, timeout=0.3, **options)
            try:
                await client.get(f"https://127.0.0.1:{port}/")
            except KoonError:
                pass

        conn = [None]

        def accept():
            conn[0], _ = listener.accept()

        acceptor = threading.Thread(target=accept, daemon=True)
        acceptor.start()
        run(go())
        acceptor.join(timeout=2)
        assert conn[0] is not None, "koon never connected"
        with conn[0]:
            conn[0].settimeout(5)
            data = b""
            while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], "big"):
                chunk = conn[0].recv(4096)
                if not chunk:
                    break
                data += chunk
            record_len = 5 + int.from_bytes(data[3:5], "big")
            return _client_hello_extension_types(data[:record_len])
    finally:
        listener.close()


def test_server_padding_removes_the_extension():
    SERVER_PADDING = 0x12E0
    with_none = _capture_client_hello(browser="chrome153", server_padding="none")
    assert SERVER_PADDING not in with_none
    with_bytes = _capture_client_hello(browser="chrome153", server_padding="9000")
    assert SERVER_PADDING in with_bytes
    # Firefox does not run this trial: unaffected either way.
    firefox = _capture_client_hello(browser="firefox156", server_padding="9000")
    assert SERVER_PADDING not in firefox


def test_async_verbs_are_coroutines(base_url):
    """The verbs are coroutines, so they can be created outside a running
    event loop and passed to asyncio.run() directly."""
    resp = asyncio.run(Koon("chrome").get(base_url + "/echo"))
    assert resp.status == 200


def test_shutdown_is_awaitable_and_the_client_stays_usable(base_url):
    async def main():
        client = Koon("chrome")
        assert (await client.get(base_url + "/echo")).status == 200
        assert await client.shutdown() is None
        assert (await client.get(base_url + "/echo")).status == 200
        await client.shutdown()

    run(main())


def test_koonsync_shutdown_blocks_and_close_does_not(base_url):
    client = KoonSync("chrome")
    assert client.get(base_url + "/echo").status == 200
    assert client.shutdown() is None
    assert client.get(base_url + "/echo").status == 200
    assert client.close() is None
    assert client.get(base_url + "/echo").status == 200
    # close() is the native, non-blocking one, as for Koon and in Node.
    assert KoonSync.close is koon._Client.close
    assert Koon.close is koon._Client.close


class RecordingKoon(Koon):
    __slots__ = ()
    shutdowns = []

    async def shutdown(self):
        RecordingKoon.shutdowns.append(self)
        await super().shutdown()


class RecordingKoonSync(KoonSync):
    __slots__ = ()
    shutdowns = []

    def shutdown(self):
        RecordingKoonSync.shutdowns.append(self)
        super().shutdown()


def test_async_with_shuts_the_client_down(base_url):
    async def go():
        async with RecordingKoon("chrome") as client:
            assert isinstance(client, RecordingKoon)
            status = (await client.get(base_url + "/echo")).status
        return client, status

    client, status = run(go())
    assert status == 200
    assert RecordingKoon.shutdowns == [client]

    async def failing():
        async with RecordingKoon("chrome"):
            raise LookupError("inside")

    with pytest.raises(LookupError):
        run(failing())
    assert len(RecordingKoon.shutdowns) == 2


def test_with_shuts_the_sync_client_down(base_url):
    with RecordingKoonSync("chrome") as client:
        assert client.get(base_url + "/echo").status == 200
    assert RecordingKoonSync.shutdowns == [client]
    # Still usable afterwards, like after shutdown().
    assert client.get(base_url + "/echo").status == 200


# ---------------------------------------------------------------------
# Errors and argument validation
# ---------------------------------------------------------------------


def test_koon_error_survives_pickle(base_url):
    """Errors raised in multiprocessing/ProcessPoolExecutor workers are
    pickled back to the parent, which needs `koon.KoonError` to resolve."""
    client = KoonSync("chrome")
    with pytest.raises(KoonError) as exc_info:
        client.get(base_url + "/slow", timeout=0.2)
    err = exc_info.value
    assert type(err).__module__ == "koon"

    restored = pickle.loads(pickle.dumps(err))
    assert type(restored) is KoonError
    assert restored.code == "TIMEOUT"
    assert str(restored) == str(err)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1.0, 1e300])
def test_invalid_timeout_is_koon_error_not_panic(base_url, timeout):
    """`Duration::from_secs_f64` panics on these; a PanicException is a
    BaseException and would escape `except Exception`."""
    client = KoonSync("chrome")
    with pytest.raises(KoonInvalidArgument) as exc_info:
        client.get(base_url + "/echo", timeout=timeout)
    assert exc_info.value.code == "INVALID_ARGUMENT"

    async def go():
        await Koon("chrome").get(base_url + "/echo", timeout=timeout)

    with pytest.raises(KoonInvalidArgument) as exc_info:
        run(go())
    assert exc_info.value.code == "INVALID_ARGUMENT"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"browser": "netscape"},
        {"browser": "chrome1"},
        {"ip_version": 5},
        {"ip_version": 300},
        {"doh": "quad9"},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"max_redirects": -1},
        {"max_redirects": 2**40},
        {"retries": -1},
        {"local_address": "nope"},
        {"resolve": ["example.com:443"]},
        {"profile_json": None, "resolve": ["example.com:443:localhost"]},
    ],
    ids=[
        "unknown-browser",
        "unknown-version",
        "ip-version",
        "ip-version-overflow",
        "doh-provider",
        "negative-timeout",
        "nan-timeout",
        "negative-max-redirects",
        "huge-max-redirects",
        "negative-retries",
        "local-address",
        "resolve-without-address",
        "resolve-with-a-name",
    ],
)
def test_invalid_client_options_are_invalid_argument(kwargs):
    with pytest.raises(KoonInvalidArgument) as exc_info:
        KoonSync(**kwargs)
    assert exc_info.value.code == "INVALID_ARGUMENT"
    assert isinstance(exc_info.value, ValueError)


def test_malformed_profile_json_is_json_error():
    with pytest.raises(KoonError) as exc_info:
        KoonSync(profile_json="{")
    assert exc_info.value.code == "JSON_ERROR"


@pytest.mark.parametrize("kwargs", [{"timeout": "soon"}, {"max_redirects": 1.5}, {"retries": "2"}])
def test_option_of_the_wrong_type_is_a_type_error(kwargs):
    with pytest.raises(TypeError):
        KoonSync(**kwargs)


def test_client_timeout_takes_fractions_and_none(base_url):
    start = time.monotonic()
    with pytest.raises(KoonError) as exc_info:
        KoonSync("chrome", timeout=0.3).get(base_url + "/slow")
    assert exc_info.value.code == "TIMEOUT"
    assert time.monotonic() - start < 1.4
    # None keeps the default (30 s), as an unset timeout does in Node and R.
    assert KoonSync("chrome", timeout=None).get(base_url + "/echo").status == 200
    assert KoonSync("chrome", timeout=2.5, max_redirects=0, retries=1).get(
        base_url + "/echo"
    ).status == 200


def test_proxy_start_takes_fractional_timeouts(tmp_path):
    async def go(**kwargs):
        proxy = await KoonProxy.start(ca_dir=str(tmp_path), **kwargs)
        await proxy.shutdown()

    run(go(timeout=2.5, resolve=["example.com:443:127.0.0.1"]))
    for kwargs in ({"timeout": -1}, {"retries": -1}, {"ip_version": 7}, {"local_address": "x"}):
        with pytest.raises(KoonInvalidArgument):
            run(go(**kwargs))


def test_local_address_accepts_strings_and_ipaddress_objects(base_url):
    import ipaddress

    for address in ("127.0.0.1", ipaddress.ip_address("127.0.0.1")):
        assert KoonSync("chrome", local_address=address).get(base_url + "/echo").status == 200


def test_resolve_connects_to_the_given_address(base_url):
    port = base_url.rsplit(":", 1)[1]
    client = KoonSync("chrome", resolve=[f"koon.test:{port}:127.0.0.1"])
    resp = client.get(f"http://koon.test:{port}/echo")
    assert resp.status == 200
    assert ("Host", f"koon.test:{port}") in [tuple(h) for h in resp.json()["headers"]]


def test_browsers_lists_every_profile():
    names = koon.browsers()
    assert isinstance(names, list) and len(names) > 200
    assert "chrome131-windows" in names and "okhttp5" in names
    assert len(set(names)) == len(names)
    for name in names[::25]:
        assert KoonSync(name).user_agent


def test_invalid_argument_is_a_value_error_and_pickles():
    """These errors are ValueErrors, so `except ValueError` catches them,
    and KoonErrors with a code as well."""
    try:
        KoonSync("netscape")
    except ValueError as e:
        err = e
    assert isinstance(err, ValueError)
    assert isinstance(err, KoonError)
    assert err.code == "INVALID_ARGUMENT"

    restored = pickle.loads(pickle.dumps(err))
    assert type(restored) is KoonInvalidArgument
    assert restored.code == "INVALID_ARGUMENT"
    assert str(restored) == str(err)


@pytest.mark.parametrize(
    "kwargs",
    [{"blocking": True}, {"stream": True}, {"mode": None}, {"form": []}, {"body": b"x"}, {"timout": 1}],
    ids=["blocking", "stream", "mode", "form", "body", "typo"],
)
def test_verbs_reject_private_and_unknown_keywords(base_url, kwargs):
    """The verbs forward **options to the native `_request`; its private
    parameters must not be reachable that way, and typos must not pass."""
    with pytest.raises(TypeError):
        KoonSync("chrome").get(base_url + "/echo", **kwargs)

    async def go():
        await Koon("chrome").get(base_url + "/echo", **kwargs)

    with pytest.raises(TypeError):
        run(go())


def test_doh_provider_is_case_insensitive():
    KoonSync("chrome", doh="CloudFlare").close()


def test_invalid_method_is_invalid_argument(base_url):
    with pytest.raises(KoonInvalidArgument) as exc_info:
        KoonSync("chrome").request("BAD METHOD", base_url + "/echo")
    assert exc_info.value.code == "INVALID_ARGUMENT"


def test_proxy_header_mode_typo_is_rejected(tmp_path):
    """A typo is rejected instead of falling back to "impersonate"."""

    async def go():
        await KoonProxy.start(header_mode="passthru", ca_dir=str(tmp_path))

    with pytest.raises(KoonInvalidArgument) as exc_info:
        run(go())
    assert exc_info.value.code == "INVALID_ARGUMENT"


def test_proxy_start_and_shutdown(tmp_path):
    async def go():
        proxy = await KoonProxy.start(header_mode="Passthrough", ca_dir=str(tmp_path))
        try:
            assert proxy.port > 0
            assert proxy.url.endswith(f":{proxy.port}")
            assert proxy.ca_cert_pem().startswith(b"-----BEGIN CERTIFICATE-----")
        finally:
            await proxy.shutdown()
        return proxy

    proxy = run(go())
    assert proxy.ca_cert_pem()  # cached, still available after shutdown


# ---------------------------------------------------------------------
# Header inputs
# ---------------------------------------------------------------------


class CaseInsensitiveHeaders(collections.abc.Mapping):
    """A mapping that is not a dict, like httpx.Headers or requests'
    CaseInsensitiveDict. Iterating it yields keys only."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def __getitem__(self, key):
        for name, value in self._pairs:
            if name.lower() == key.lower():
                return value
        raise KeyError(key)

    def __iter__(self):
        return (name for name, _ in self._pairs)

    def __len__(self):
        return len(self._pairs)


@pytest.mark.parametrize(
    "headers",
    [
        types.MappingProxyType({"X-First": "a", "X-Second": "b"}),
        CaseInsensitiveHeaders([("X-First", "a"), ("X-Second", "b")]),
    ],
    ids=["mappingproxy", "custom-mapping"],
)
def test_any_mapping_is_accepted_as_headers(base_url, headers):
    client = KoonSync("chrome", headers=headers)
    resp = client.get(base_url + "/echo", headers=headers)
    sent = resp.request_headers
    first, second = find(sent, "x-first"), find(sent, "x-second")
    assert first != -1 and second != -1 and first < second
    assert sent[first][1] == "a"
    client.close()


# ---------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------


@pytest.fixture
def counting_url():
    """A server that counts its requests: `/redirect` goes to `/target`."""
    paths = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            paths.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/target")
            else:
                self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", paths
    finally:
        server.shutdown()
        server.server_close()


def test_a_raising_hook_fails_the_request_with_its_exception(counting_url):
    """Like httpx event hooks: the exception a hook raises is what the
    request raises. A raising on_request sends nothing, a raising
    on_redirect does not follow."""
    base, paths = counting_url
    boom = ValueError("request hook")

    def on_request(method, url):
        raise boom

    with pytest.raises(ValueError) as exc_info:
        KoonSync("chrome").get(base + "/", on_request=on_request)
    assert exc_info.value is boom
    with pytest.raises(ValueError) as exc_info:
        KoonSync("chrome", on_request=on_request).get(base + "/")
    assert exc_info.value is boom
    assert paths == []

    class Custom(Exception):
        pass

    def on_response(status, url, headers):
        raise Custom(status)

    async def go(path, **hooks):
        return await Koon("chrome").get(base + path, **hooks)

    with pytest.raises(Custom) as exc_info:
        run(go("/", on_response=on_response))
    assert exc_info.value.args == (200,)
    assert paths == ["/"]

    def on_redirect(status, url, headers):
        raise LookupError(url)

    with pytest.raises(LookupError):
        run(go("/redirect", on_redirect=on_redirect))
    assert paths == ["/", "/redirect"]

    async def stream():
        return await Koon("chrome", on_response=on_response).request_streaming(
            "GET", base + "/"
        )

    with pytest.raises(Custom):
        run(stream())

    # A KeyboardInterrupt-like BaseException passes through as well.
    def interrupt(method, url):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        KoonSync("chrome").get(base + "/", on_request=interrupt)


def test_on_response_receives_headers_as_pairs(base_url):
    seen = []
    client = KoonSync(
        "chrome", on_response=lambda status, url, headers: seen.append((status, headers))
    )
    client.get(base_url + "/echo")
    status, headers = seen[0]
    assert status == 200
    assert isinstance(headers, list)
    assert ("content-type", "application/json") in headers


# ---------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------


def test_response_body_and_text_are_built_once(base_url):
    resp = KoonSync("chrome").get(base_url + "/echo")
    assert resp.body is resp.body
    assert resp.text is resp.text
    assert resp.headers is resp.headers
    assert resp.request_headers is resp.request_headers
    assert isinstance(resp.headers, list) and isinstance(resp.headers[0], tuple)
    assert json.loads(resp.body) == resp.json()
    assert resp.header("CONTENT-TYPE") == "application/json"
    assert resp.content_type == "application/json"
    assert resp.header("x-missing") is None


def test_multipart_file_field_with_empty_data_stays_a_file(base_url):
    """An empty file with an empty content type is still a file field, not
    a text field."""
    resp = KoonSync("chrome").post_multipart(
        base_url + "/echo",
        [
            {"name": "upload", "file_data": b"", "content_type": ""},
            {"name": "note", "value": "hi"},
        ],
    )
    body = json.loads(resp.text)["body"]
    assert 'name="upload"; filename="file"' in body
    assert 'name="note"\r\n\r\nhi' in body


@pytest.mark.parametrize(
    "field", [{"name": "empty"}, {"value": "no name"}], ids=["no-value", "no-name"]
)
def test_invalid_multipart_field_is_invalid_argument(base_url, field):
    with pytest.raises(KoonInvalidArgument) as exc_info:
        KoonSync("chrome").post_multipart(base_url + "/echo", [field])
    assert exc_info.value.code == "INVALID_ARGUMENT"


def test_streaming_bytes_received_after_collect(base_url):
    """bytes_received counts the head plus every body byte read, also after
    collect()."""

    async def go():
        stream = await Koon("chrome").request_streaming("GET", base_url + "/echo")
        head = stream.bytes_received
        body = await stream.collect()
        return head, stream.bytes_received, len(body)

    head, after, body_len = run(go())
    assert head > 0
    assert after == head + body_len


def test_streaming_async_iteration(base_url):
    async def go():
        stream = await Koon("chrome").request_streaming("GET", base_url + "/echo")
        assert stream.headers is stream.headers
        assert stream.request_headers is stream.request_headers
        return b"".join([chunk async for chunk in stream])

    assert json.loads(run(go()))["path"] == "/echo"


# ---------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------


def test_websocket_text_and_binary_roundtrip(ws_url):
    async def go():
        async with await Koon("chrome").websocket(ws_url) as ws:
            await ws.send("hello")
            text = await ws.receive()
            await ws.send(b"\x00\x01\xff")
            binary = await ws.receive()
            return text, binary

    text, binary = run(go())
    assert text == {"type": "text", "data": "hello"}
    assert binary == {"type": "binary", "data": b"\x00\x01\xff"}


def test_websocket_close_code_out_of_range_is_invalid_argument(ws_url):
    async def go():
        ws = await Koon("chrome").websocket(ws_url)
        try:
            await ws.close(70000)
        finally:
            await ws.close()

    with pytest.raises(KoonInvalidArgument):
        run(go())


def test_websocket_send_rejects_other_types(ws_url):
    async def go():
        ws = await Koon("chrome").websocket(ws_url)
        try:
            await ws.send(42)
        finally:
            await ws.close()

    with pytest.raises(TypeError):
        run(go())


def test_version_is_the_installed_distributions():
    from importlib.metadata import version

    assert koon.__version__ == version("koon")
