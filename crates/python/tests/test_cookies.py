"""Tests for set_cookies()/cookies(): Playwright/CDP-compatible round-trip,
and the report of the cookies set_cookies() skips."""

import json

import pytest

from koon import Koon, KoonError, KoonInvalidArgument, KoonSync


def test_cookie_jar_stores_set_cookie_and_sends_it_back(base_url):
    """End-to-end: a Set-Cookie response header is stored automatically and
    sent back as a Cookie header on the next request to the same origin."""
    client = KoonSync("chrome")
    resp = client.get(base_url + "/set-cookie")
    assert resp.status == 200

    resp2 = client.get(base_url + "/echo")
    payload = json.loads(resp2.text)
    received = {n.lower(): v for n, v in payload["headers"]}
    assert "cookie" in received
    assert "sid=abc123" in received["cookie"]
    client.close()


def test_set_and_get_cookies_roundtrip():
    client = KoonSync("chrome")
    skipped = client.set_cookies(
        [
            {
                "name": "sid",
                "value": "abc123",
                "domain": "example.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
            }
        ]
    )
    assert skipped == []
    cookies = client.cookies()
    assert len(cookies) == 1
    c = cookies[0]
    assert c["name"] == "sid"
    assert c["value"] == "abc123"
    assert c["domain"] == "example.com"
    assert c["path"] == "/"
    assert c["secure"] is True
    assert c["httpOnly"] is True
    assert c["sameSite"] == "Lax"
    assert c["expires"] == -1  # session cookie
    assert "hostOnly" in c

    # The exact shape returned by cookies() must feed straight back in.
    client.set_cookies(cookies)
    assert len(client.cookies()) == 1
    client.close()


def test_cookie_from_url_is_host_only():
    client = KoonSync("chrome")
    client.set_cookies(
        [{"name": "a", "value": "1", "url": "https://example.com/path/page"}]
    )
    cookies = client.cookies()
    assert len(cookies) == 1
    assert cookies[0]["domain"] == "example.com"
    assert cookies[0]["hostOnly"] is True
    client.close()


def test_cookie_from_url_takes_path_and_secure_from_the_url():
    """Playwright semantics: the path is the URL path up to its last '/',
    and the scheme decides `secure` (an explicit `secure` is ignored)."""
    client = KoonSync("chrome")
    client.set_cookies(
        [
            {"name": "a", "value": "1", "url": "https://Example.com/dir/page?q=1"},
            {"name": "b", "value": "2", "url": "http://example.org", "secure": True},
        ]
    )
    by_name = {c["name"]: c for c in client.cookies()}
    assert by_name["a"]["domain"] == "example.com"
    assert by_name["a"]["path"] == "/dir/"
    assert by_name["a"]["secure"] is True
    assert by_name["a"]["hostOnly"] is True
    assert by_name["b"]["path"] == "/"
    assert by_name["b"]["secure"] is False
    client.close()


def test_leading_dot_domain_means_domain_cookie_and_is_exported_with_dot():
    client = KoonSync("chrome")
    client.set_cookies([{"name": "a", "value": "1", "domain": ".example.com"}])
    cookies = client.cookies()
    assert cookies[0]["hostOnly"] is False
    assert cookies[0]["domain"] == ".example.com"

    # The export feeds back in and stays a domain cookie.
    other = KoonSync("chrome")
    other.set_cookies([{k: v for k, v in cookies[0].items() if k != "hostOnly"}])
    assert other.cookies() == cookies
    client.close()
    other.close()


@pytest.mark.parametrize("missing", ["name", "value"])
def test_cookie_without_required_key_is_invalid_argument(missing):
    cookie = {"name": "a", "value": "1", "domain": "example.com"}
    del cookie[missing]
    client = KoonSync("chrome")
    with pytest.raises(KoonInvalidArgument) as exc_info:
        client.set_cookies([{"name": "ok", "value": "1", "domain": "example.com"}, cookie])
    assert exc_info.value.code == "INVALID_ARGUMENT"
    assert f"cookie 1 is missing the required key '{missing}'" in str(exc_info.value)
    assert client.cookies() == []  # atomic
    client.close()


@pytest.mark.parametrize(
    "cookie",
    [
        {"name": "a", "value": "1", "domain": "example.com", "expires": float("nan")},
        {"name": "a", "value": "1", "domain": "example.com", "expires": float("inf")},
        {"name": "a", "value": "1", "domain": "example.com", "expires": -5},
        {"name": "a", "value": "1", "url": "https://example.com/", "domain": "example.com"},
        {"name": "a", "value": "1", "url": "https://example.com/", "path": "/x"},
    ],
    ids=["nan-expires", "inf-expires", "negative-expires", "url-and-domain", "url-and-path"],
)
def test_invalid_cookie_params_are_skipped_and_reported(cookie):
    client = KoonSync("chrome")
    skipped = client.set_cookies([{"name": "ok", "value": "1", "domain": "example.com"}, cookie])
    assert [(s["index"], s["name"]) for s in skipped] == [(1, "a")]
    assert isinstance(skipped[0]["reason"], str) and skipped[0]["reason"]
    assert [c["name"] for c in client.cookies()] == ["ok"]
    client.close()


def test_explicit_host_only_overrides_dot_heuristic():
    client = KoonSync("chrome")
    client.set_cookies(
        [{"name": "a", "value": "1", "domain": ".example.com", "hostOnly": True}]
    )
    cookies = client.cookies()
    assert cookies[0]["hostOnly"] is True
    client.close()


def test_expires_minus_one_is_session_cookie():
    client = KoonSync("chrome")
    client.set_cookies(
        [{"name": "a", "value": "1", "domain": "example.com", "expires": -1}]
    )
    assert client.cookies()[0]["expires"] == -1
    client.close()


def test_expires_future_timestamp_kept():
    client = KoonSync("chrome")
    far_future = 4102444800.0  # 2100-01-01
    client.set_cookies(
        [{"name": "a", "value": "1", "domain": "example.com", "expires": far_future}]
    )
    assert client.cookies()[0]["expires"] == pytest.approx(far_future)
    client.close()


def test_missing_domain_and_url_skips_the_cookie():
    client = KoonSync("chrome")
    skipped = client.set_cookies([{"name": "a", "value": "1"}])
    assert [(s["index"], s["name"]) for s in skipped] == [(0, "a")]
    assert "url or a domain" in skipped[0]["reason"]
    assert client.cookies() == []
    client.close()


def test_partitioned_cookie_is_skipped():
    """Browsers send partitioned (CHIPS) cookies only in a third-party
    context, so a full browser export imports without them."""
    client = KoonSync("chrome")
    skipped = client.set_cookies(
        [
            {"name": "kept", "value": "1", "domain": "example.com"},
            {
                "name": "a",
                "value": "1",
                "domain": "example.com",
                "partitionKey": {"topLevelSite": "https://example.com"},
            },
        ]
    )
    assert [c["name"] for c in client.cookies()] == ["kept"]
    assert [(s["index"], s["name"]) for s in skipped] == [(1, "a")]
    assert "partitioned" in skipped[0]["reason"]
    client.close()


def test_opaque_partition_key_is_skipped():
    """CDP marks a cookie with an opaque partition key by
    partitionKeyOpaque, as the Node binding reads it."""
    client = KoonSync("chrome")
    skipped = client.set_cookies(
        [
            {"name": "kept", "value": "v", "domain": "example.com", "partitionKeyOpaque": False},
            {"name": "opaque", "value": "v", "domain": "example.com", "partitionKeyOpaque": True},
        ]
    )
    assert [c["name"] for c in client.cookies()] == ["kept"]
    assert [(s["index"], s["name"]) for s in skipped] == [(1, "opaque")]
    assert "partitioned" in skipped[0]["reason"]
    client.close()


def test_partition_key_none_is_accepted():
    """CDP always includes partitionKey, set to None for an ordinary cookie:
    that must not be treated as partitioned."""
    client = KoonSync("chrome")
    client.set_cookies(
        [
            {
                "name": "a",
                "value": "1",
                "domain": "example.com",
                "partitionKey": None,
            }
        ]
    )
    assert len(client.cookies()) == 1
    client.close()


def test_one_invalid_cookie_does_not_cost_the_others():
    client = KoonSync("chrome")
    skipped = client.set_cookies(
        [
            {"name": "good", "value": "1", "domain": "example.com"},
            {"name": "bad", "value": "1"},  # no domain/url
            {"name": "also-good", "value": "2", "domain": "example.com"},
        ]
    )
    assert [s["index"] for s in skipped] == [1]
    assert sorted(c["name"] for c in client.cookies()) == ["also-good", "good"]
    client.close()


def test_invalid_same_site_value_skips_the_cookie():
    client = KoonSync("chrome")
    skipped = client.set_cookies(
        [{"name": "a", "value": "1", "domain": "example.com", "sameSite": "bogus"}]
    )
    assert "sameSite" in skipped[0]["reason"]
    assert client.cookies() == []
    client.close()


def test_same_site_case_insensitive():
    client = KoonSync("chrome")
    client.set_cookies(
        [{"name": "a", "value": "1", "domain": "example.com", "sameSite": "sTrIcT"}]
    )
    assert client.cookies()[0]["sameSite"] == "Strict"
    client.close()


def test_cookies_work_on_async_client_too():
    async def go():
        client = Koon("chrome")
        assert client.set_cookies([{"name": "a", "value": "1", "domain": "example.com"}]) == []
        return client.cookies()

    import asyncio

    cookies = asyncio.run(go())
    assert len(cookies) == 1
    assert cookies[0]["name"] == "a"


def test_cookie_jar_disabled_raises_on_set():
    client = KoonSync("chrome", cookie_jar=False)
    with pytest.raises(KoonError) as exc_info:
        client.set_cookies([{"name": "a", "value": "1", "domain": "example.com"}])
    assert exc_info.value.code == "COOKIE_JAR_DISABLED"
    client.close()
