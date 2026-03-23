"""Pre-release test: Python async API (Koon)"""
import asyncio, os, sys
passed = failed = skipped = 0

def ok(label, condition):
    global passed, failed
    if condition:
        print(f"  [PASS] {label}")
        passed += 1
    else:
        print(f"  [FAIL] {label}")
        failed += 1

def skip(label):
    global skipped
    print(f"  [SKIP] {label}")
    skipped += 1

async def main():
    global passed, failed
    print("\n=== Python Async (Koon) ===\n")

    from koon import Koon

    # ── Response Properties ────────────────────────────────────────
    print("-- Response Properties --")
    client = Koon("chrome145", timeout=15)
    resp = await client.get("https://httpbin.org/get")
    ok("status=200", resp.status == 200)
    ok("status_code alias", resp.status_code == 200)
    ok("ok is True", resp.ok is True)
    ok("text is string", isinstance(resp.text, str) and "url" in resp.text)
    ok("json() returns dict", isinstance(resp.json(), dict))
    ok("headers is list of tuples", isinstance(resp.headers, list) and len(resp.headers) > 0)
    ok("body is bytes", isinstance(resp.body, bytes) and len(resp.body) > 0)
    ok("content_type", resp.content_type is not None and "json" in resp.content_type)
    ok("bytes_sent > 0", resp.bytes_sent > 0)
    ok("bytes_received > 0", resp.bytes_received > 0)

    # ── Browser Profiles ──────────────────────────────────────────
    print("-- Browser Profiles --")
    for profile in ["chrome145", "firefox148", "safari183"]:
        c = Koon(profile, timeout=15)
        r = await c.get("https://httpbin.org/get")
        ok(f"{profile} GET status=200", r.status == 200)

    # ── HTTP Methods ──────────────────────────────────────────────
    print("-- HTTP Methods --")
    resp = await client.post("https://httpbin.org/post", "async body")
    ok("POST echoes body", "async body" in resp.json().get("data", ""))

    resp = await client.put("https://httpbin.org/put", "put data")
    ok("PUT status=200", resp.status == 200)

    resp = await client.delete("https://httpbin.org/delete")
    ok("DELETE status=200", resp.status == 200)

    resp = await client.head("https://httpbin.org/get")
    ok("HEAD body empty", len(resp.body) == 0)

    # ── Per-Request Headers ───────────────────────────────────────
    print("-- Per-Request Headers --")
    resp = await client.get("https://httpbin.org/headers", headers={"X-Koon-Test": "async456"})
    ok("custom header sent", resp.json().get("headers", {}).get("X-Koon-Test") == "async456")

    # ── Timeout ───────────────────────────────────────────────────
    print("-- Timeout --")
    try:
        await client.get("https://httpbin.org/delay/10", timeout=2)
        ok("timeout triggers", False)
    except Exception as e:
        ok("timeout triggers", "TIMEOUT" in str(e).upper())

    # ── Cookies ───────────────────────────────────────────────────
    print("-- Cookies --")
    await client.get("https://httpbin.org/cookies/set/asynckey/asyncval")
    resp = await client.get("https://httpbin.org/cookies")
    ok("cookie persisted", resp.json().get("cookies", {}).get("asynckey") == "asyncval")

    session = client.save_session()
    client2 = Koon("chrome145", timeout=15)
    client2.load_session(session)
    resp2 = await client2.get("https://httpbin.org/cookies")
    ok("session restore", resp2.json().get("cookies", {}).get("asynckey") == "asyncval")

    # ── Redirect ──────────────────────────────────────────────────
    print("-- Redirect --")
    resp = await client.get("https://httpbin.org/redirect/3")
    ok("redirect followed", resp.status == 200)

    # ── Per-Request Proxy ─────────────────────────────────────────
    print("-- Per-Request Proxy --")
    proxy = os.environ.get("KOON_TEST_PROXY")
    if proxy:
        try:
            resp = await client.get("https://httpbin.org/ip", proxy=proxy)
            ok("per-request proxy works", resp.status == 200)
        except Exception as e:
            ok(f"per-request proxy ({e})", False)
    else:
        skip("per-request proxy (KOON_TEST_PROXY not set)")

    # ── WebSocket ─────────────────────────────────────────────────
    print("-- WebSocket --")
    try:
        ws = await client.websocket("wss://echo.websocket.org")
        await ws.receive()  # skip server greeting
        await ws.send("koon-test")
        msg = await ws.receive()
        ok("websocket echo", msg is not None and msg.get("data") == "koon-test")
        await ws.close()
    except Exception as e:
        ok(f"websocket ({e})", False)

    # ── Streaming ─────────────────────────────────────────────────
    print("-- Streaming --")
    try:
        stream = await client.request_streaming("GET", "https://httpbin.org/bytes/5000")
        body = await stream.collect()
        ok("streaming collect", len(body) == 5000)
    except Exception as e:
        ok(f"streaming ({e})", False)

    # ── WAF Smoke ─────────────────────────────────────────────────
    print("-- WAF Smoke (soft-fail) --")
    for url, name in [("https://nowsecure.nl", "Cloudflare"), ("https://www.nike.com", "Akamai")]:
        try:
            r = await client.get(url)
            if r.status == 200:
                print(f"  [PASS] {name} -> 200")
                passed += 1
            else:
                print(f"  [WARN] {name} -> {r.status}")
        except Exception as e:
            print(f"  [WARN] {name} -> {e}")

asyncio.run(main())

total = passed + failed
print(f"\n=== python-async: {passed}/{total} passed", end="")
if failed:
    print(f", {failed} FAILED", end="")
if skipped:
    print(f", {skipped} skipped", end="")
print(" ===\n")
sys.exit(1 if failed else 0)
