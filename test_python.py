"""Unified koon test suite — Python bindings."""
import asyncio
import json
import os
import tempfile

PASS = 0
FAIL = 0

def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}" + (f"  ({detail})" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f"  ({detail})" if detail else ""))

async def main():
    from koon import Koon

    print("=== koon Python Test Suite ===\n")

    # --- 1. Browser profiles GET ---
    print("[Browsers]")

    chrome = Koon("chrome145")
    r = await chrome.get("https://www.google.com")
    ok("1. Chrome 145 GET google.com", r.status == 200, f"{r.status} {r.version} {len(r.body)}b")

    firefox = Koon("firefox147")
    r = await firefox.get("https://www.cloudflare.com")
    ok("2. Firefox 147 GET cloudflare.com", r.status == 200, f"{r.status} {r.version} {len(r.body)}b")

    safari = Koon("safari18.3")
    r = await safari.get("https://www.amazon.com")
    ok("3. Safari 18.3 GET amazon.com", r.status in (200, 202, 503), f"{r.status} {r.version} {len(r.body)}b")

    edge = Koon("edge145")
    r = await edge.get("https://www.nike.com")
    ok("4. Edge 145 GET nike.com", r.status == 200, f"{r.status} {r.version} {len(r.body)}b")

    opera = Koon("opera127")
    r = await opera.get("https://httpbin.org/get")
    ok("5. Opera 127 GET httpbin.org", r.status == 200, f"{r.status} {r.version}")

    # --- 2. HTTP methods ---
    print("\n[HTTP Methods]")

    r = await chrome.post("https://httpbin.org/post", b"hello from python")
    j = r.json()
    ok("6. POST with body", r.status == 200 and j["data"] == "hello from python", f'echo: "{j["data"]}"')

    r = await chrome.put("https://httpbin.org/put", b"put data")
    ok("7. PUT with body", r.status == 200, f"{r.status}")

    r = await chrome.delete("https://httpbin.org/delete")
    ok("8. DELETE", r.status == 200, f"{r.status}")

    r = await chrome.patch("https://httpbin.org/patch", b"patch data")
    ok("9. PATCH with body", r.status == 200, f"{r.status}")

    r = await chrome.head("https://httpbin.org/get")
    ok("10. HEAD", r.status == 200 and len(r.body) == 0, f"{r.status} body={len(r.body)}b")

    # --- 3. Features ---
    print("\n[Features]")

    custom = Koon("chrome145", headers={"X-Koon-Test": "python-binding"})
    r = await custom.get("https://httpbin.org/headers")
    j = r.json()
    ok("11. Custom headers", "python-binding" in json.dumps(j["headers"]))

    await chrome.get("https://httpbin.org/cookies/set/pytest/pyvalue")
    r = await chrome.get("https://httpbin.org/cookies")
    j = r.json()
    ok("12. Cookie persistence", j["cookies"].get("pytest") == "pyvalue", f'{j["cookies"]}')

    session = chrome.save_session()
    ok("13. Session save", "cookies" in session and "pytest" in session)

    chrome2 = Koon("chrome145")
    chrome2.load_session(session)
    r = await chrome2.get("https://httpbin.org/cookies")
    j = r.json()
    ok("14. Session load", j["cookies"].get("pytest") == "pyvalue")

    tmpfile = os.path.join(tempfile.gettempdir(), "koon_py_test_session.json")
    chrome.save_session_to_file(tmpfile)
    ok("15. Session save to file", os.path.exists(tmpfile))
    chrome3 = Koon("chrome145")
    chrome3.load_session_from_file(tmpfile)
    os.remove(tmpfile)
    r = await chrome3.get("https://httpbin.org/cookies")
    j = r.json()
    ok("16. Session load from file", j["cookies"].get("pytest") == "pyvalue")

    profile = chrome.export_profile()
    ok("17. Profile export", "cipher_list" in profile and "http2" in profile)

    rand = Koon("chrome145", randomize=True)
    r = await rand.get("https://httpbin.org/get")
    ok("18. Randomize", r.status == 200)

    # --- 4. TLS Fingerprint ---
    print("\n[Fingerprint]")

    r = await chrome.get("https://tls.browserleaks.com/json")
    fp = r.json()
    ok("19. Chrome JA3N", fp["ja3n_hash"] == "8e19337e7524d2573be54efb2b0784c9", fp["ja3n_hash"])
    ok("20. Chrome JA4", fp["ja4"] == "t13d1516h2_8daaf6152771_d8a2da3f94cd", fp["ja4"])
    ok("21. Chrome Akamai", fp["akamai_hash"] == "52d84b11737d980aef856699f885ca86", fp["akamai_hash"])

    r = await firefox.get("https://tls.browserleaks.com/json")
    fp = r.json()
    ok("22. Firefox JA3N", fp["ja3n_hash"] == "e4147a4860c1f347354f0a84d8787c02", fp["ja3n_hash"])

    r = await safari.get("https://tls.browserleaks.com/json")
    fp = r.json()
    ok("23. Safari JA3", fp["ja3_hash"] == "773906b0efdefa24a7f2b8eb6985bf37", fp["ja3_hash"])

    # --- 5. Anti-Bot Sites ---
    print("\n[Anti-Bot]")

    r = await chrome.get("https://nowsecure.nl")
    ok("24. nowsecure.nl (Cloudflare)", r.status == 200, f"{r.status}")

    r = await firefox.get("https://www.ticketmaster.com")
    ok("25. ticketmaster.com", r.status == 200, f"{r.status}")

    # --- 6. WebSocket ---
    print("\n[WebSocket]")

    ws = await chrome.websocket("wss://echo.websocket.org")
    welcome = await ws.receive()
    await ws.send("hello from koon python")
    echo = await ws.receive()
    ok("26. WebSocket echo", echo is not None and echo["data"] == "hello from koon python", f'"{echo["data"]}"')
    await ws.close()

    # --- 7. Streaming ---
    print("\n[Streaming]")

    streaming = await chrome.request_streaming("GET", "https://httpbin.org/bytes/5000")
    ok("27. Streaming status", streaming.status == 200, f"{streaming.status} {streaming.version}")
    body = await streaming.collect()
    ok("28. Streaming collect", len(body) == 5000, f"{len(body)} bytes")

    # --- 8. Multipart ---
    print("\n[Multipart]")

    r = await chrome.post_multipart("https://httpbin.org/post", [
        {"name": "field1", "value": "python_test"},
        {"name": "file", "file_data": b"file content here", "filename": "test.txt", "content_type": "text/plain"},
    ])
    j = r.json()
    ok("29. Multipart field", "python_test" in json.dumps(j), f'form={j.get("form", {})}')
    ok("30. Multipart file", "file content here" in json.dumps(j), f'files={j.get("files", {})}')

    # --- Summary ---
    total = PASS + FAIL
    print(f"\n=== Python: {PASS}/{total} passed", end="")
    if FAIL:
        print(f", {FAIL} FAILED ===")
    else:
        print(" ===")

asyncio.run(main())
