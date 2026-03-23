"""Pre-release test: Python sync API (KoonSync)"""
import os, sys
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

print("\n=== Python Sync (KoonSync) ===\n")

from koon import KoonSync

# ── Section 1: Basic Functionality ─────────────────────────────────
print("-- Basic Functionality --")
client = KoonSync("chrome145", timeout=15)
ok("KoonSync construction", client is not None)

resp = client.get("https://httpbin.org/get")
ok("GET httpbin status=200", resp.status == 200)
ok("status_code alias", resp.status_code == 200)
ok("ok is True", resp.ok is True)
ok("text is string", isinstance(resp.text, str) and "url" in resp.text)
ok("json() returns dict", isinstance(resp.json(), dict))

# ── Section 2: POST ────────────────────────────────────────────────
print("-- POST --")
resp = client.post("https://httpbin.org/post", "sync body test")
ok("POST status=200", resp.status == 200)
data = resp.json()
ok("POST body echoed", "sync body test" in data.get("data", ""))

# ── Section 3: Multiple Profiles ───────────────────────────────────
print("-- Browser Profiles --")
for profile in ["chrome145", "firefox148", "safari183"]:
    c = KoonSync(profile, timeout=15)
    r = c.get("https://httpbin.org/get")
    ok(f"{profile} GET status=200", r.status == 200)
    c.close()

# ── Section 4: Cookies ─────────────────────────────────────────────
print("-- Cookies --")
client.get("https://httpbin.org/cookies/set/testkey/testval")
resp = client.get("https://httpbin.org/cookies")
cookies = resp.json().get("cookies", {})
ok("cookie persisted", cookies.get("testkey") == "testval")

session = client.save_session()
ok("save_session returns string", isinstance(session, str) and len(session) > 10)

client2 = KoonSync("chrome145", timeout=15)
client2.load_session(session)
resp2 = client2.get("https://httpbin.org/cookies")
cookies2 = resp2.json().get("cookies", {})
ok("load_session restores cookies", cookies2.get("testkey") == "testval")
client2.close()

client.clear_cookies()
resp = client.get("https://httpbin.org/cookies")
ok("clear_cookies works", resp.json().get("cookies", {}).get("testkey") is None)

# ── Section 5: Per-Request Headers ─────────────────────────────────
print("-- Per-Request Headers --")
resp = client.get("https://httpbin.org/headers", headers={"X-Koon-Test": "sync123"})
hdrs = resp.json().get("headers", {})
ok("custom header sent", hdrs.get("X-Koon-Test") == "sync123")

# ── Section 6: Redirect ───────────────────────────────────────────
print("-- Redirect --")
resp = client.get("https://httpbin.org/redirect/3")
ok("redirect followed to 200", resp.status == 200 and "redirect" not in resp.url)

# ── Section 7: Multiple Sequential Calls ──────────────────────────
print("-- Sequential Calls (event loop stability) --")
try:
    for i in range(5):
        r = client.get("https://httpbin.org/get")
    ok("5 sequential calls without crash", True)
except Exception as e:
    ok(f"5 sequential calls without crash ({e})", False)

# ── Section 8: Per-Request Proxy ──────────────────────────────────
print("-- Per-Request Proxy --")
proxy = os.environ.get("KOON_TEST_PROXY")
if proxy:
    try:
        resp = client.get("https://httpbin.org/ip", proxy=proxy)
        ok("per-request proxy works", resp.status == 200)
    except Exception as e:
        ok(f"per-request proxy works ({e})", False)
else:
    skip("per-request proxy (KOON_TEST_PROXY not set)")

# ── Section 9: Timeout ────────────────────────────────────────────
print("-- Timeout --")
try:
    client.get("https://httpbin.org/delay/10", timeout=2)
    ok("timeout triggers on slow endpoint", False)
except Exception as e:
    ok("timeout triggers on slow endpoint", "TIMEOUT" in str(e).upper())

# ── Section 10: WAF Smoke ─────────────────────────────────────────
print("-- WAF Smoke (soft-fail) --")
for url, name in [("https://nowsecure.nl", "Cloudflare"), ("https://www.nike.com", "Akamai")]:
    try:
        r = client.get(url)
        if r.status == 200:
            print(f"  [PASS] {name} ({url}) -> 200")
            passed += 1
        else:
            print(f"  [WARN] {name} ({url}) -> {r.status}")
    except Exception as e:
        print(f"  [WARN] {name} ({url}) -> {e}")

# ── Cleanup ────────────────────────────────────────────────────────
client.close()

# ── Summary ────────────────────────────────────────────────────────
total = passed + failed
print(f"\n=== python-sync: {passed}/{total} passed", end="")
if failed:
    print(f", {failed} FAILED", end="")
if skipped:
    print(f", {skipped} skipped", end="")
print(" ===\n")
sys.exit(1 if failed else 0)
