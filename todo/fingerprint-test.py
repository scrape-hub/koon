"""
koon v0.6.2 — Fingerprint Comparison Test
Tests koon vs curl_cffi vs tls-client vs curl against 68 WAF-protected sites.
"""
import subprocess, time, sys

# ─── Site lists ────────────────────────────────────────────────────────
SITES = [
    # Akamai Bot Manager (25)
    ("Akamai", "nike.com"), ("Akamai", "adidas.com"), ("Akamai", "zalando.com"),
    ("Akamai", "footlocker.com"), ("Akamai", "macys.com"), ("Akamai", "costco.com"),
    ("Akamai", "sephora.com"), ("Akamai", "homedepot.com"),
    ("Akamai", "dickssportinggoods.com"), ("Akamai", "mrporter.com"),
    ("Akamai", "finishline.com"), ("Akamai", "lufthansa.com"),
    ("Akamai", "delta.com"), ("Akamai", "united.com"), ("Akamai", "emirates.com"),
    ("Akamai", "marriott.com"), ("Akamai", "airbnb.com"),
    ("Akamai", "capitalone.com"), ("Akamai", "americanexpress.com"),
    ("Akamai", "ups.com"), ("Akamai", "sony.com"), ("Akamai", "ea.com"),
    ("Akamai", "usatoday.com"), ("Akamai", "cnbc.com"), ("Akamai", "bbc.com"),

    # Cloudflare (25)
    ("Cloudflare", "discord.com"), ("Cloudflare", "notion.so"),
    ("Cloudflare", "canva.com"), ("Cloudflare", "medium.com"),
    ("Cloudflare", "stockx.com"), ("Cloudflare", "glassdoor.com"),
    ("Cloudflare", "indeed.com"), ("Cloudflare", "coinbase.com"),
    ("Cloudflare", "shopify.com"), ("Cloudflare", "crunchyroll.com"),
    ("Cloudflare", "npmjs.com"), ("Cloudflare", "priceline.com"),
    ("Cloudflare", "etsy.com"), ("Cloudflare", "wayfair.com"),
    ("Cloudflare", "g2.com"), ("Cloudflare", "zendesk.com"),
    ("Cloudflare", "hubspot.com"), ("Cloudflare", "gitlab.com"),
    ("Cloudflare", "figma.com"), ("Cloudflare", "linear.app"),
    ("Cloudflare", "kraken.com"), ("Cloudflare", "depop.com"),
    ("Cloudflare", "soundcloud.com"), ("Cloudflare", "reddit.com"),
    ("Cloudflare", "nowsecure.nl"),

    # Kasada (5)
    ("Kasada", "twitch.tv"), ("Kasada", "kick.com"),
    ("Kasada", "canadagoose.com"), ("Kasada", "playstation.com"),
    ("Kasada", "hyatt.com"),

    # DataDome (5)
    ("DataDome", "tripadvisor.com"), ("DataDome", "vinted.com"),
    ("DataDome", "deezer.com"), ("DataDome", "hermes.com"),
    ("DataDome", "patreon.com"),

    # Imperva (5)
    ("Imperva", "gamestop.com"), ("Imperva", "walmart.com"),
    ("Imperva", "westernunion.com"), ("Imperva", "hsbc.com"),
    ("Imperva", "seatgeek.com"),

    # Shape/F5 (3)
    ("Shape/F5", "nordstrom.com"), ("Shape/F5", "starbucks.com"),
    ("Shape/F5", "southwest.com"),
]


# ─── Test functions ────────────────────────────────────────────────────
def test_curl(url):
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "-L", url],
            capture_output=True, text=True, timeout=20
        )
        return int(r.stdout.strip()) if r.stdout.strip().isdigit() else "ERR"
    except Exception:
        return "ERR"


def test_curl_cffi(session, url):
    try:
        r = session.get(url, timeout=15, allow_redirects=True)
        return r.status_code
    except Exception:
        return "ERR"


def test_tls_client(session, url):
    try:
        r = session.get(url, timeout_seconds=15, allow_redirects=True)
        return r.status_code
    except Exception:
        return "ERR"


def test_koon(client, url):
    try:
        r = client.get(url)
        return r.status
    except Exception as e:
        if "TIMEOUT" in str(e):
            return "T/O"
        return "ERR"


# ─── Setup clients ─────────────────────────────────────────────────────
from curl_cffi.requests import Session as CffiSession
import tls_client
from koon import KoonSync

cffi_chrome = CffiSession(impersonate="chrome")
cffi_firefox = CffiSession(impersonate="firefox")

tlsc = tls_client.Session(client_identifier="chrome_131", random_tls_extension_order=True)

koon_chrome = KoonSync("chrome145", timeout=15)
koon_firefox = KoonSync("firefox148", timeout=15)
koon_safari = KoonSync("safari183", timeout=15)

TOOLS = [
    ("curl",          lambda url: test_curl(url)),
    ("cffi_chrome",   lambda url: test_curl_cffi(cffi_chrome, url)),
    ("cffi_firefox",  lambda url: test_curl_cffi(cffi_firefox, url)),
    ("tls_client",    lambda url: test_tls_client(tlsc, url)),
    ("koon_chrome",   lambda url: test_koon(koon_chrome, url)),
    ("koon_firefox",  lambda url: test_koon(koon_firefox, url)),
    ("koon_safari",   lambda url: test_koon(koon_safari, url)),
]

# ─── Run tests ─────────────────────────────────────────────────────────
tool_names = [t[0] for t in TOOLS]
header = "WAF".ljust(12) + "Site".ljust(28) + "".join(t.ljust(14) for t in tool_names)
print(f"\nTesting {len(SITES)} sites × {len(TOOLS)} tools = {len(SITES)*len(TOOLS)} requests\n")
print(header)
print("-" * len(header))

results = []
start = time.time()

for waf, domain in SITES:
    url = f"https://{domain}"
    row = {"waf": waf, "domain": domain}

    for name, fn in TOOLS:
        row[name] = fn(url)

    line = waf.ljust(12) + domain.ljust(28)
    for name in tool_names:
        s = row[name]
        if s == 200:
            line += f"\033[32m{s}\033[0m".ljust(14 + 9)
        elif s == 403:
            line += f"\033[31m{s}\033[0m".ljust(14 + 9)
        else:
            line += f"\033[33m{s}\033[0m".ljust(14 + 9)
    print(line)
    results.append(row)

elapsed = time.time() - start
print(f"\nDone in {elapsed:.0f}s\n")

# ─── Summary ───────────────────────────────────────────────────────────
wafs = list(dict.fromkeys(w for w, _ in SITES))
print("═" * 70)
print("PASS RATES (HTTP 200)")
print("═" * 70)
print("WAF".ljust(14) + "".join(t.ljust(14) for t in tool_names))
print("-" * (14 + 14 * len(tool_names)))

for waf in wafs:
    waf_rows = [r for r in results if r["waf"] == waf]
    n = len(waf_rows)
    counts = []
    for t in tool_names:
        passed = sum(1 for r in waf_rows if r[t] == 200)
        counts.append(f"{passed}/{n}")
    print(waf.ljust(14) + "".join(c.ljust(14) for c in counts))

print("-" * (14 + 14 * len(tool_names)))
total_line = "TOTAL".ljust(14)
for t in tool_names:
    passed = sum(1 for r in results if r[t] == 200)
    total_line += f"{passed}/{len(results)} ({100*passed//len(results)}%)".ljust(14)
print(total_line)

# ─── Markdown ──────────────────────────────────────────────────────────
print("\n\n## Markdown\n")
md_header = "| WAF | Site | curl | curl_cffi Chrome | curl_cffi Firefox | tls-client | koon Chrome | koon Firefox | koon Safari |"
md_sep    = "|-----|------|------|------------------|-------------------|------------|-------------|--------------|-------------|"
print(md_header)
print(md_sep)
for r in results:
    def f(s):
        if s == 200: return "✅ 200"
        if s == 403: return "❌ 403"
        return f"⚠️ {s}"
    cols = " | ".join(f(r[t]) for t in tool_names)
    print(f"| {r['waf']} | {r['domain']} | {cols} |")
