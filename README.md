# koon

[![npm](https://img.shields.io/npm/v/koonjs)](https://www.npmjs.com/package/koonjs)
[![PyPI](https://img.shields.io/pypi/v/koon)](https://pypi.org/project/koon/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/scrape-hub/koon/blob/master/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/scrape-hub/koon/ci.yml?label=CI)](https://github.com/scrape-hub/koon/actions)

An HTTP client that impersonates real browsers at the TLS, HTTP/2, and HTTP/3 fingerprint level.

Built in Rust on top of BoringSSL with native bindings for **Node.js**, **Python**, **R**, and a **CLI**. Bot detection from Akamai, Cloudflare and others judges a client first by how it connects; koon connects exactly like the browser it names, checked against captures from the real browsers.

Every binding uses the same fingerprint engine, so a profile behaves the same from Rust, Node.js, Python, R and the CLI.

## Install

**Node.js**
```bash
npm install koonjs
```

**Python**
```bash
pip install koon
pip install "koon[httpx]"      # with the httpx transport's dependency
pip install "koon[requests]"   # with the requests adapter's dependency
```

**R**
```r
# Windows, or macOS on Apple silicon, with R 4.6: the prebuilt package of the release
install.packages("https://github.com/scrape-hub/koon/releases/download/v1.1.0/koon_1.1.0.zip", repos = NULL)  # Windows
install.packages("https://github.com/scrape-hub/koon/releases/download/v1.1.0/koon_1.1.0.tgz", repos = NULL)  # macOS

# Other platforms and R versions build from source: Rust 1.85+ and CMake, on
# Windows also Rtools, LLVM and `rustup target add x86_64-pc-windows-gnu`
remotes::install_github("scrape-hub/koon", subdir = "crates/r")
```

**CLI**: download from [Releases](https://github.com/scrape-hub/koon/releases), or:
```bash
cargo install --git https://github.com/scrape-hub/koon koon-cli
```

**Claude Code**: [koon-mcp](https://github.com/scrape-hub/koon-mcp) fetches web pages and PDFs for Claude through koon.

## Quick start

**Node.js**
```javascript
import { Koon } from 'koonjs';

const client = new Koon({ browser: 'chrome' });   // latest Chrome koon knows
const resp = await client.get('https://httpbin.org/json');
console.log(resp.ok);      // true
console.log(resp.text());  // body as string
console.log(resp.json());  // parsed JSON
```

**Python**
```python
from koon import KoonSync

client = KoonSync("chrome")
resp = client.get("https://httpbin.org/json")
print(resp.ok)      # True
print(resp.json())  # parsed JSON
```

**R**
```r
library(koon)

client <- Koon$new("chrome")
resp <- client$get("https://httpbin.org/json")
resp$ok      # TRUE
resp$text    # body as string
```

**CLI**
```bash
koon -b chrome https://example.com
```

**Rust**
```rust
use koon_core::{Client, Chrome};

let client = Client::new(Chrome::latest())?;
let r = client.get("https://example.com").await?;
```

## What it does

koon reproduces three fingerprint layers that bot detection systems check:

| Layer | What's fingerprinted | How koon matches it |
|-------|---------------------|-------------------|
| **TLS** | Cipher suites, curves, extensions, ALPN, GREASE, ALPS | BoringSSL with per-browser config (JA3/JA4 verified) |
| **HTTP/2** | SETTINGS, WINDOW_UPDATE, pseudo-header order, stream IDs, HEADERS priorities, HPACK encoding, TLS record layout, PING and close | Forked h2 crate reproducing Chrome's, Firefox's, Safari's and OkHttp's frame layout (Akamai hash verified) |
| **HTTP/3** | QUIC ClientHello, transport parameters and their order, packet layout (packet numbers, padding, CRYPTO framing, ACKs), HTTP/3 SETTINGS, QPACK, connection close | Forked quinn + h3 reproducing Chrome's (quiche), Firefox's (neqo) and Safari's (Apple) stacks; QUIC JA4 verified |

Every fingerprint change of every browser is checked against captures from the real browser: JA4, JA3N, JA3 and the Akamai HTTP/2 hash over the network, the raw ClientHello, the decrypted QUIC packets and the request headers byte for byte offline. `koon verify` runs the network check against your installed koon, also through your proxy (see [Fingerprint self-test](#fingerprint-self-test)).

## Why koon

**Gets the page where plain HTTP clients are turned away.** Bot protection checks how a client connects before it looks at anything else. Python's `requests` and Node's `fetch` fail that check on many of the sites people scrape; koon passes it:

| Site | Python `requests` | Node.js `fetch` | koon |
|---|---|---|---|
| indeed.com | 403 | 403 | 200 |
| bloomberg.com | 403 | 403 | 200 |
| reuters.com | 401 | 401 | 200 |
| tripadvisor.com | 403 | 403 | 200 |
| expedia.com | 429 | 429 | 200 |
| stockx.com | 403 | 403 | 200 |
| upwork.com | 403 | 403 | 200 |
| investing.com | 403 | 403 | 200 |

**Always the current browser.** Sites turn away browsers that are a few months out of date: American Airlines, Emirates and Hilton let in today's Firefox and not last spring's. koon follows the newest Chrome, Firefox and Safari, and `chrome` or `firefox` without a version always means the newest one koon knows.

## Limits

koon does not run JavaScript. A site that puts a JavaScript challenge first (Akamai, DataDome, AWS WAF, Kasada, PerimeterX) needs a real browser once; `blockedBy` says when that happens. Hand the browser's cookies to koon with `setCookies()` (`set_cookies()` in Python and R) and koon usually carries on from there.

Pick proxies whose operating system matches the profile. Bot protection compares the TCP/IP fingerprint of a connection (TTL, TCP window size and options) with the OS the browser claims; that layer comes from the kernel of the machine or proxy that opens the TCP connection, not from koon. A Windows Chrome profile through a Linux datacenter proxy is a mismatch no HTTP client can hide.

Match the language to the IP as well. koon asks for English pages unless you set `locale`, and some sites turn away a request whose language does not fit the country of its IP.

## Supported browsers

| Browser | Versions | Platforms | Profiles |
|---------|----------|-----------|----------|
| Chrome | 131-155 | Windows, macOS, Linux, Android | 100 |
| Firefox | 135-157 | Windows, macOS, Linux, Android | 92 |
| Safari | 15.6-27.0 | macOS, iOS | 41 |
| Edge | 131-154 | Windows, macOS, Android | 72 |
| Opera | 124-136 | Windows, macOS, Linux | 39 |
| Opera Mobile | 102 | Android | 1 |
| Brave | 153-154 (1.95, 1.96) | Windows, macOS, Linux, Android | 8 |
| Samsung Internet | 29-30 | Android | 2 |
| OkHttp | 4, 5 | Android | 2 |

**357 profiles** total. `koon --list-browsers`, `Koon.browsers()` (Node), `koon.browsers()` (Python) and `koon_browsers()` (R) list them all.

### Profile naming

Format: `{browser}{version}{-os}`. All parts but the browser name are optional, dash included (`chrome154-macos` or `chrome154macos`). Omit the version for the latest of any browser. Without an OS, desktop browsers default to Windows except Safari (macOS); Brave is named by the Chromium version it reports (`brave154` = Brave 1.96).

| Browser | Example profiles |
|---------|-------------------|
| Chrome, Firefox, Opera | `chrome155`, `-windows`, `-macos`, `-linux` |
| Edge, Brave | `edge154`, `-windows`, `-macos` (Brave also `-linux`) |
| Safari | `safari270-macos` |
| Chrome/Firefox/Edge/Brave Mobile (Android) | `chrome-mobile155`, `firefox-mobile157`, `edge-mobile154`, `brave-mobile154` |
| Safari Mobile (iOS) | `safari-mobile270` |
| Samsung Internet, Opera Mobile (Android) | `samsung30`, `opera-mobile102` |
| OkHttp | `okhttp4`, `okhttp5` (`-android` suffix optional) |

Safari's fingerprint follows the OS, not the Safari version: each profile reproduces the real Safari shipped with the macOS/iOS release in the table above (iOS 26 also reports a frozen OS version in its User-Agent, as real iPhones do). HTTP/3 uses Alt-Svc and, on a few releases, only the DNS HTTPS record; Safari never sends ECH.

Chrome Mobile and Firefox Mobile send their desktop counterpart's fingerprint with an Android User-Agent. Edge, Brave, Samsung Internet and Opera on Android are all built on Chrome on Android, each with its own quirks (dropped `trust_anchors`; Brave additionally its Shields' reduced client hints and `sec-gpc`; Samsung Internet its own branding and no HTTP/3). OkHttp reproduces Android's Conscrypt TLS stack; it keeps no cookies itself, so koon's jar stands in for one an app would add.

## Features

- **Fingerprints on every layer**: TLS, HTTP/2 and HTTP/3 as in the table above; header order, casing and values of navigations, form posts, fetch() calls and WebSocket handshakes, with cookie, referer, origin and your own headers where the browser puts them; the client hints Chromium sends when a site asks for them
- **HTTP/3 like the browser**: found through Alt-Svc or, on the first connection, the DNS HTTPS record; racing TCP like Chrome or straight to QUIC like Safari, with fallback to TCP; 0-RTT on resumed connections
- **Encrypted Client Hello and DNS**: real ECH from DNS HTTPS records over TCP and QUIC, read over DNS-over-HTTPS (Cloudflare, Google) or, as Chrome and Firefox do by default, with a plain query to the system's nameserver; ECH GREASE in the browser's shape otherwise (needs the `doh` feature in Rust)
- **Chrome's field trials**: like a slice of real Chrome installations, a client may be enrolled in Chrome's handshake-padding trial; pin the group with `serverPadding`, `server_padding` or `--server-padding`
- **Fingerprint self-test**: `koon verify` checks your installed koon against the real browsers' fingerprints (see [below](#fingerprint-self-test))
- **TLS sessions and certificates**: session tickets per origin, used once, over TCP and QUIC; certificates verified against Mozilla's roots plus every trust anchor of the Chrome Root Store
- **Cookies and sessions**: a jar with domain, path, expiry, Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefixes and public-suffix protection; import and export as Playwright/CDP cookie objects; save and load cookies and TLS tickets as JSON
- **Proxies**: HTTP, HTTPS and SOCKS5, round-robin rotation, custom CONNECT headers; retries switch the proxy and never send a POST twice; HTTP/3 goes direct
- **MITM proxy server**: re-sends any program's traffic through koon; loopback only unless allowed, optional authentication, capped connections
- **WebSocket**: `wss://` and `ws://` with the browser's handshake, over HTTP/2 where the browser uses it; send and receive concurrently
- **Streaming**: response bodies read on demand with backpressure, uploads from a stream, multipart forms with the browser's boundary format
- **Hooks**: `onRequest`, `onResponse` and `onRedirect` for logging, guards and stopping a redirect to a captcha, per client or per request
- **Per-request options**: headers, timeout, proxy and redirect following without touching the client
- **Response body cap**: 100 MiB by default, decompression bombs included
- **Request headers on every response**: exactly what was sent, HTTP/2 and HTTP/3 pseudo-headers included
- **Bot protection named**: `blockedBy` (`blocked_by` in Python, R and Rust) names the bot protection that answered instead of the page (Cloudflare, Akamai, DataDome, ...), which the status code alone does not tell
- **Plain HTTP**: `http://` with the header set browsers use for insecure origins
- **Network options**: local address binding, IPv4 or IPv6 only, host pinning like curl's `--resolve`, `locale` for an Accept-Language that matches the proxy's country
- **Key logging**: `SSLKEYLOGFILE` writes the TLS secrets (TCP, QUIC and DoH) for Wireshark
- **Custom profiles**: export a profile as JSON, change it and load it back (see [Custom profiles](#custom-profiles))
- **Drop-in adapters**: an httpx transport, a requests adapter and a `fetch()` for Node; `KoonSync`, a blocking Python client
- **Structured errors**: a machine-readable code on every error (`TIMEOUT`, `TLS_ERROR`, `PROXY_ERROR`, ...)

## Usage

### Node.js

```javascript
import { Koon, KoonProxy } from 'koonjs';

// Browser profile + options
const client = new Koon({
  browser: 'chrome',                   // latest Chrome on Windows; Koon.browsers() lists all
  headers: { 'X-Custom': 'value' },    // or [name, value] pairs, a Map, a fetch Headers
  proxy: 'socks5://127.0.0.1:1080',    // optional
  timeout: 15,                         // seconds, fractions allowed; 0 = no timeout
  localAddress: '192.168.1.100',       // optional: bind to specific IP
  retries: 3,                          // optional: retry on transport errors
  locale: 'fr-FR',                     // optional: Accept-Language for proxy geo
  ipVersion: 4,                        // optional: force IPv4 DNS resolution
  resolve: ['example.com:443:203.0.113.7'],  // optional: connect there, like curl --resolve
  proxyHeaders: {                      // optional: CONNECT tunnel headers
    'X-Session-Id': 'abc123',
  },
  maxResponseBody: 100 * 1024 * 1024,  // optional: cap on the decompressed body; 0 = no cap
  serverPadding: 'none',               // optional: pin Chrome's server-padding trial group
  onRedirect: (status, url, headers) => {
    return !url.includes('captcha');   // false stops; anything else follows
  },
});

// HTTP methods
const r1 = await client.get('https://httpbin.org/get');
const r2 = await client.post('https://httpbin.org/post', 'data');
const r3 = await client.put('https://httpbin.org/put', 'data');
const r4 = await client.delete('https://httpbin.org/delete');
const r5 = await client.patch('https://httpbin.org/patch', 'data');
const r6 = await client.head('https://httpbin.org/get');

// User-Agent (useful for Puppeteer/Playwright sync)
console.log(client.userAgent);  // "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/155..."

// Response
console.log(r1.ok);                             // true (status 2xx)
console.log(r1.status);                         // 200
console.log(r1.text());                         // body as string (charset-aware)
console.log(r1.json());                         // parsed JSON
console.log(r1.contentType);                    // e.g. "text/html; charset=utf-8"
console.log(r1.header('content-type'));         // case-insensitive header lookup
console.log(r1.body);                           // raw Buffer
console.log(r1.tlsResumed);                     // TLS session was reused
console.log(r1.connectionReused);               // pooled connection was reused
console.log(r1.remoteAddress);                  // peer IP (the proxy when one is used)
console.log(r1.blockedBy);                      // null, or e.g. 'cloudflare' when bot protection answered
console.log(r1.bytesSent, r1.bytesReceived);    // bandwidth per request

// Per-request headers, timeout, proxy and hooks
const r7 = await client.get('https://httpbin.org/get', {
  headers: [['Authorization', 'Bearer token']], // pairs or an object
  timeout: 2.5,                               // 2.5 s for this request only
  proxy: 'http://user:pass@other-proxy:8080', // override proxy for this request
  onResponse: (status, url) => console.log(status, url),
});

// A hook that throws fails the request with what it threw; a throwing
// onRequest stops the request before it is sent.
const guarded = new Koon({
  onRequest: (method, url) => {
    if (!url.startsWith('https://httpbin.org/')) throw new Error(`blocked: ${url}`);
  },
});

// Cookies persist automatically
await client.get('https://httpbin.org/cookies/set/name/value');
const r = await client.get('https://httpbin.org/cookies');

// Clear cookies (keeps TLS sessions and connection pool)
client.clearCookies();

// Session save/load
const session = client.saveSession();           // JSON string
const client2 = new Koon({ browser: 'chrome' });
client2.loadSession(session);

// File: save/load to disk
client.saveSessionToFile('session.json');
client2.loadSessionFromFile('session.json');

// WebSocket
const ws = await client.websocket('wss://echo.websocket.org');
await ws.send('hello');
const msg = await ws.receive();  // { isText: true, data: Buffer }
await ws.close();

// Streaming
const stream = await client.requestStreaming('GET', 'https://example.com/large');
console.log(stream.status);
for await (const chunk of stream) process.stdout.write(chunk);  // or nextChunk() / collect()
// The body arrives decoded (gzip, br, ...); { decode: false } in the options
// gives the bytes as sent. cancel() drops the rest of the body; leaving for
// await early does too.

// Multipart upload
await client.postMultipart('https://httpbin.org/post', [
  { name: 'field', value: 'text' },
  { name: 'file', fileData: Buffer.from('...'), filename: 'upload.txt', contentType: 'text/plain' },
]);

// Every profile name
console.log(Koon.browsers());  // ['chrome131-windows', 'chrome131-macos', ...]

// Closing: close() drops the pooled connections without waiting; before the
// process exits, shutdown() ends them the way the browser does.
client.close();
await client.shutdown();

// MITM proxy
const proxy = await KoonProxy.start({
  browser: 'chrome',
  listenAddr: '127.0.0.1:8080',
  // allowNonLoopback: true,            // needed to bind a non-loopback address
  // auth: { username: 'user', password: 'pass' },  // require Proxy-Authorization
  // maxConnections: 512,               // concurrent connections accepted (default)
});
console.log(proxy.url);         // http://127.0.0.1:8080
console.log(proxy.caCertPath);  // path to CA cert for trust
await proxy.shutdown();
```

**fetch()**: `koonFetch()` returns a `fetch()` that sends through a koon
client and resolves to a standard `Response`, so fetch-based code only swaps
the function:

```javascript
import { koonFetch } from 'koonjs';

const fetch = koonFetch({ browser: 'chrome', proxy: 'http://user:pass@proxy:8080' });
const resp = await fetch('https://httpbin.org/post', {
  method: 'POST',
  body: new URLSearchParams({ q: 'koon' }),       // strings, Buffers, Blobs, FormData, streams
  signal: AbortSignal.timeout(10_000),
});
console.log(resp.status, await resp.json());
for await (const chunk of (await fetch('https://example.com/large')).body) {}  // streamed
```

Only the headers you set are added to the browser's, where the browser puts
them; Node's own fetch headers (`user-agent: node`, ...) are never sent.
Redirects (`follow`, `manual`, `error`) and cookies are handled by the koon
client, `signal` cancels the request or its body, and failures reject with
`TypeError('fetch failed')` whose `cause` carries the koon error `code`. The
details are in `index.d.ts`.

### Python

`KoonSync` provides a blocking API, with no `asyncio` needed:

```python
import koon
from koon import KoonSync

# Browser profile + options; leaving the with block shuts the client down
with KoonSync("chrome",                          # latest Chrome on Windows
    headers={"X-Custom": "value"},               # or a list of (name, value) pairs
    timeout=15,                                  # seconds, fractions allowed; 0 = no timeout
    retries=3,                                   # retry on transport errors
    locale="fr-FR",                              # Accept-Language for proxy geo
    ip_version=4,                                # force IPv4 DNS resolution
    resolve=["example.com:443:203.0.113.7"],     # connect there, like curl --resolve
    proxy_headers={"X-Session-Id": "abc123"},    # CONNECT tunnel headers
    max_response_body=100 * 1024 * 1024,         # cap on the decompressed body; 0 = no cap
    server_padding="none",                       # pin Chrome's server-padding trial group
    on_redirect=lambda s, u, h: "captcha" not in u,  # False stops; anything else follows
) as client:

    # HTTP methods
    r = client.get("https://httpbin.org/get")
    r = client.post("https://httpbin.org/post", "data")
    r = client.put("https://httpbin.org/put", "data")
    r = client.delete("https://httpbin.org/delete")
    r = client.patch("https://httpbin.org/patch", "data")
    r = client.head("https://httpbin.org/get")

    # Response
    print(r.ok)                 # True (status 2xx)
    print(r.status)             # 200
    print(r.text)               # body as string (charset-aware)
    print(r.json())             # parsed JSON
    print(r.content_type)       # e.g. "text/html; charset=utf-8"
    print(r.header("content-type"))  # case-insensitive header lookup
    print(r.tls_resumed)        # TLS session was reused
    print(r.connection_reused)  # pooled connection was reused
    print(r.bytes_sent, r.bytes_received)  # bandwidth per request
    print(r.blocked_by)         # None, or e.g. "cloudflare" when bot protection answered

    # Per-request headers, timeout, proxy and hooks
    r = client.get("https://httpbin.org/get",
        headers=[("Authorization", "Bearer token")],
        timeout=2.5,                                 # 2.5 s for this request only
        proxy="http://user:pass@other-proxy:8080",   # override proxy for this request
        on_response=lambda status, url, headers: print(status, url),
    )

    # Cookies persist automatically
    client.get("https://httpbin.org/cookies/set/name/value")
    r = client.get("https://httpbin.org/cookies")

    # Clear cookies (keeps TLS sessions and connection pool)
    client.clear_cookies()

    # Session save/load
    session = client.save_session()
    client2 = KoonSync("chrome")
    client2.load_session(session)

    # User-Agent (useful for Puppeteer/Playwright sync)
    print(client.user_agent)  # "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/155..."

    # Streaming: the body is read as it arrives, decoded (decode=False for the
    # bytes as sent); leaving the with block (or close()) drops the rest of it
    with client.request_streaming("GET", "https://example.com/large") as stream:
        for chunk in stream:  # or next_chunk() / collect()
            ...

# An exception a hook raises is what the request raises; a raising
# on_request stops the request before it is sent.
def only_httpbin(method, url):
    if not url.startswith("https://httpbin.org/"):
        raise PermissionError(url)

guarded = KoonSync("chrome", on_request=only_httpbin)

# Every profile name
print(koon.browsers())  # ['chrome131-windows', 'chrome131-macos', ...]
```

`close()` drops the pooled connections without waiting; `shutdown()` (what
leaving a `with` block calls) ends them the way the browser does when it
quits, waiting at most 300 ms for the closes to be sent.

For async code, use `Koon` instead: same API, but all request methods are coroutines.

```python
from koon import Koon

async with Koon("chrome") as client:
    resp = await client.get("https://httpbin.org/get")

    # WebSocket (async only)
    ws = await client.websocket("wss://echo.websocket.org")
    await ws.send("hello")
    msg = await ws.receive()
    await ws.close()

    # Streaming; leaving async with (or close(), aclose()) drops the rest of
    # the body, breaking out of async for does not
    async with await client.request_streaming("GET", "https://example.com/large") as stream:
        async for chunk in stream:  # or next_chunk() / collect()
            ...
```

**httpx and requests**: code written for httpx or requests keeps its client
and gets koon's fingerprint from a transport (`pip install koon[httpx]`,
`koon[requests]`):

```python
import httpx
from koon.httpx import KoonTransport, AsyncKoonTransport

with httpx.Client(transport=KoonTransport("chrome", proxy="http://proxy:8080")) as client:
    r = client.get("https://example.com", follow_redirects=True)
    with client.stream("GET", "https://example.com/large") as r:
        for chunk in r.iter_bytes():
            ...

async with httpx.AsyncClient(transport=AsyncKoonTransport("firefox")) as client:
    r = await client.get("https://example.com")

import requests
from koon.requests import KoonAdapter, Session

with Session("chrome") as s:                      # a requests.Session with the adapter
    r = s.get("https://example.com", timeout=10)
session = requests.Session()                      # or mount it yourself
session.mount("https://", KoonAdapter("chrome"))
```

The library keeps its part: redirects, cookies (its jar; koon's is off),
auth, hooks, timeouts, and with requests the proxies from `proxies=` and the
environment. Its own default headers, such as `User-Agent: python-httpx/x.y`,
`python-requests/x.y` and `Accept: */*`, are dropped, so the browser's go out
in the browser's order; every header you set is sent where the browser puts
it. `files=` uploads go out as the browser encodes multipart forms (its
boundary and escaping). koon decodes the body, so responses come without
Content-Encoding; closing a streamed response drops the rest of it. Pass
koon's client options, the proxy included, to the transport or adapter, and
`verify=False` to skip certificate checks. Unsupported options raise instead
of being ignored, and errors are the library's (`httpx.ConnectError`,
`requests.exceptions.SSLError` and the like) with the `KoonError` as
`__cause__`. The full rules are in `koon/httpx.pyi` and `koon/requests.pyi`.

### R

```r
library(koon)

# Browser profile + options
client <- Koon$new("chrome", proxy = "socks5://127.0.0.1:1080",
                    timeout = 15,                  # seconds, fractions allowed; 0 = none
                    local_address = "192.168.1.100", retries = 3L,
                    locale = "fr-FR", ip_version = 4L,
                    resolve = "example.com:443:203.0.113.7",  # like curl --resolve
                    proxy_headers = c(`X-Session-Id` = "abc123"),
                    max_response_body = 100 * 1024 * 1024,    # cap on decompressed body; 0 = none
                    server_padding = "none",       # pin Chrome's server-padding trial group
                    # FALSE stops; anything else (NULL from a logger too) follows
                    on_redirect = function(status, url, headers) !grepl("captcha", url))

# HTTP methods (synchronous)
resp <- client$get("https://httpbin.org/get")
resp <- client$post("https://httpbin.org/post", "data")
resp <- client$put("https://httpbin.org/put", "data")
resp <- client$delete("https://httpbin.org/delete")
resp <- client$patch("https://httpbin.org/patch", "data")
resp <- client$head("https://httpbin.org/get")

# Response
resp$ok         # TRUE (status 2xx)
resp$status     # 200
resp$version    # "h2"
resp$text           # body as string (charset-aware)
resp$content_type   # e.g. "text/html; charset=utf-8"
resp$body           # raw vector
resp$headers        # data.frame with name + value columns
resp$blocked_by     # NULL, or e.g. "cloudflare" when bot protection answered

# Parse JSON (via jsonlite)
data <- jsonlite::fromJSON(resp$text)

# Per-request headers (a named vector or a named list) and callbacks
resp <- client$get("https://httpbin.org/get",
  headers = list(Authorization = "Bearer token"),
  timeout = 2.5,
  on_response = function(status, url, headers) message(status, " ", url)
)

# An error a callback raises fails the request and is re-raised as is;
# a failing on_request stops the request before it is sent.
guarded <- Koon$new("chrome", on_request = function(method, url) {
  if (!startsWith(url, "https://httpbin.org/")) stop("blocked: ", url)
})

# Cookies persist automatically
client$get("https://httpbin.org/cookies/set/name/value")
resp <- client$get("https://httpbin.org/cookies")

# Clear cookies (keeps TLS sessions and connection pool)
client$clear_cookies()

# Session save/load
json <- client$save_session()
client2 <- Koon$new("chrome")
client2$load_session(json)

# Export profile as JSON
client$export_profile()

# List all browser profiles
koon_browsers()   # "chrome131-windows" "chrome131-macos" ...

# Close the pooled connections without waiting, or end them as the browser
# does before the session ends
client$close()
client$shutdown()
```

### CLI

```bash
# GET with browser profile
koon -b chrome https://example.com

# POST with body (a file with -d @file; above 16 MiB it is streamed from disk)
koon -b firefox -X POST -d '{"key":"value"}' https://httpbin.org/post

# Multipart form, as curl -F: fields, file uploads (;type= ;filename=), text from a file
koon -F name=value -F photo=@photo.png -F "doc=@report.bin;type=application/pdf" https://httpbin.org/post

# Custom headers
koon -b safari -H "Authorization: Bearer token" https://api.example.com

# Verbose output (request/response headers on stderr, and the bot protection if one answered)
koon -v https://httpbin.org/get

# Response headers: -i includes them in the output, -I sends a HEAD request
koon -i https://example.com
koon -I https://example.com

# Fail on HTTP errors (status >= 400): no output, exit code 22
koon -f -o page.html https://example.com

# JSON output: status, headers, body, version, url and blocked_by
koon --json https://httpbin.org/get

# Save the response to a file (written as it arrives)
koon -o page.html https://example.com

# Timeout in seconds, fractions allowed (0: none)
koon --timeout 2.5 https://example.com

# Cap the decompressed response body (0: no cap); pin the server-padding trial group
koon --max-response-body 52428800 https://example.com
koon --server-padding none https://example.com

# Proxy
koon --proxy socks5://127.0.0.1:1080 https://example.com

# Connect to a given address instead of resolving the host, like curl
koon --resolve example.com:443:203.0.113.7 https://example.com

# Session persistence
koon --save-session session.json https://example.com/login
koon --load-session session.json https://example.com/dashboard

# DNS-over-HTTPS
koon --doh cloudflare https://example.com

# Another OS or a specific version
koon -b chrome-macos https://example.com
koon -b firefox154-linux https://example.com

# List all browser profiles
koon --list-browsers

# Export profile as JSON
koon --export-profile chrome

# Start MITM proxy (--allow-non-loopback to bind a non-loopback address, then
# consider --auth; --max-connections caps concurrent connections, default 512)
koon proxy --browser chrome --listen 127.0.0.1:8080
koon proxy --listen 0.0.0.0:8080 --allow-non-loopback --auth user:pass --max-connections 200

# Check that koon still sends the real browsers' fingerprints (exit code 20 on a mismatch)
koon verify
koon verify -b firefox154-windows chrome-mobile --json
koon verify --proxy http://user:pass@proxy.example:8080
```

curl's `-L`, `-s`, `-S` and `--compressed` are accepted and change nothing, so
copied curl command lines run: koon follows redirects unless `--no-follow`,
shows no progress meter and always decompresses. Exit codes are curl's where
one fits (7 connection failed, 22 HTTP error with `--fail`, 28 timeout, 35 TLS
error, 97 proxy error, and more), plus 20 for a fingerprint mismatch in `koon verify`;
`koon --help` lists them all.

### Rust

```toml
[dependencies]
koon-core = { git = "https://github.com/scrape-hub/koon.git" }
# DNS-over-HTTPS and ECH from DNS HTTPS records need the `doh` feature:
# koon-core = { git = "https://github.com/scrape-hub/koon.git", features = ["doh"] }
```

BoringSSL is built with the optimisation level of your profile. Debug builds
compile it without optimisation, which makes every TLS handshake several times
slower; to keep it fast in development, add to your `Cargo.toml`:

```toml
[profile.dev.package.btls-sys]
opt-level = 3
```

```rust
use std::time::Duration;

use koon_core::{Body, BrowserProfile, Chrome, Client, Os, RequestOptions, parse_method};

#[tokio::main]
async fn main() -> Result<(), koon_core::Error> {
    // The latest Chrome koon knows (Windows), or a specific version and OS
    let _latest = Client::new(Chrome::latest())?;
    let _macos = Client::new(Chrome::version(154, Os::MacOS)?)?;

    // Or by name, with the builder for full control
    let profile = BrowserProfile::resolve("chrome-windows")?;
    let client = Client::builder(profile)
        .max_retries(3)
        .locale("fr-FR")
        .ip_version(koon_core::IpVersion::V4)
        .on_redirect(|_status, url, _headers| {
            Ok(!url.contains("captcha"))  // Ok(false) stops; an Err fails the request
        })
        .build()?;

    let r = client.get("https://example.com").await?;
    println!("{} {} ({} bytes)", r.status, r.version, r.body.len());
    if let Some(by) = r.blocked_by() {
        println!("{by} answered instead of the page");
    }

    // Per-request headers, timeout, proxy, redirects and hooks
    let options = RequestOptions {
        headers: vec![("accept".into(), "application/json".into())],
        timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    let r = client
        .send(parse_method("GET")?, "https://httpbin.org/json", Body::empty(), options)
        .await?;
    println!("{}", r.text());

    // Clear cookies without resetting TLS/pool
    client.clear_cookies();

    // End open HTTP/3 connections like the browser before exiting
    client.shutdown().await;

    Ok(())
}
```

## Fingerprint self-test

`koon verify` checks that the koon you have installed still produces the
fingerprints of the real browsers. Each profile connects to
[tls.browserleaks.com](https://tls.browserleaks.com/json) (tls.peet.ws if that
fails), which reports the JA4, JA3N, JA3 and Akamai HTTP/2 fingerprint it sees.
Where a QUIC reference exists (Chrome 134-155, Edge 153-154, Opera 136, Brave, Opera Mobile,
Firefox and the Safari releases whose transport parameters were captured;
Samsung Internet uses no HTTP/3), the
check also goes over HTTP/3 to quic.browserleaks.com for the QUIC JA4. Every
field is compared with the value captured from the real browser.

```
$ koon verify -b firefox
firefox -> firefox157-windows: match
  reference    firefox-156: Firefox 156-157 (without ffdhe groups): real Firefox 156.0.1 captures; 157 from the 157.0 beta (ClientHello capture and tls.browserleaks.com)
  reference    firefox-quic: QUIC JA4 of real Firefox 155.0.1 and 157.0 beta QUIC ClientHellos (157 also from quic.browserleaks.com)
  service      https://tls.browserleaks.com/json
  http3        https://quic.browserleaks.com/?minify=1
  ja4          match        t13d1517h2_8daaf6152771_3cbfd9057e0d
  ja3n_hash    match        f9c6a2c424206e61efb6c1a6325596b5
  ja3_hash     match        9d42e90b0225e779f03141ddcd699df2
  akamai_hash  match        6ea73faa8fc5aac76bded7bd238f6433
  akamai_text  match        1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
  quic_ja4     match        q13d0315h3_55b375c5d22e_dc5437974b47

1 profile: 1 match
```

- Without `-b` it checks the latest `chrome`, `firefox`, `safari`, `edge`,
  `opera`, `brave`, `samsung`, `opera-mobile` and `okhttp`; `-b` takes any
  profile names (`-b chrome154-linux edge-macos`).
- A field is `match`, `MISMATCH` (with the expected value), or `not checked`
  with the reason: no reference value (JA3 of browsers that shuffle their
  extensions), not reported by the service (tls.peet.ws has no JA3N), or
  HTTP/3 not used (UDP blocked, or a proxy).
- Browser versions without a capture are reported as `no reference`: Safari
  releases without a capture of their own (e.g. Safari 16.6 on iOS and 26.6
  on iOS) and Firefox on Android before 146. Safari on iOS 18.0 to 18.2 has
  no QUIC check: the simulators never sent QUIC there, so no QUIC capture
  exists. macOS 15.1 and 15.2 get their QUIC check through the HTTPS record
  (they ignore Alt-Svc).
- `--json` prints the reports as JSON. `--proxy` and the other connection
  options apply; HTTP/3 does not go through a proxy. `--service URL` asks
  another service that answers in the format of browserleaks or tls.peet.ws
  (e.g. a self-hosted [TrackMe](https://github.com/pagpeter/TrackMe)),
  `--skip-http3` leaves out the QUIC check.
- Exit code 0 when every checked field matches, 20 on a mismatch, and the
  code of the connection error (7, 28, 35, 97, and so on) when no service answers.

The service sees the connection as it arrives: a proxy or antivirus that
terminates TLS replaces koon's ClientHello with its own, which shows as a
mismatch.

The bindings return the same report as an object:

```js
const report = await Koon.verify('chrome', { proxy: 'http://user:pass@proxy.example:8080' });
console.log(report.outcome); // 'match', 'mismatch', 'no_reference' or 'unreachable'
```

```python
report = koon.verify("firefox")
print(report["outcome"], [f for f in report["fields"] if f["status"] == "mismatch"])
```

In Rust, `koon_core::verify::verify("chrome", None)` returns a `VerifyReport`;
`verify_with` checks with a client you built (proxy, DNS, local address), and
`references_for` gives the reference values of a profile.

## Custom profiles

A profile is plain JSON: export a built-in one, change what you need, and load
the file instead of a browser name.

```bash
koon --export-profile chrome154-windows > my-chrome.json
koon --profile my-chrome.json https://example.com
```

Node `exportProfile()` / `profileJson`, Python `export_profile()` /
`profile_json`, R `$export_profile()` / `profile_json`, Rust
`BrowserProfile::to_json_pretty()` / `from_json()` / `from_file()`; the MITM
proxy takes a profile the same way (`koon proxy --profile`).

| Key | Content |
|-----|---------|
| `tls` | The ClientHello: cipher, group and signature algorithm lists, ALPN and ALPS, GREASE, extension order, ECH GREASE, trust anchor IDs, and more |
| `http2` | SETTINGS and their order, window sizes, pseudo-header order, priorities, and the optional frame-layout keys below |
| `quic` | Optional; without it the profile does not use HTTP/3. The QUIC stack whose wire behaviour it follows (`chromium`, `neqo` or `apple`), transport parameters, HTTP/3 SETTINGS and an optional QUIC ClientHello (`tls`) |
| `headers` | The headers of a navigation and their values |
| `header_family` | Optional: `chromium`, `firefox`, `safari`, `okhttp` or `other`, whose header order and browser rules requests follow; detected from the headers when missing |
| `ua_client_hints` | Optional, for Chromium profiles: the high-entropy client hint values (`full_version`, `full_version_list`, `platform_version`, `architecture`, `bitness`, `model`, `wow64`, `form_factors`) and the device's `device_memory_mib`, `device_pixel_ratio` and `viewport_px` (`[width, height]` in device pixels), sent when a site asks for them |

The optional `http2` keys reproduce a browser's frame layout; a key left out
keeps the http2 crate's behaviour:

- `initial_stream_id`: ID of the first stream (Firefox uses 3)
- `headers_priority`: `chromium` or `firefox`, to derive each request's HEADERS priority from the request as that browser does, instead of `headers_stream_dependency` for every request
- `initial_stream_window_size`: each stream's receive window, raised by a WINDOW_UPDATE after its HEADERS when larger than `initial_window_size`
- `stream_window_update`, `connection_window_update`: when the windows are topped up, as `{"threshold": N, "low_window": N, "interval_ms": N}`
- `header_compression`: `chromium` or `firefox`, that browser's HPACK encoder
- `write_frames_individually`: a TLS record per frame (default `false`)
- `max_header_frame_size`: largest HEADERS/CONTINUATION payload
- `ping`: `{"when": "idle", "idle_ms": N, "timeout_ms": N}` (Firefox) or `{"when": "before_request"}` (Chromium)
- `goaway_on_close`, `close_notify`: send GOAWAY and TLS close_notify when closing a connection (default `true`)

The rustdoc of `BrowserProfile`, `TlsConfig`, `Http2Config`, `QuicConfig` and
`UaClientHints` describes every field (`cargo doc -p koon-core --open`).

A field the profile does not have is rejected with an error that names it,
so a typo never falls back to a default silently. Profile files from koon 0.8
are not accepted; export the profile again from the current version. A
profile file cannot turn off certificate verification: that is a client
option (`ignoreTlsErrors`, `ignore_tls_errors`, `-k`).

## Architecture

```
koon-core         Rust library: TLS, HTTP/2, HTTP/3, profiles, proxy
koon-node         Node.js native addon via napi-rs
koon-python       Python extension via PyO3 + maturin
koon-r            R package via extendr
koon-cli          Command-line interface via clap
```

Key dependencies:
- [btls](https://github.com/scrape-hub/btls) (fork of [0x676e67/btls](https://github.com/0x676e67/btls)): BoringSSL Rust bindings, patched for browser ClientHellos
- [http2](https://github.com/scrape-hub/http2) (fork): HTTP/2 with browser frame and header layout
- [quinn](https://github.com/scrape-hub/quinn) + [h3](https://github.com/scrape-hub/h3) (forks): QUIC and HTTP/3 with browser packet and frame layout
- [napi-rs](https://napi.rs): Rust to Node.js bridge
- [PyO3](https://pyo3.rs) + [maturin](https://github.com/PyO3/maturin): Rust to Python bridge
- [extendr](https://extendr.rs): Rust to R bridge

## Building from source

Only needed if you want to build koon yourself instead of using the published packages.

**Requirements:**
- Rust 1.85+
- CMake
- NASM (Windows, optional: without it BoringSSL is built from portable C, which is slower)
- C compiler: MSVC (Windows), GCC or Clang (Linux/macOS)

```bash
# Core library
cargo build --release -p koon-core

# Node.js addon
cargo build --release -p koon-node

# Python package
cd crates/python && pip install -e .

# R package
R CMD INSTALL crates/r

# CLI binary
cargo build --release -p koon-cli
```

## License

[MIT](https://github.com/scrape-hub/koon/blob/master/LICENSE)
