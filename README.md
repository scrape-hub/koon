# koon

An HTTP client that impersonates real browsers at the TLS, HTTP/2, and HTTP/3 fingerprint level.

Built in Rust on top of BoringSSL with native bindings for **Node.js**, **Python**, **R**, and a **CLI**. Passes Akamai, Cloudflare, and other bot detection systems by reproducing exact browser fingerprints — verified against real browser captures.

## Install

**Node.js**
```bash
npm install koonjs
```

**Python**
```bash
pip install koon
```

**R**
```r
# Install from source (requires Rust toolchain)
remotes::install_github("scrape-hub/koon", subdir = "crates/r")
```

**CLI** — download from [Releases](https://github.com/scrape-hub/koon/releases), or:
```bash
cargo install koon-cli
```

## Quick start

**Node.js**
```javascript
const { Koon } = require('koonjs');

const client = new Koon({ browser: 'chrome145' });
const resp = await client.get('https://httpbin.org/json');
console.log(resp.ok);      // true
console.log(resp.text());  // body as string
console.log(resp.json());  // parsed JSON
```

**Python**
```python
from koon import Koon

client = Koon("chrome145")
resp = await client.get("https://httpbin.org/json")
print(resp.ok)      # True
print(resp.json())  # parsed JSON
```

**R**
```r
library(koon)

client <- Koon$new("chrome145")
resp <- client$get("https://httpbin.org/json")
resp$ok      # TRUE
resp$text    # body as string
```

**CLI**
```bash
koon -b chrome145 https://example.com
```

**Rust**
```rust
use koon_core::{Client, profile::Chrome};

let client = Client::new(Chrome::v145_windows());
let r = client.get("https://example.com").await?;
```

## What it does

koon reproduces three fingerprint layers that bot detection systems check:

| Layer | What's fingerprinted | How koon matches it |
|-------|---------------------|-------------------|
| **TLS** | Cipher suites, curves, extensions, ALPN, GREASE, ALPS | BoringSSL with per-browser config (JA3/JA4 verified) |
| **HTTP/2** | SETTINGS order, pseudo-header order, WINDOW_UPDATE, PRIORITY frames | Forked h2 crate with header ordering API (Akamai hash verified) |
| **HTTP/3** | QUIC transport params, H3 settings | Quinn + h3 with browser-matching config |

All fingerprints are tested against hashes captured from real browsers. 10 integration tests verify JA3N, JA4, and Akamai hashes for Chrome, Firefox, Safari, Edge, and Opera.

## Supported browsers

| Browser | Versions | Platforms | Profiles |
|---------|----------|-----------|----------|
| Chrome | 131 – 145 | Windows, macOS, Linux, Android | 60 |
| Firefox | 135 – 148 | Windows, macOS, Linux, Android | 56 |
| Safari | 15.6 – 18.3 | macOS, iOS | 15 |
| Edge | 131 – 145 | Windows, macOS | 30 |
| Opera | 124 – 127 | Windows, macOS, Linux | 12 |
| OkHttp | 4, 5 | Android | 2 |

**175 profiles** total. Use `koon --list-browsers` (CLI) to see all profiles.

### Profile naming

Format: `{browser}{version}{-os}` — all parts except the browser name are optional. Both `chrome145-macos` and `chrome145macos` work (dash is optional).

**Desktop browsers with OS variants:**

| Browser | Default (Windows) | Windows | macOS | Linux |
|---------|-------------------|---------|-------|-------|
| Chrome 145 | `chrome145` | `chrome145-windows` | `chrome145-macos` | `chrome145-linux` |
| Firefox 148 | `firefox148` | `firefox148-windows` | `firefox148-macos` | `firefox148-linux` |
| Edge 145 | `edge145` | `edge145-windows` | `edge145-macos` | — |
| Opera 127 | `opera127` | `opera127-windows` | `opera127-macos` | `opera127-linux` |
| Safari 18.3 | `safari183` | — | `safari183-macos` | — |

**Mobile browsers:**

| Browser | Example |
|---------|---------|
| Chrome Mobile (Android) | `chrome-mobile145` |
| Firefox Mobile (Android) | `firefox-mobile148` |
| Safari Mobile (iOS) | `safari-mobile183` |

**OkHttp (Android apps):**

| Version | Name |
|---------|------|
| OkHttp 4 | `okhttp4` |
| OkHttp 5 | `okhttp5` |

**Shorthand** — omit the version to get the latest:

| Shorthand | Resolves to |
|-----------|-------------|
| `chrome` | Chrome 145 Windows |
| `firefox` | Firefox 148 Windows |
| `safari` | Safari 18.3 macOS |
| `edge` | Edge 145 Windows |
| `opera` | Opera 127 Windows |
| `chrome-mobile` | Chrome Mobile 145 Android |
| `firefox-mobile` | Firefox Mobile 148 Android |
| `safari-mobile` | Safari Mobile 18.3 iOS |
| `okhttp` | OkHttp 5 |

## Features

- **TLS fingerprint** — cipher list, curves, sigalgs, extension order, GREASE, ALPS, cert compression, delegated credentials
- **HTTP/2 fingerprint** — SETTINGS order, pseudo-header order, stream dependencies, priority frames, window sizes
- **HTTP/3 (QUIC)** — Alt-Svc discovery, QUIC transport parameter fingerprinting, H3 connection pooling
- **Header order preservation** — HTTP/2 (via forked h2) and HTTP/1.1
- **Encrypted Client Hello** — real ECH from DNS HTTPS records, with GREASE fallback
- **DNS-over-HTTPS** — Cloudflare and Google resolvers with ECH config discovery
- **TLS session resumption** — session ticket caching across requests
- **Cookie jar** — automatic persistence with domain/path/expiry/Secure/HttpOnly/SameSite
- **Proxy** — HTTP CONNECT and SOCKS5, with H3 fallback to H2 through proxies
- **MITM proxy server** — local proxy that re-sends all traffic through koon's fingerprinted stack
- **WebSocket** — `wss://` connections with browser-matching TLS handshake
- **Streaming responses** — chunked body streaming with async iterator support
- **Multipart form-data** — file uploads with custom content types
- **Per-request headers and timeout** — override defaults per request without affecting the client
- **Ergonomic response API** — `ok`, `text()`, `json()`, `header()` on every response
- **Session persistence** — save/load cookies and TLS session tickets to JSON
- **Fingerprint randomization** — slight jitter on UA build number, accept-language q-values, H2 window sizes
- **Response decompression** — gzip, brotli, deflate, zstd (automatic)
- **Local address binding** — bind outgoing connections to a specific local IP (multi-IP servers, IP rotation)
- **Connection pooling** — H3 multiplexed + H2 multiplexed + H1.1 keep-alive
- **Custom redirect hook** — `onRedirect(status, url, headers) → bool` to intercept and stop redirects (captcha detection, geo-block handling)
- **Automatic retry** — retry on transport errors (connection, TLS, timeout) with automatic proxy rotation
- **Request hooks** — `onRequest`/`onResponse` observe-only callbacks for logging and debugging
- **Proxy rotation** — round-robin over multiple proxy URLs, proxy-aware connection pool
- **Bandwidth tracking** — per-request `bytesSent`/`bytesReceived` + cumulative counters on the client
- **String body** — `post()`, `put()`, `patch()` accept strings directly (no `Buffer.from()` needed)
- **User-Agent property** — `client.userAgent` exposes the profile UA for Puppeteer/Playwright sync
- **Geo-locale matching** — `locale: 'fr-FR'` generates Accept-Language matching proxy geography
- **Structured errors** — machine-readable `[CODE]` prefix on all errors (TIMEOUT, TLS_ERROR, PROXY_ERROR, etc.)
- **Connection info** — `resp.tlsResumed` and `resp.connectionReused` for debugging connection behavior
- **CONNECT proxy headers** — custom headers in the HTTP CONNECT tunnel (session IDs, geo-targeting for Bright Data, Oxylabs)
- **IPv4/IPv6 toggle** — restrict DNS resolution to a specific IP version
- **Mobile browser profiles** — Chrome Mobile (Android), Firefox Mobile (Android), Safari Mobile (iOS) with platform-specific TLS/H2 fingerprints
- **OkHttp profiles** — Android app impersonation (OkHttp 4.x, 5.x) with Conscrypt TLS stack fingerprint

## Usage

### Node.js

```javascript
const { Koon } = require('koonjs');

// Browser profile + options
const client = new Koon({
  browser: 'chrome145',
  headers: { 'X-Custom': 'value' },
  proxy: 'socks5://127.0.0.1:1080',  // optional
  localAddress: '192.168.1.100',      // optional: bind to specific IP
  randomize: true,                     // optional: slight fingerprint jitter
  retries: 3,                          // optional: retry on transport errors
  locale: 'fr-FR',                     // optional: Accept-Language for proxy geo
  ipVersion: 4,                        // optional: force IPv4 DNS resolution
  proxyHeaders: {                      // optional: CONNECT tunnel headers
    'X-Session-Id': 'abc123',
  },
  onRedirect: (status, url, headers) => {
    return !url.includes('captcha');   // stop if redirect goes to captcha
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
console.log(client.userAgent);  // "Mozilla/5.0 ... Chrome/145..."

// Response
console.log(r1.ok);                             // true (status 2xx)
console.log(r1.status);                         // 200
console.log(r1.text());                         // body as UTF-8 string
console.log(r1.json());                         // parsed JSON
console.log(r1.header('content-type'));          // case-insensitive header lookup
console.log(r1.body);                           // raw Buffer
console.log(r1.tlsResumed);                     // TLS session was reused
console.log(r1.connectionReused);               // pooled connection was reused
console.log(r1.bytesSent, r1.bytesReceived);    // bandwidth per request

// Per-request headers and timeout
const r7 = await client.get('https://httpbin.org/get', {
  headers: { 'Authorization': 'Bearer token' },
  timeout: 5000,  // 5s timeout for this request only
});

// Cookies persist automatically
await client.get('https://httpbin.org/cookies/set/name/value');
const r = await client.get('https://httpbin.org/cookies');

// Clear cookies (keeps TLS sessions and connection pool)
client.clearCookies();

// Session save/load
const session = client.saveSession();           // JSON string
const client2 = new Koon({ browser: 'chrome145' });
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
const body = await stream.collect();  // or iterate with nextChunk()

// Multipart upload
await client.postMultipart('https://httpbin.org/post', [
  { name: 'field', value: 'text' },
  { name: 'file', fileData: Buffer.from('...'), filename: 'upload.txt', contentType: 'text/plain' },
]);

// MITM proxy
const { KoonProxy } = require('koonjs');
const proxy = await KoonProxy.start({ browser: 'chrome145', listenAddr: '127.0.0.1:8080' });
console.log(proxy.url);         // http://127.0.0.1:8080
console.log(proxy.caCertPath);  // path to CA cert for trust
await proxy.shutdown();
```

### Python

```python
import asyncio
from koon import Koon

async def main():
    client = Koon("chrome145",
        headers={"X-Custom": "value"},
        local_address="192.168.1.100",
        retries=3,  # retry on transport errors
        locale="fr-FR",  # Accept-Language for proxy geo
        ip_version=4,  # force IPv4 DNS resolution
        proxy_headers={"X-Session-Id": "abc123"},  # CONNECT tunnel headers
        on_redirect=lambda s, u, h: "captcha" not in u,  # stop on captcha redirect
    )

    # HTTP methods
    r = await client.get("https://httpbin.org/get")
    r = await client.post("https://httpbin.org/post", "data")
    r = await client.put("https://httpbin.org/put", "data")
    r = await client.delete("https://httpbin.org/delete")
    r = await client.patch("https://httpbin.org/patch", "data")
    r = await client.head("https://httpbin.org/get")

    # User-Agent (useful for Puppeteer/Playwright sync)
    print(client.user_agent)  # "Mozilla/5.0 ... Chrome/145..."

    # Response
    print(r.ok)                 # True (status 2xx)
    print(r.status)             # 200
    print(r.text)               # body as string (property)
    print(r.json())             # parsed JSON
    print(r.header("content-type"))  # case-insensitive header lookup
    print(r.tls_resumed)        # TLS session was reused
    print(r.connection_reused)  # pooled connection was reused
    print(r.bytes_sent, r.bytes_received)  # bandwidth per request

    # Per-request headers and timeout
    r = await client.get("https://httpbin.org/get",
        headers={"Authorization": "Bearer token"},
        timeout=5000,  # 5s timeout for this request only
    )

    # Cookies persist automatically
    await client.get("https://httpbin.org/cookies/set/name/value")
    r = await client.get("https://httpbin.org/cookies")

    # Clear cookies (keeps TLS sessions and connection pool)
    client.clear_cookies()

    # Session save/load
    session = client.save_session()
    client2 = Koon("chrome145")
    client2.load_session(session)

    # WebSocket
    ws = await client.websocket("wss://echo.websocket.org")
    await ws.send("hello")
    msg = await ws.receive()
    await ws.close()

    # Streaming
    stream = await client.request_streaming("GET", "https://example.com/large")
    body = await stream.collect()

    # Multipart upload
    await client.post_multipart("https://httpbin.org/post", [
        {"name": "field", "value": "text"},
        {"name": "file", "file_data": b"...", "filename": "upload.txt", "content_type": "text/plain"},
    ])

    # MITM proxy
    from koon import KoonProxy
    proxy = await KoonProxy.start(browser="chrome145", listen_addr="127.0.0.1:8080")
    print(proxy.url)
    await proxy.shutdown()

asyncio.run(main())
```

### R

```r
library(koon)

# Browser profile + options
client <- Koon$new("chrome145", proxy = "socks5://127.0.0.1:1080", randomize = TRUE,
                    local_address = "192.168.1.100", retries = 3L,
                    locale = "fr-FR", ip_version = 4L,
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
resp$version    # "HTTP/2.0"
resp$text       # body as string
resp$body       # raw vector
resp$headers    # data.frame with name + value columns

# Parse JSON (via jsonlite)
data <- jsonlite::fromJSON(resp$text)

# Per-request headers
resp <- client$get("https://httpbin.org/get",
  headers = c(Authorization = "Bearer token")
)

# Cookies persist automatically
client$get("https://httpbin.org/cookies/set/name/value")
resp <- client$get("https://httpbin.org/cookies")

# Clear cookies (keeps TLS sessions and connection pool)
client$clear_cookies()

# Session save/load
json <- client$save_session()
client2 <- Koon$new("chrome145")
client2$load_session(json)

# Export profile as JSON
client$export_profile()

# List all browsers
koon_browsers()
```

### CLI

```bash
# GET with browser profile
koon -b chrome145 https://example.com

# POST with body
koon -b firefox147 -X POST -d '{"key":"value"}' https://httpbin.org/post

# Custom headers
koon -b safari18.3 -H "Authorization: Bearer token" https://api.example.com

# Verbose output (request/response headers)
koon -b chrome145 -v https://httpbin.org/get

# JSON output
koon -b chrome145 --json https://httpbin.org/get

# Save response to file
koon -b chrome145 -o page.html https://example.com

# Proxy
koon -b chrome145 --proxy socks5://127.0.0.1:1080 https://example.com

# Session persistence
koon -b chrome145 --save-session session.json https://example.com/login
koon -b chrome145 --load-session session.json https://example.com/dashboard

# DNS-over-HTTPS
koon -b chrome145 --doh cloudflare https://example.com

# OS-specific user-agent
koon -b chrome145-macos https://example.com

# Fingerprint randomization
koon -b chrome145 --randomize https://example.com

# List all browser profiles
koon --list-browsers

# Export profile as JSON
koon --export-profile chrome145

# Start MITM proxy
koon proxy --browser chrome145 --listen 127.0.0.1:8080
```

### Rust

```toml
[dependencies]
koon-core = { git = "https://github.com/scrape-hub/koon.git" }
```

```rust
use koon_core::{BrowserProfile, Client};
use koon_core::profile::Chrome;

#[tokio::main]
async fn main() -> Result<(), koon_core::Error> {
    // From a specific profile constructor
    let client = Client::new(Chrome::v145_windows())?;

    // Or with builder for full control
    let profile = BrowserProfile::resolve("chrome145")?;
    let client = Client::builder(profile)
        .max_retries(3)
        .locale("fr-FR")
        .ip_version(koon_core::IpVersion::V4)
        .on_redirect(|status, url, _headers| {
            !url.contains("captcha")
        })
        .build()?;

    let r = client.get("https://example.com").await?;
    println!("{} {} ({} bytes)", r.status, r.version, r.body.len());

    // Clear cookies without resetting TLS/pool
    client.clear_cookies();

    Ok(())
}
```

## Architecture

```
koon-core         Rust library — TLS, HTTP/2, HTTP/3, profiles, proxy
koon-node         Node.js native addon via napi-rs
koon-python       Python extension via PyO3 + maturin
koon-r            R package via extendr
koon-cli          Command-line interface via clap
```

Key dependencies:
- [boring2](https://github.com/0x676e67/boring2) — BoringSSL Rust bindings
- [http2](https://github.com/scrape-hub/http2) (fork) — HTTP/2 with header field ordering
- [quinn](https://github.com/quinn-rs/quinn) + [h3](https://github.com/hyperium/h3) — QUIC / HTTP/3
- [napi-rs](https://napi.rs) — Rust to Node.js bridge
- [PyO3](https://pyo3.rs) + [maturin](https://github.com/PyO3/maturin) — Rust to Python bridge
- [extendr](https://extendr.rs) — Rust to R bridge

## Building from source

Only needed if you want to build koon yourself instead of using the published packages.

**Requirements:**
- Rust 1.85+
- CMake
- NASM (Windows only, for BoringSSL assembly)
- C compiler — MSVC (Windows), GCC or Clang (Linux/macOS)

```bash
# Core library
cargo build --release -p koon-core

# Node.js addon
cargo build --release -p koon-node

# Python package
cd crates/python && pip install -e .

# R package
cd crates/r && Rscript -e "rextendr::document(); devtools::install()"

# CLI binary
cargo build --release -p koon-cli
```

## License

[MIT](LICENSE)
