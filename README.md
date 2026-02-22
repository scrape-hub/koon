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

| Browser | Versions | Profiles |
|---------|----------|----------|
| Chrome | 131 - 145 | 15 |
| Firefox | 135 - 147 | 13 |
| Safari | 15.6 - 18.3 | 11 |
| Edge | 131 - 145 | 15 |
| Opera | 124 - 127 | 4 |

Each profile includes Windows, macOS, and Linux user-agent variants (`chrome145-macos`, `firefox147-linux`, etc.). **134 profiles** total.

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
- **Connection pooling** — H3 multiplexed + H2 multiplexed + H1.1 keep-alive

## Usage

### Node.js

```javascript
const { Koon } = require('koonjs');

// Browser profile + options
const client = new Koon({
  browser: 'chrome145',
  headers: { 'X-Custom': 'value' },
  proxy: 'socks5://127.0.0.1:1080',  // optional
  randomize: true,                     // optional: slight fingerprint jitter
});

// HTTP methods
const r1 = await client.get('https://httpbin.org/get');
const r2 = await client.post('https://httpbin.org/post', Buffer.from('data'));
const r3 = await client.put('https://httpbin.org/put', Buffer.from('data'));
const r4 = await client.delete('https://httpbin.org/delete');
const r5 = await client.patch('https://httpbin.org/patch', Buffer.from('data'));
const r6 = await client.head('https://httpbin.org/get');

// Response
console.log(r1.ok);                             // true (status 2xx)
console.log(r1.status);                         // 200
console.log(r1.text());                         // body as UTF-8 string
console.log(r1.json());                         // parsed JSON
console.log(r1.header('content-type'));          // case-insensitive header lookup
console.log(r1.body);                           // raw Buffer

// Per-request headers and timeout
const r7 = await client.get('https://httpbin.org/get', {
  headers: { 'Authorization': 'Bearer token' },
  timeout: 5000,  // 5s timeout for this request only
});

// Cookies persist automatically
await client.get('https://httpbin.org/cookies/set/name/value');
const r = await client.get('https://httpbin.org/cookies');

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
    client = Koon("chrome145", headers={"X-Custom": "value"})

    # HTTP methods
    r = await client.get("https://httpbin.org/get")
    r = await client.post("https://httpbin.org/post", b"data")
    r = await client.put("https://httpbin.org/put", b"data")
    r = await client.delete("https://httpbin.org/delete")
    r = await client.patch("https://httpbin.org/patch", b"data")
    r = await client.head("https://httpbin.org/get")

    # Response
    print(r.ok)        # True (status 2xx)
    print(r.status)    # 200
    print(r.text)      # body as string (property)
    print(r.json())    # parsed JSON
    print(r.header("content-type"))  # case-insensitive header lookup

    # Per-request headers and timeout
    r = await client.get("https://httpbin.org/get",
        headers={"Authorization": "Bearer token"},
        timeout=5000,  # 5s timeout for this request only
    )

    # Cookies persist automatically
    await client.get("https://httpbin.org/cookies/set/name/value")
    r = await client.get("https://httpbin.org/cookies")

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
client <- Koon$new("chrome145", proxy = "socks5://127.0.0.1:1080", randomize = TRUE)

# HTTP methods (synchronous)
resp <- client$get("https://httpbin.org/get")
resp <- client$post("https://httpbin.org/post", charToRaw("data"))
resp <- client$put("https://httpbin.org/put", charToRaw("data"))
resp <- client$delete("https://httpbin.org/delete")
resp <- client$patch("https://httpbin.org/patch", charToRaw("data"))
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
    let client = Client::new(Chrome::v145_windows());

    // Or resolve by name (supports "chrome145", "firefox147-linux", etc.)
    let profile = BrowserProfile::resolve("chrome145")?;
    let client = Client::new(profile);

    let r = client.get("https://example.com").await?;
    println!("{} {} ({} bytes)", r.status, r.version, r.body.len());

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
