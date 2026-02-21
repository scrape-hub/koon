# koon

Browser-impersonating HTTP client. Matches real browser TLS, HTTP/2, and HTTP/3 fingerprints to bypass bot detection (Akamai, Cloudflare, etc.).

Built in Rust with BoringSSL. Bindings for Node.js (napi-rs) and Python (PyO3).

## Features

- **134 browser profiles** — Chrome 131-145, Firefox 135-147, Safari 15.6-18.3, Edge 131-145, Opera 124-127
- **TLS fingerprint** — JA3/JA4 match via cipher list, curves, sigalgs, extensions, GREASE, ALPS, ECH
- **HTTP/2 fingerprint** — Akamai hash match via settings order, pseudo-header order, priority frames, window sizes
- **HTTP/3 (QUIC)** — Alt-Svc discovery, QUIC transport fingerprinting, connection pooling
- **Header order** — Preserved in both HTTP/2 (forked h2 crate) and HTTP/1.1
- **Cookie jar** — Automatic cookie persistence with domain/path/expiry matching
- **Proxy** — HTTP CONNECT and SOCKS5
- **MITM proxy server** — Local proxy that re-sends traffic with fingerprinted TLS/H2
- **WebSocket** — `wss://` with browser-matching TLS handshake
- **Streaming** — Chunked response body streaming
- **Multipart** — Form-data file uploads
- **Session persistence** — Save/load cookies and TLS session tickets
- **DNS-over-HTTPS** — Cloudflare/Google DoH with ECH support
- **Fingerprint randomization** — Slight jitter on UA build, accept-language q-values, H2 windows
- **OS variants** — Windows, macOS, Linux user-agents per profile

## CLI

```bash
# Build
cargo build --release -p koon-cli

# Simple GET
koon https://example.com

# Browser profile + verbose
koon -b firefox147 -v https://httpbin.org/get

# POST with body
koon -b chrome145 -X POST -d '{"key":"value"}' https://httpbin.org/post

# Custom headers
koon -b safari18.3 -H "Authorization: Bearer token" https://api.example.com

# JSON output (status, headers, body)
koon -b chrome145 --json https://httpbin.org/get

# Save to file
koon -b chrome145 -o response.html https://example.com

# With proxy
koon -b chrome145 --proxy socks5://127.0.0.1:1080 https://example.com

# Session persistence
koon -b chrome145 --save-session session.json https://example.com/login
koon -b chrome145 --load-session session.json https://example.com/dashboard

# Fingerprint randomization
koon -b chrome145 --randomize https://example.com

# DNS-over-HTTPS
koon -b chrome145 --doh cloudflare https://example.com

# OS-specific profile
koon -b chrome145-macos https://example.com

# List all profiles
koon --list-browsers

# Export profile as JSON
koon --export-profile chrome145

# MITM proxy server
koon proxy --browser chrome145 --listen 127.0.0.1:8080
```

## Node.js

```bash
# Build native addon
cargo build --release -p koon-node
# Copy: target/release/koon_node.dll -> ./koon.win32-x64-msvc.node (Windows)
# Copy: target/release/libkoon_node.so -> ./koon.linux-x64-gnu.node (Linux)
# Copy: target/release/libkoon_node.dylib -> ./koon.darwin-x64.node (macOS)
```

```javascript
const { Koon } = require('./koon.win32-x64-msvc.node');

// GET request
const client = new Koon({ browser: 'chrome145' });
const response = await client.get('https://example.com');
console.log(response.status);                          // 200
console.log(response.version);                         // "HTTP/2.0"
console.log(Buffer.from(response.body).toString());    // HTML

// POST
const r = await client.post('https://httpbin.org/post', Buffer.from('data'));

// Custom headers
const custom = new Koon({ browser: 'firefox147', headers: { 'X-Custom': 'value' } });

// With proxy
const proxied = new Koon({ browser: 'chrome145', proxy: 'socks5://127.0.0.1:1080' });

// Randomized fingerprint
const rand = new Koon({ browser: 'chrome145', randomize: true });

// Cookie persistence
await client.get('https://httpbin.org/cookies/set/name/value');
const cookies = await client.get('https://httpbin.org/cookies');
// cookies.body contains {"cookies": {"name": "value"}}

// Session save/load
const session = client.saveSession();
const client2 = new Koon({ browser: 'chrome145' });
client2.loadSession(session);

// WebSocket
const ws = await client.websocket('wss://echo.websocket.org');
await ws.send('hello');
const msg = await ws.receive();
await ws.close();

// Streaming
const stream = await client.requestStreaming('GET', 'https://example.com/large');
console.log(stream.status);
const body = await stream.collect();

// Multipart upload
const r = await client.postMultipart('https://httpbin.org/post', [
  { name: 'field', value: 'text' },
  { name: 'file', fileData: Buffer.from('content'), filename: 'test.txt', contentType: 'text/plain' },
]);

// Profile export
console.log(client.exportProfile()); // Full JSON profile
```

## Python

```bash
# Build and install
cd crates/python
pip install -e .
```

```python
import asyncio
from koon import Koon

async def main():
    # GET request
    client = Koon("chrome145")
    r = await client.get("https://example.com")
    print(r.status)         # 200
    print(r.version)        # "HTTP/2.0"
    print(r.text())         # HTML

    # POST
    r = await client.post("https://httpbin.org/post", b"data")
    print(r.json())

    # Custom headers
    custom = Koon("firefox147", headers={"X-Custom": "value"})

    # With proxy
    proxied = Koon("chrome145", proxy="socks5://127.0.0.1:1080")

    # Randomized fingerprint
    rand = Koon("chrome145", randomize=True)

    # Cookie persistence
    await client.get("https://httpbin.org/cookies/set/name/value")
    r = await client.get("https://httpbin.org/cookies")
    print(r.json()["cookies"])  # {"name": "value"}

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
    r = await client.post_multipart("https://httpbin.org/post", [
        {"name": "field", "value": "text"},
        {"name": "file", "file_data": b"content", "filename": "test.txt", "content_type": "text/plain"},
    ])

asyncio.run(main())
```

## Rust (as library)

```toml
[dependencies]
koon-core = { git = "https://github.com/hrylx/koon.git" }
```

```rust
use koon_core::{BrowserProfile, Client};
use koon_core::profile::Chrome;

#[tokio::main]
async fn main() {
    let profile = Chrome::v145_windows();
    let client = Client::new(profile);

    let response = client.get("https://example.com").await.unwrap();
    println!("{} {}", response.status, response.version);
    println!("{}", String::from_utf8_lossy(&response.body));
}
```

## Build requirements

- Rust 1.85+
- CMake (for BoringSSL)
- NASM (for BoringSSL asm on Windows)
- Visual Studio Build Tools (Windows) or GCC/Clang (Linux/macOS)
- Python 3.9+ and maturin (for Python bindings)

## License

MIT
