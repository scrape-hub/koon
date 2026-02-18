# Changelog

All notable changes to koon will be documented in this file.

## [0.1.0] - 2026-02-19

### Added

#### Core
- **TLS Fingerprinting**: BoringSSL-based TLS with JA3/JA4 fingerprint control
  - Cipher suites, curves, signature algorithms, GREASE, extension permutation
  - ECH GREASE, ALPS, OCSP stapling, SCT, cert compression (Brotli/Zlib/Zstd)
  - Delegated credentials, PSK, session tickets, key shares limit
- **HTTP/2 Fingerprinting**: Frame-level control via `http2` crate (unstable features)
  - Settings order, pseudo-header order, stream dependency, window sizes
  - Akamai fingerprint matching
- **HTTP/1.1 Support**: Header-order-preserving requests with chunked transfer encoding
- **WebSocket (wss://)**: Manual HTTP/1.1 Upgrade handshake over fingerprinted TLS
  - `PrefixedStream` for leftover byte replay after upgrade
  - Text/binary send/receive, close with code+reason
  - Force HTTP/1.1-only ALPN (no h2) for WebSocket connections
- **Cookie Jar**: Automatic cookie management
  - Domain/path matching, host-only cookies
  - Expires/Max-Age support with HTTP date parsing
  - Secure, HttpOnly, SameSite attributes
- **Connection Pool**: H2 multiplexed + H1.1 keep-alive connection reuse
- **Redirect Following**: 301/302/303/307/308 with configurable max redirects
  - Method/body preservation for 307/308, POST-to-GET for others
  - Relative URL resolution
- **Response Decompression**: gzip, deflate, brotli, zstd (auto-detected)
- **Proxy Support**: HTTP CONNECT tunnel + SOCKS5 (optional feature)
- **JSON Profile System**: `BrowserProfile::from_json()`, `to_json_pretty()`, `from_file()`
  - Export/import profiles for customization
- **Root CA Certificates**: Mozilla bundle via `webpki-root-certs` (cross-platform)

#### Browser Profiles
- **Chrome**: v131 (Windows/macOS/Linux), v145 (Windows/macOS/Linux)
- **Firefox**: v135 (Windows/macOS/Linux)
- **Safari**: v18.3 (macOS)
- **Edge**: v131 (Windows/macOS)

#### Node.js Bindings (`koon-node`)
- `Koon` class with `get`, `post`, `put`, `delete`, `patch`, `head`, `request`
- `KoonWebSocket` class with `send`, `receive`, `close`
- `KoonOptions`: browser selection, custom profile JSON, proxy, timeout, headers, redirects, cookies
- `KoonResponse`: status, headers (preserving duplicates), body (Buffer), version, url
- `KoonWsMessage`: is_text flag + data Buffer
- `exportProfile()` for JSON profile export

#### Python Bindings (`koon-python`)
- `Koon` class with `get`, `post`, `put`, `delete`, `patch`, `head`, `request`
- `KoonWebSocket` class with `send`, `receive`, `close`, `async with` support
- Constructor: browser selection, custom profile JSON, proxy, timeout, headers, redirects, cookies
- `KoonResponse`: status, headers (list of tuples), body (bytes), text, version, url, `json()`
- `export_profile()` for JSON profile export
- Built with PyO3 + maturin, async via `pyo3-async-runtimes` (tokio)

#### Build
- Workspace with `default-members = ["crates/core"]` to avoid napi warnings in `cargo test`
- Release profile: strip, opt-level "z", LTO, single codegen unit
