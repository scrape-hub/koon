# Changelog

All notable changes to koon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.6.3] - 2026-03-23

### Fixed

- **KoonSync event loop** (Python) — coroutine creation now deferred inside running event loop, fixing `RuntimeError: no running event loop`
- **R error handling** — request errors no longer crash the R session; errors are catchable via `tryCatch()`
- **R `Koon` export** — `Koon` class is now properly exported and callable without full namespace prefix
- **R default arguments** — optional parameters (`proxy`, `headers`, `timeout`, etc.) now default to `NULL` instead of being required

### Changed

- **SEO metadata** — added keywords, classifiers, and descriptions to PyPI, npm, and crates.io for better discoverability
- **npm README** — package now includes the full README on the npm page
- **CI** — added macOS Python wheel builds (arm64 + x64); npm publish now copies README into package

## [0.6.2] - 2026-03-23

### Fixed

- **Proxy auth for HTTP CONNECT** — Credentials from the proxy URL (`http://user:pass@host:port`) are now automatically sent as `Proxy-Authorization: Basic` header in the CONNECT request. Previously required manual `proxy_headers`. SOCKS5 auth was not affected.

### Added

- **`status_code` alias** (Node.js, Python, R) — `response.status_code` as alias for `response.status`
- **`KoonSync` Python wrapper** — Synchronous API for Python (`from koon import KoonSync`). Covers all HTTP methods without requiring `asyncio`. WebSocket and streaming remain async-only.
- **Per-request proxy** (Node.js, Python) — `proxy` parameter on `.get()`, `.post()` etc. allows switching proxies per request without creating a new client

## [0.6.1] - 2026-03-18

### Changed

- **Node.js: modular platform packages** — Native binaries are now distributed as separate npm packages (`koonjs-win32-x64-msvc`, `koonjs-linux-x64-gnu`, `koonjs-darwin-arm64`, `koonjs-darwin-x64`) via `optionalDependencies`. npm installs only the binary for your platform, reducing download size from ~30 MB to ~8 MB.
- **macOS support** — Added macOS binaries for Apple Silicon (arm64) and Intel (x64) to the Node.js package and CLI

[0.6.3]: https://github.com/scrape-hub/koon/releases/tag/v0.6.3
[0.6.2]: https://github.com/scrape-hub/koon/releases/tag/v0.6.2
[0.6.1]: https://github.com/scrape-hub/koon/releases/tag/v0.6.1

## [0.6.0] - 2026-03-17

First public release.

### Features

- **175 browser profiles** — Chrome 131–145, Firefox 135–148, Safari 15.6–18.3, Edge 131–145, Opera 124–127, OkHttp 4/5
- **Mobile profiles** — Chrome Mobile (Android), Firefox Mobile (Android), Safari Mobile (iOS) with platform-specific TLS/H2 fingerprints
- **TLS fingerprinting** — Cipher list, curves, sigalgs, extension order, GREASE, ALPS, cert compression (Brotli/Zlib/Zstd), delegated credentials. JA3/JA4 verified against real browser captures
- **HTTP/2 fingerprinting** — SETTINGS order, pseudo-header order, stream dependencies, PRIORITY frames, WINDOW_UPDATE. Akamai hash verified
- **HTTP/3 (QUIC)** — Alt-Svc discovery, QUIC transport parameter fingerprinting, H3 connection pooling, proxy fallback
- **Encrypted Client Hello (ECH)** — Real ECH from DNS HTTPS records with GREASE fallback
- **DNS-over-HTTPS** — Cloudflare and Google resolvers with ECH config discovery
- **TLS session resumption** — Automatic session ticket caching across requests
- **Cookie jar** — Domain/path matching, Expires/Max-Age, Secure/HttpOnly/SameSite
- **Proxy** — HTTP CONNECT + SOCKS5, with proxy rotation (round-robin over multiple URLs)
- **MITM proxy server** — Local proxy that re-sends traffic through koon's fingerprinted TLS/HTTP2 stack
- **WebSocket (wss://)** — Over fingerprinted TLS handshake
- **Streaming responses** — Chunked body streaming with async iterator support (Node.js, Python)
- **Multipart form-data** — File uploads with custom content types
- **Session persistence** — Save/load cookies and TLS session tickets to JSON
- **Fingerprint randomization** — Subtle jitter on UA build number, accept-language q-values, H2 window sizes
- **Response decompression** — gzip, brotli, deflate, zstd (automatic)
- **Connection pooling** — H3 multiplexed + H2 multiplexed + H1.1 keep-alive
- **Automatic retry** — Retry on transport errors with proxy rotation
- **Custom redirect hook** — Intercept and stop redirects (captcha detection, geo-block handling)
- **Request hooks** — `onRequest`/`onResponse` observe-only callbacks for logging
- **Per-request headers and timeout** — Override defaults per request
- **Ergonomic response API** — `ok`, `text()`, `json()`, `header()`, `contentType` on every response
- **Charset-aware `text()` decoding** — respects the charset from the Content-Type header (Shift_JIS, ISO-8859-1, Windows-1252, etc.) via `encoding_rs`. Falls back to UTF-8
- **Structured errors** — Machine-readable `[CODE]` prefix (TIMEOUT, TLS_ERROR, PROXY_ERROR, etc.)
- **Connection info** — `tlsResumed`, `connectionReused`, `remoteAddress` on responses
- **Bandwidth tracking** — Per-request and cumulative byte counters
- **Local address binding** — Bind outgoing connections to a specific local IP
- **Geo-locale matching** — Generate Accept-Language headers matching proxy geography
- **CONNECT proxy headers** — Custom headers in the HTTP CONNECT tunnel
- **IPv4/IPv6 toggle** — Restrict DNS resolution to a specific IP version
- **User-Agent property** — Access the profile UA for Puppeteer/Playwright sync
- **Header order preservation** — HTTP/2 (via forked h2) and HTTP/1.1
- **Chromium CORS header ordering** — Automatic sec-fetch-* and CORS header handling

### Platforms

- **Node.js** — `npm install koonjs` (Windows x64, Linux x64, macOS arm64, macOS x64)
- **Python** — `pip install koon` (Windows x64, Linux x64)
- **R** — `remotes::install_github("scrape-hub/koon", subdir = "crates/r")`
- **CLI** — Download from [GitHub Releases](https://github.com/scrape-hub/koon/releases)
- **Rust** — `koon-core` crate (from source)

### Breaking Changes (vs pre-release versions)

- **Timeout unit changed from milliseconds to seconds** across all bindings (Node.js, Python, R). The CLI already used seconds. If you used `timeout: 30000`, change to `timeout: 30`.

[0.6.0]: https://github.com/scrape-hub/koon/releases/tag/v0.6.0
