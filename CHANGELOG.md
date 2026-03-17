# Changelog

All notable changes to koon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-03-17

First public release.

### Features

- **`contentType` getter** on responses (Node.js, Python, R) — convenience accessor for the Content-Type header value
- **Charset-aware `text()` decoding** — responses now respect the charset from the Content-Type header (e.g. Shift_JIS, ISO-8859-1, Windows-1252) instead of assuming UTF-8. Powered by `encoding_rs` (Mozilla's encoding engine). Falls back to UTF-8 when no charset is specified.

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
- **Ergonomic response API** — `ok`, `text()`, `json()`, `header()` on every response
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

- **Node.js** — `npm install koonjs` (Windows x64, Linux x64)
- **Python** — `pip install koon` (Windows x64, Linux x64)
- **R** — `remotes::install_github("scrape-hub/koon", subdir = "crates/r")`
- **CLI** — Download from [GitHub Releases](https://github.com/scrape-hub/koon/releases)
- **Rust** — `koon-core` crate (from source)

### Breaking Changes (vs pre-release versions)

- **Timeout unit changed from milliseconds to seconds** across all bindings (Node.js, Python, R). The CLI already used seconds. If you used `timeout: 30000`, change to `timeout: 30`.

[0.6.0]: https://github.com/scrape-hub/koon/releases/tag/v0.6.0
