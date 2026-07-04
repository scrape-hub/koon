# Changelog

All notable changes to koon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.8.0] - 2026-07-04

### Security

- **Cookie domain validation** — `Set-Cookie` with an explicit `Domain` is now
  validated per RFC 6265: it must domain-match the request host and must not be
  scoped to a public suffix (via the embedded Public Suffix List). Prevents a
  response from one host injecting cookies for an unrelated host (`evil.com`
  setting `Domain=bank.com`) or sharing a cookie across an entire eTLD
  (`foo.co.uk` setting `Domain=co.uk`).
- **Sensitive headers stripped on cross-origin redirects** — caller-supplied
  `Authorization`, `Cookie`, and `Proxy-Authorization` headers are now removed
  when a redirect crosses origin (scheme, host, or port), matching browser and
  reqwest behavior. Previously they leaked to the redirect target.

### Fixed

- **Alt-Svc `ma=` overflow panic** — a malicious `alt-svc: h3=":443"; ma=<huge>`
  header no longer panics the request task via `Instant + Duration` overflow
  (now uses `checked_add` with a fallback, like the cookie path).
- **HTTP CONNECT tunnel** — the proxy response is now parsed properly (status
  line `HTTP/1.x 200`) instead of substring-matching `"200"` anywhere in the
  response, reads until the end of headers, and is bounded by the client
  timeout so a silent proxy can't hang the connection.
- **Retry safety** — automatic retries no longer replay non-idempotent methods
  (POST/PATCH) after the body was sent, avoiding duplicate submissions. Such
  methods are retried only on errors that provably occur before the body is
  sent (connection/TLS/proxy setup).
- **HTTP/2 and HTTP/3 body-read timeout** — response body reads are now bounded
  by the timeout, closing a Slowloris-style hang where a server sent headers
  then stalled the body. HTTP/3 previously had no timeout at all.
- **HTTP/3 connection reuse** — pooled H3 connections are now keyed by the
  origin port instead of the advertised Alt-Svc port, restoring connection
  reuse when a server advertises H3 on a non-443 port.
- **Poison-resistant locks** — the cookie jar, Alt-Svc cache, TLS session
  cache, DNS/DoH caches, MITM leaf-cert cache, and QUIC endpoint now recover
  from a poisoned mutex instead of cascading panics that permanently break the
  client (matching the connection pool's existing strategy).
- **`timeout = 0` now means "no timeout"** across all bindings, instead of
  silently failing every request instantly (`Duration::ZERO` applied to
  `tokio::time::timeout`).
- **Node.js: byte counters no longer truncate** — per-response `bytesSent` /
  `bytesReceived` are returned as `BigInt` (u64) instead of being cast to u32,
  fixing silent overflow above 4 GB.
- **Node.js / Python: no more `blocking_lock()`** in synchronous getters —
  `bytesReceived` uses `try_lock()`, and the MITM proxy's CA PEM is cached at
  startup, removing a panic risk and event-loop stall.
- **Node.js: streaming requests honor a per-request proxy** — `requestStreaming`
  no longer silently ignores `opts.proxy`.
- **Node.js: default-profile resolution errors** now throw an exception instead
  of aborting the Node process via the panic hook.
- **R: negative `timeout` / `max_redirects`** no longer wrap into huge values
  (a negative `timeout` silently became an effectively infinite one).
- **R package now builds end-to-end** via `R CMD INSTALL` (previously only
  `cargo check` had been run, which builds the staticlib but never links or
  loads it, so several build breakages went unnoticed). Fixed: auto-detected
  clang/Rtools/gcc include paths (no hard-coded toolchain versions), a relative
  `koon-core` path instead of an absolute one, gnu compiler selection for
  BoringSSL (CMake was picking MSVC `cl`), `-lstdc++` linkage for BoringSSL's
  C++ code, and R wrappers (`zzz.R`, `extendr-wrappers.R`) synced with the new
  constructor/method signatures.

### Added

- **New browser profiles** — Chrome 146–150, Firefox 149–152, Edge 146–149,
  Opera 128–133, and Safari 26.0–26.5 (macOS + iOS). Safari adopts Apple's 2025
  year-based version scheme; 26.x reuses the verified 18.x TLS/H2 fingerprint.
- **Core: `request_streaming_with_headers_and_proxy`** — per-request proxy
  override for streaming requests.
- **Python: streaming and multipart parity** — `request_streaming` now accepts
  `headers`, `timeout`, and `proxy`; `post_multipart` accepts `headers`,
  `timeout`, and `proxy`; added a `close()` method.
- **R: parity improvements** — `profile_json` constructor argument (load custom
  JSON profiles), a generic `request(method, ...)` for arbitrary HTTP methods,
  a per-request `timeout`, and structured error messages with a `[CODE]` prefix
  (e.g. `[TIMEOUT]`, `[TLS_ERROR]`).

## [0.7.0] - 2026-03-24

### Changed

- **BoringSSL migration** — Migrated from `boring2` to `btls` v0.5.5 (same author, new crate name). Affects `btls`, `tokio-btls`, and new `quinn-btls` fork for QUIC.
- **HTTP/3 per-browser TLS fingerprint** — QUIC/H3 connections now use the same TLS configuration as H2 (cipher list, curves, sigalgs, GREASE, cert compression, delegated credentials, record size limit). Previously H3 always used Chrome-default TLS regardless of profile. Firefox H3 now sends Firefox TLS (3 TLS 1.3 ciphers, no GREASE, record_size_limit), Chrome H3 sends Chrome TLS, etc.
- **Default OS changed to macOS** — Chrome, Firefox, Edge, and Opera profiles now default to macOS when no OS is specified (e.g. `Chrome::v145()` returns macOS). Windows and Linux remain available via explicit constructors. Validated with 89-site testsuite: no regressions vs. Windows profiles.
- **HTTP/3 certificate verification enabled** — QUIC connections now verify server certificates via `webpki-root-certs` (Mozilla CA bundle), replacing the previous `verify_peer(false)` workaround that was needed because BoringSSL's `set_default_verify_paths()` fails on Windows.

### Fixed

- **Protocol-relative redirect URLs** — Redirects to `//host/path` URLs (without scheme) are now handled correctly, inheriting the scheme from the original request.
- **HTTP/3 Cloudflare compatibility** — Fixed GREASE frame ordering bug in h3 crate (hyperium/h3#206) that caused Cloudflare to reject H3 requests with 400. GREASE is now disabled for H3 connections. Also added `max_field_section_size` to H3 SETTINGS.

### Internal

- **quinn-btls fork** — Created [scrape-hub/btls](https://github.com/scrape-hub/btls) fork adding `Config::from_builder(SslContextBuilder)` to quinn-btls, enabling custom TLS configuration for QUIC. `Config::new()` delegates to `from_builder()` internally — no breaking change to the upstream API.

[0.8.0]: https://github.com/scrape-hub/koon/releases/tag/v0.8.0
[0.7.0]: https://github.com/scrape-hub/koon/releases/tag/v0.7.0

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
