# Changelog

All notable changes to koon will be documented in this file.

## [0.3.0] - 2026-02-19

### Added

#### Automated Capture Tool (`tools/capture/`)
- **Browser fingerprint capture pipeline**: Automated download, launch, and capture
  - `download.mjs`: Chrome for Testing API + Mozilla FTP download with version resolution
  - `capture.mjs`: Playwright (Chrome) + geckodriver/WebDriver (Firefox) fingerprint capture
  - `convert.mjs`: Raw browserleaks.com JSON → koon BrowserProfile JSON conversion
  - `index.mjs`: CLI entry point (`--browser chrome --versions 131,145`)
  - `mappings.mjs`: IANA → BoringSSL cipher/curve/sigalg/extension name mappings
- Captured and verified: Chrome 131, Chrome 145, Firefox 135 (Windows)

#### Anti-Bot Evasion
- **H2 PRIORITY Frames**: Firefox priority tree (streams 3/5/7/9/11) now sent during H2 handshake
  - Chrome/Edge: `no_rfc7540_priorities=true` sent in SETTINGS (matching real Chrome 131+)
  - `enable_connect_protocol` SETTINGS support (Safari 18.3)
- **TLS Session Resumption**: Automatic session caching keyed by hostname
  - `SessionCache` stores `SslSession` objects across connections
  - `set_new_session_callback` on `SslContext` + `set_session` before handshake
  - `ClientBuilder::session_resumption(bool)` toggle (default: true)
- **Fingerprint Randomization**: `BrowserProfile::randomize()` method
  - Chrome/Edge: UA build number jittered within version range (6778-6810.0-265)
  - `accept-language` q-values randomized (0.7-0.9)
  - H2 `initial_window_size` and `initial_conn_window_size` ±32KB jitter
  - TLS fingerprint (JA3/JA4) unchanged — only non-critical fields modified
- **DNS-over-HTTPS** (optional `doh` feature): Encrypted DNS via HTTPS POST
  - `DohResolver::with_cloudflare()` / `with_google()` presets
  - A/AAAA resolution with 5-minute TTL cache
  - HTTPS record queries (type 65) for ECHConfigList + ALPN
  - Minimal TLS config (not browser-fingerprinted) for DoH transport
  - `ClientBuilder::doh(resolver)` integration
- **Real ECH** (Encrypted Client Hello): Uses ECHConfigList from DNS HTTPS records
  - `configure_connection()` applies `set_ech_config_list()` when available
  - Automatic fallback to ECH GREASE when no DNS record found
  - Requires `doh` feature for DNS HTTPS record queries

### Fixed
- **Chrome 131 ALPS codepoint**: Was incorrectly set to `alps_use_new_codepoint: true` (new codepoint 0x44CD).
  Real Chrome 131 uses old codepoint 0x4469. Verified via capture tool against tls.browserleaks.com.
  Chrome 145 correctly uses the new codepoint — now has separate `chrome_tls_v145()` function.
- **Firefox 135 H2 settings**: 4 corrections from real browser capture:
  - `max_frame_size`: `None` → `Some(16384)` (Firefox sends SETTINGS_MAX_FRAME_SIZE=16384)
  - `max_header_list_size`: `Some(65536)` → `None` (Firefox doesn't send this setting)
  - `settings_order`: Removed `MaxConcurrentStreams` and `MaxHeaderListSize` (Firefox only sends 4 settings)
  - `headers_stream_dependency`: Removed (Firefox doesn't set stream dependency on HEADERS frame)

### Dependencies Added
- `rand` v0.9 (fingerprint randomization)
- `hickory-proto` v0.25 (optional, DNS wire format for DoH)

### Changed
- `TlsConnector::build_connector()` now accepts `Option<SessionCache>`
- `TlsConnector::configure_connection()` now accepts `Option<&SessionCache>` + `Option<&[u8]>` (ECH config)
- `Client` struct now stores `SessionCache` and optional `DohResolver`
- Chrome profiles: `no_rfc7540_priorities: Some(true)` (was `None`)
- Firefox profile: 5 PRIORITY frames in H2 config (was empty)
- **Chrome 131–145** (15 versions × 3 platforms = 45 profiles) — all verified via capture tool
  - Chrome ≤134: old ALPS codepoint (0x4469), Chrome ≥135: new ALPS codepoint (0x44CD)
  - H2/QUIC fingerprint identical across all versions (same Akamai hash)
  - Generic `chrome_profile(major, os)` generator replaces per-version boilerplate
- **Firefox 135–147** (13 versions × 3 platforms = 39 profiles) — all verified via capture tool
  - TLS/H2/QUIC fingerprint identical across all versions (same JA3/JA4/Akamai hash)
  - Only User-Agent differs per version
- **Edge 131–145** (15 versions × 2 platforms = 30 profiles) — shares Chrome TLS/H2 engine
- **Safari 15.6–18.3** (5 versions × 1 platform = 5 profiles) — data sourced from tls-client (bogdanfinn)
  - Safari 15.6–16.0: H2 initial_window=4MB, pseudo m/sc/p/a
  - Safari 17.0: H2 initial_window drops to 2MB
  - Safari 18.0+: pseudo order changes to m/sc/a/p, adds no_rfc7540_priorities
  - Safari 18.3: sigalgs updated (ecdsa_sha1 removed, ecdsa_secp521r1_sha512 added)
- `Chrome::latest()` → v145, `Firefox::latest()` → v147, `Edge::latest()` → v145
- Node.js/Python bindings: all 122 profiles exposed (e.g. `chrome138windows`, `firefox146linux`, `safari170macos`)

## [0.2.0] - 2026-02-19

### Added

#### Core
- **HTTP/2 Header Field Order**: Forked `http2` crate with `HeadersOrder` API
  - H2 request headers now sent in exact profile-defined order (critical for Akamai fingerprinting)
  - `HeadersOrder` + `HeadersOrderBuilder` types following existing `PseudoOrder` pattern
  - Threaded through client → proto → streams → frame encoding pipeline
- **HTTP/3 (QUIC) Support**: Full HTTP/3 protocol via Quinn + h3 + h3-quinn
  - QUIC transport parameters fingerprinting (RFC 9000): window sizes, stream limits, MTU, idle timeout
  - HTTP/3 settings (RFC 9114): QPACK table capacity, blocked streams
  - Alt-Svc header discovery: automatic H3 upgrade after H1/H2 response
  - Connection pooling: H3 connections multiplexed alongside H2/H1.1
  - Proxy fallback: automatic H2/H1 when proxy is configured (no CONNECT-UDP/MASQUE)
  - TLS via rustls for QUIC (separate from BoringSSL TCP TLS fingerprint)
- **QuicConfig**: New profile field with browser-specific QUIC transport parameters
  - Chrome v131/v145, Firefox v135, Edge v131 QUIC profiles
  - Safari: no H3 (matches real browser behavior)

### Changed
- `http2` dependency changed from crates.io to forked version with `HeadersOrder` support
- `BrowserProfile` now includes optional `quic: Option<QuicConfig>` field
- `ConnectionPool` now supports `PoolEntry::Http3` variant
- `Error` enum extended with `Quic(String)` and `Http3(String)` variants

### Dependencies Added
- `quinn` v0.11 (QUIC transport, rustls-ring crypto)
- `h3` v0.0.8 (HTTP/3 protocol)
- `h3-quinn` v0.0.10 (Quinn adapter for h3)
- `rustls` v0.23 (TLS for QUIC connections)
- `webpki-roots` v1 (Root CA certs for rustls)

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
