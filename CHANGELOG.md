# Changelog

All notable changes to koon will be documented in this file.

## [0.4.3] - 2026-02-22

### Added
- **CI/CD Pipelines** (GitHub Actions):
  - `ci.yml`: `cargo test` + `cargo clippy` on push/PR to master (Ubuntu, Go for BoringSSL)
  - `release.yml`: Automated build + publish on `v*` tag push
    - 5 platform matrix: Windows x64, Linux x64/ARM64, macOS x64/ARM64
    - Node.js native addons → npm (`koon`)
    - Python wheels → PyPI (`koon`)
    - CLI binaries → GitHub Releases
    - Python source distribution (sdist)

## [0.4.2] - 2026-02-21

### Fixed
- **Safari JA4 fingerprint**: Now matches real Safari 18.2 exactly (`t13d2014h2_a09f3c656075_14788d8d241b`)
  - Added duplicate `rsa_pss_rsae_sha384` in sigalgs (real Safari/Apple SecureTransport quirk)
  - Removed unverified `ecdsa_secp521r1_sha512` from Safari 18.3 sigalgs
  - All Safari profiles (15.6–18.3) now use unified sigalgs matching real captures
  - Verified via boring2's patched BoringSSL (uniqueness check removed for Safari compat)
  - **Result**: Safari profiles now pass Cloudflare, Canva, Glassdoor, Medium (previously blocked with 403)
- **Firefox headers**: Added missing `upgrade-insecure-requests: 1` and `sec-fetch-user: ?1` headers
  (real Firefox sends both; missing headers were detectable by anti-bot systems like Datadome)
- **Safari headers**: Version-specific header sets matching real browser behavior:
  - Safari 15.6–16.0: No `sec-fetch-*` headers (added in WebKit 16.4), no `priority` header
  - Safari 17.0: Added `sec-fetch-*` headers, no `priority` header
  - Safari 18.0+: Added `upgrade-insecure-requests: 1`, `priority: u=0, i`
  - Header order verified against real Safari 18.2 capture (Apple DTS Engineer, macOS 15.2)
- **R build**: Fixed `koon-core` path resolution when `R CMD INSTALL` copies to temp directory

## [0.4.1] - 2026-02-21

### Added
- **R Bindings** (`koon-r`): R package via extendr for browser-impersonating HTTP requests
  - `Koon$new(browser, proxy, timeout, randomize, headers)` — create client with browser profile
  - `$get(url)`, `$post(url, body)`, `$put(url, body)`, `$delete(url)`, `$patch(url, body)`, `$head(url)` — synchronous HTTP methods
  - Response as R list: `$status` (integer), `$version`, `$url`, `$body` (raw), `$text` (character), `$headers` (data.frame)
  - `$save_session()` / `$load_session(json)` — session persistence (cookies + TLS)
  - `$export_profile()` — export browser profile as JSON
  - `koon_browsers()` — list all available browser profiles
  - All requests synchronous via `tokio::Runtime::block_on()` (R is single-threaded)
  - Build via `rextendr::document()` or `R CMD INSTALL`

## [0.4.0] - 2026-02-21

### Refactored
- **client.rs split**: 1975-line monolith split into 8 focused modules
  (`client/{mod,execute,connection,h1,h2,h3,headers,response,alt_svc}.rs`)
- **BrowserProfile::resolve()**: Centralized browser name parsing in core, replacing
  3x duplicated resolution code in Node.js (190 lines), Python (152), CLI (112)
- **Header deduplication**: 8 duplicated header-building blocks consolidated into
  `headers::build_request_headers()`
- **Chromium headers**: Shared `chromium_headers()` for Chrome/Edge/Opera profiles
- **HTTP/1.1 parsing**: Unified header parsing with shared `read_and_parse_headers()`
- **Test parametrization**: Consolidated repetitive tests into shared helpers

### Added
- **README.md**: Usage examples for CLI, Node.js, Python, and Rust
- **npm package**: `package.json`, `index.js` (platform-aware loader), `index.d.ts` (TypeScript types)
- **LICENSE**: MIT license file
- **Unified test suites**: `test_cli.sh` (28 tests), `test_node.cjs` (30 tests), `test_python.py` (30 tests)

### Fixed
- Version mismatch: workspace version now 0.4.0 (was 0.1.0)
- Python type stubs updated with all missing classes and methods

### Removed
- `build.bat` (hardcoded paths, not portable)

## [0.3.6] - 2026-02-21

### Added
- **CLI Tool** (`koon-cli`): curl-like command-line interface for browser-impersonating HTTP requests
  - `koon <url>` — GET request with Chrome latest profile
  - `-b <browser>` — browser profile selection (chrome, firefox147, safari, edge, opera, etc.)
  - `-X <METHOD>` — HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD)
  - `-d <data>` — request body (use `@filename` to read from file)
  - `-H "Key: Value"` — custom headers (repeatable)
  - `--proxy <url>` — HTTP CONNECT or SOCKS5 proxy
  - `-o <file>` — save response body to file
  - `-v` — verbose output (request/response headers)
  - `--json` — structured JSON output (status, headers, body, version, url)
  - `--randomize` — slight fingerprint randomization
  - `--doh <provider>` — DNS-over-HTTPS (cloudflare, google)
  - `--save-session <file>` / `--load-session <file>` — session persistence (v0.3.4)
  - `--export-profile <name>` — export browser profile as JSON
  - `--list-browsers` — list all 134 available browser profiles
  - `--profile <file>` — load custom profile from JSON file
  - `--no-follow`, `--max-redirects`, `--no-cookies`, `--no-session-resumption` — request control
  - `koon proxy` subcommand — start local MITM proxy server (v0.3.5)
    - `--listen`, `--header-mode`, `--ca-dir`, `--browser`, `--randomize`

### Fixed
- **Python**: `KoonStreamingResponse` and `KoonProxy` now exported from `koon.__init__`
- **Core**: `Opera` profile module now re-exported from `koon_core`
- **Proxy**: Fix truncated response bodies — content-length and content-encoding headers now
  replaced with actual decompressed body size (koon auto-decompresses gzip/brotli/zstd)
- **Deflate decompression**: Try zlib-wrapped (RFC 1950) first, fall back to raw deflate (RFC 1951)
- **DoH Cloudflare**: Add content-length header to DoH H2 POST requests (Cloudflare requires it)

### Added
- **Comprehensive feature test suite** (`tests/features.rs`): 65 tests covering all features
  - 25 unit tests (no network): profile JSON roundtrip, randomization invariants, builder options,
    cookie jar serialization, Safari/Firefox/Chrome profile properties
  - 40 integration tests (`--ignored`): decompression (gzip/brotli/deflate), redirects (301-308,
    body preservation), session save/load, TLS session resumption, streaming responses, custom
    headers, all HTTP methods, multipart POST, cookie persistence, connection pool reuse,
    WebSocket echo, MITM proxy start/shutdown/traffic, DoH (Cloudflare + Google), timeout,
    large response, status codes, all 5 browser profiles (Chrome/Firefox/Safari/Edge/Opera)

## [0.3.5] - 2026-02-21

### Added
- **Local MITM Proxy Server**: Intercepts HTTPS traffic and re-sends it with koon's fingerprinted TLS/HTTP2 stack
  - `ProxyServer::start(config)` — bind TCP listener, spawn accept loop, return server handle
  - `ProxyServerConfig` — listen address, browser profile, header mode, CA dir, timeout
  - `HeaderMode::Impersonate` (default) — replace client headers with profile headers
  - `HeaderMode::Passthrough` — pass client headers through, only TLS/H2 fingerprinted
  - HTTPS CONNECT tunnel with per-domain leaf certificate signing
  - Plain HTTP request forwarding (absolute URL)
  - `ProxyServer::port()`, `url()`, `local_addr()`, `ca_cert_path()`, `ca_cert_pem()`, `shutdown()`
- **Certificate Authority**: Auto-generate and persist MITM CA certificate
  - `CertAuthority::load_or_generate(dir)` — load from disk or generate RSA 2048 CA + save
  - Per-domain leaf certificates with SAN, cached in memory
  - CA stored as `koon-ca.pem` + `koon-ca-key.pem` in configurable directory (default: `~/.koon/ca/`)
- **Client Passthrough Mode**: `Client::request_with_raw_headers()` for proxy passthrough
  - Uses fingerprinted TLS + H2 settings but with caller-supplied HTTP headers
  - Supports H2 and H1.1 connections with connection pooling
- **Node.js**: `KoonProxy` class with `start(options)`, `port`, `url`, `caCertPath`, `caCertPem()`, `shutdown()`
  - `KoonProxyOptions` — browser, profile_json, listen_addr, header_mode, ca_dir, timeout, randomize
- **Python**: `KoonProxy` class with `start(...)`, `port`, `url`, `ca_cert_path`, `ca_cert_pem()`, `shutdown()`

### Changed
- `proxy` module refactored from single file to directory (`proxy/config.rs`, `proxy/ca.rs`, `proxy/server.rs`)
- Existing `ProxyConfig`/`ProxyKind`/`ProxyAuth` imports unchanged (re-exported from `proxy::config`)

## [0.3.4] - 2026-02-21

### Added
- **Session Save/Load**: Persist and restore client state (cookies + TLS sessions) across restarts
  - `Client::save_session()` → JSON string with all cookies and TLS session tickets (base64-encoded DER)
  - `Client::load_session(json)` → restore cookies and TLS sessions from JSON
  - `Client::save_session_to_file(path)` / `Client::load_session_from_file(path)` → file I/O convenience methods
  - `CookieJar::to_json()` / `CookieJar::from_json()` → standalone cookie serialization
  - `CookieJar::cookies()` → read access to stored cookies
  - `SessionCache::export()` / `SessionCache::import()` → TLS session serialization via base64-encoded DER
  - `SessionExport`, `SessionCacheExport` — public types for session data
  - `Cookie`, `SameSite` — now public and re-exported from `koon_core`
  - **Node.js**: `saveSession()`, `loadSession(json)`, `saveSessionToFile(path)`, `loadSessionFromFile(path)`
  - **Python**: `save_session()`, `load_session(json)`, `save_session_to_file(path)`, `load_session_from_file(path)`

### Dependencies Added
- `base64` v0.22 (TLS session DER encoding)

## [0.3.3] - 2026-02-19

### Added
- **Integration Tests**: 10 fingerprint verification tests against `tls.browserleaks.com`
  - Chrome 131 (old ALPS), Chrome 135, Chrome 145, Firefox 135, Firefox 147, Edge 145
  - Safari 15.6, Safari 17.0, Safari 18.0, Safari 18.3
  - Asserts JA4, Akamai hash, and Akamai text against reference captures
  - `#[ignore]` attribute — run with `cargo test --test fingerprint -- --ignored`

- **TLS record_size_limit**: `TlsConfig::record_size_limit` option (RFC 8449)
  - Firefox profiles set `record_size_limit: Some(16385)` — matches real Firefox extension count (17)
  - Fixes JA4 mismatch: `t13d1717h2` (correct) instead of `t13d1716h2` (was missing extension 0x001c)

### Fixed
- **Firefox PRIORITY frames**: Removed 5 spurious PRIORITY frames from Firefox 135–147 profiles
  - Real Firefox 135+ does not send RFC 7540 PRIORITY frames (deprecated since ~FF100)
  - Verified via capture: Akamai text PRIORITY segment is `0`
- **Chrome SETTINGS_NO_RFC7540_PRIORITIES**: Removed setting `9:1` from Chrome/Edge/Opera SETTINGS frame
  - Real Chrome communicates this via ALPS, not the SETTINGS frame
  - Verified: capture akamai_text contains only settings 1,2,4,6
- **Safari 18.x H2 profile**: Corrected against real Safari 18.2 capture (curl_cffi#460)
  - Window size: 4MB (was 2MB), settings order: 2,4,3 (was wrong), pseudo order: m,s,p,a (was m,s,a,p)
  - Removed EnableConnectProtocol and NoRfc7540Priorities (real Safari doesn't send these)
  - Connection window: WINDOW_UPDATE=10485760 (was 10420225)
- **Safari TLS extensions**: Added `pre_shared_key: true` for all Safari profiles
  - Real Safari sends psk_key_exchange_modes (0x002d), fixes extension count 13→14

- **TLS 1.3 cipher order preservation**: `TlsConfig::preserve_tls13_cipher_order` flag
  - Uses `boring2::set_preserve_tls13_cipher_list()` to override BoringSSL's AES-HW-dependent order
  - Must be called BEFORE `set_cipher_list()` to take effect
  - Enabled for Firefox profiles (NSS order: AES_128→CHACHA20→AES_256)

### Fixed
- **Firefox JA3N hash**: Now matches real Firefox captures exactly (`e4147a4860c1f347354f0a84d8787c02`)
  - Root cause: TLS 1.3 cipher IDs were misidentified (4866=AES_256, not CHACHA20; 4867=CHACHA20, not AES_256)
  - Firefox cipher_list reordered: AES_128(4865)→CHACHA20(4867)→AES_256(4866) — matches real Firefox/NSS
  - `preserve_tls13_cipher_order: true` enables BoringSSL to honor this order

### Verified
- **All fingerprint hashes match real browser captures**:
  - Chrome 131–145: JA4, JA3N, Akamai ✅
  - Firefox 135–147: JA4, JA3N, Akamai ✅ (JA3N now fixed!)
  - Safari 15.6–18.3: JA4, Akamai ✅
  - Edge 145: JA4, JA3N, Akamai ✅

### Changed
- Example `fingerprint_test.rs` cleaned up: fingerprint tests moved to `tests/fingerprint.rs`, smoke tests retained

## [0.3.2] - 2026-02-19

### Added
- **HTTP/2 GOAWAY Handling**: Transparent retry on fresh connection when server sends GOAWAY
  - `Error::is_h2_goaway()` helper to detect remote GOAWAY errors
  - `new_connection_request()` extracted from `execute_single_request` to enable retry without duplication
  - Pooled H2 connections that receive GOAWAY are evicted and the request is retried on a new connection
  - Removed `eprintln!` from H2 and H3 connection driver tasks
- **Multipart Form-Data**: `multipart::Multipart` builder for `multipart/form-data` POST requests
  - `Multipart::new()` with random boundary (`----koon` + 24 alphanums)
  - `.text(name, value)` and `.file(name, filename, content_type, data)` builder methods
  - `.build()` returns `(body_bytes, content_type_header)`
  - `Client::post_multipart(url, multipart)` convenience method
  - 6 unit tests (boundary format, content-type, text/file encoding, mixed fields, closing boundary)
  - **Node.js**: `postMultipart(url, fields)` with `KoonMultipartField` interface
  - **Python**: `post_multipart(url, fields=[{name, value/file_data, filename, content_type}])`
- **Streaming Response Body**: `streaming::StreamingResponse` for large downloads without full buffering
  - `Client::request_streaming(method, url, body)` — returns `StreamingResponse` instead of `HttpResponse`
  - `StreamingResponse::next_chunk()` delivers body data in chunks via `mpsc` channel
  - `StreamingResponse::collect_body()` collects entire body (convenience fallback)
  - H2 streaming: background task forwards `recv_stream.data()` chunks through channel
  - H1 streaming: background task owns TLS stream, streams chunked/content-length/close body
  - H1 streaming helpers: `stream_chunked_body`, `stream_content_length_body`, `stream_until_close`
  - No redirect following (caller handles 3xx manually, like `fetch(redirect: 'manual')`)
  - No decompression (raw compressed chunks delivered as-is)
  - **Node.js**: `KoonStreamingResponse` class with `nextChunk()`, `collect()`, status/headers/version/url getters
  - **Python**: `KoonStreamingResponse` with `next_chunk()`, `collect()`, `async for chunk in resp` iteration

### Changed
- `execute_single_request()` now accepts `extra_headers: &[(String, String)]` parameter
- `send_on_h2()` and `send_on_h1()` now accept `extra_headers` for per-request header injection
- `request_with_headers()` public method for sending requests with extra headers
- `HttpResponse` re-exported from `lib.rs`
- `KoonHeader` in Node.js bindings now derives `Clone`

## [0.3.1] - 2026-02-19

### Added
- **DoH Connection Reuse**: `DohResolver` now uses a persistent HTTP/2 connection to the DoH server
  - All DNS queries (A, AAAA, HTTPS) are multiplexed on a single TCP+TLS connection
  - Lazy connection creation with automatic reconnection on failure
  - Replaces per-query HTTP/1.1 `Connection: close` approach
- **ECH Retry Logic**: Automatic retry with server-provided ECH configs after ECH rejection
  - `tls_connect_inner()` catches `SSL_R_ECH_REJECTED` and calls `get_ech_retry_configs()`
  - Single retry with new TCP+TLS connection using retry configs (no infinite loop)
  - Port parameter propagated through `tls_connect()` / `tls_connect_ws()` / `tls_connect_inner()`
- **Node.js Bindings**: 3 new `KoonOptions` fields exposed
  - `randomize: boolean` — fingerprint randomization (UA build, q-val, H2 window jitter)
  - `session_resumption: boolean` — TLS session resumption toggle (default: true)
  - `doh: 'cloudflare' | 'google'` — encrypted DNS with ECH support
- **Python Bindings**: 3 new `Koon()` constructor parameters exposed
  - `randomize: bool` — fingerprint randomization (default: False)
  - `session_resumption: bool` — TLS session resumption toggle (default: True)
  - `doh: str | None` — encrypted DNS provider ('cloudflare' or 'google')

### Changed
- **Connection Pool TTL/Eviction + Max-Size**: Idle connections are now evicted after 90s (matching Chrome), pool capped at 256 entries
  - `TimedEntry` wrapper tracks insertion timestamp per connection
  - Expired entries evicted on every `insert_*()` via `retain()`; also checked on `try_get_*()` / `try_take_*()`
  - Oldest entry evicted when pool reaches max capacity
  - `ConnectionPool::new(max_size, ttl)` replaces parameterless constructor
- `http2` dependency pinned to tag `v0.5.12-headers-order` (was `branch = "headers-order"`)
- `koon-node` and `koon-python` Cargo.toml: `koon-core` dependency now includes `features = ["doh"]`
- `DohResolver` struct gains `h2_sender` field for persistent H2 connection
- `Client::tls_connect()`, `tls_connect_ws()`, `tls_connect_inner()` now accept `port: u16` parameter

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
- **Opera 124–127** (4 versions × 3 platforms = 12 profiles) — shares Chrome TLS/H2/QUIC engine
  - Opera 124→Chromium 140, Opera 125→141, Opera 126→142, Opera 127→143
  - `sec-ch-ua` uses `"Opera"` brand, UA includes `OPR/` suffix
- `Chrome::latest()` → v145, `Firefox::latest()` → v147, `Edge::latest()` → v145, `Opera::latest()` → v127
- Node.js/Python bindings: all 134 profiles exposed (e.g. `chrome138windows`, `firefox146linux`, `opera127macos`)

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
