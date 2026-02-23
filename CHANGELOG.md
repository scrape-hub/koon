# Changelog

All notable changes to koon will be documented in this file.

## [0.5.3] - 2026-02-24

### Changed
- **Node.js: `browser` option accepts any string** — replaced the fixed enum with a free-form string that is passed directly to the core's `BrowserProfile::resolve()`. All naming formats now work: `firefox148-macos`, `firefox148macos`, `chrome-mobile145`, `chromemobile145`, etc. New profiles added in the core are automatically available without updating the bindings. Removes ~490 lines of boilerplate.
- **README: expanded browser profile documentation** — added per-category tables with concrete examples for every browser-OS combination, shorthand names, and a note that the dash separator is optional.

## [0.5.2] - 2026-02-23

### Added
- **`remoteAddress` on Response**: All responses (buffered + streaming) now expose `remoteAddress` — the peer IP address (e.g. `"1.2.3.4"` or `"::1"`). Available on Node.js (`response.remoteAddress`), Python (`response.remote_address`), and R (`resp$remote_address`). Returns `null`/`None`/`NULL` for HTTP/3 (QUIC). Useful for proxy users to verify exit IP without extra requests.

## [0.5.1] - 2026-02-23

### Fixed
- Small bugfix Release

### Changed
- macOS builds temporarily removed

## [0.5.0] - 2026-02-23

### Added
- **Mobile Browser Profiles**: Chrome Mobile, Firefox Mobile, Safari Mobile
  - `chrome-mobile145`, `firefox-mobile148`, `safari-mobile183`
  - Also available via OS suffix: `chrome145-android`, `safari183-ios`, `firefox148-android`
  - Available on all platforms: Node.js, Python, R, CLI
- **Firefox 148**: Desktop + Android profiles
- **OkHttp Profiles**: Android app impersonation (OkHttp 4.x, 5.x)
  - `okhttp4`, `okhttp5`
- **CONNECT Proxy Headers**: Custom headers in the HTTP CONNECT tunnel request
  - Node.js: `new Koon({ proxyHeaders: { 'X-Session-ID': 'abc' } })`
  - Python: `Koon("chrome", proxy_headers={"X-Session-ID": "abc"})`
  - R: `Koon$new("chrome", proxy_headers = c("X-Session-ID" = "abc"))`
  - CLI: `koon --proxy-header "X-Session-ID: abc"`
- **IPv4/IPv6 Toggle**: Restrict DNS resolution to a specific IP version
  - Node.js: `new Koon({ ipVersion: 4 })`
  - Python: `Koon("chrome", ip_version=4)`
  - R: `Koon$new("chrome", ip_version = 4L)`
  - CLI: `koon --ip-version 4`
- **String Body**: `post()`, `put()`, `patch()`, `request()` now accept strings directly
  - Node.js: `client.post(url, '{"key":"value"}')`  (no more `Buffer.from()`)
  - Python: `await client.post(url, '{"key":"value"}')`  (no more `b'...'`)
- **User-Agent Property**: Access the profile's UA string for use in Puppeteer/Playwright
  - Node.js: `client.userAgent`
  - Python: `client.user_agent`
  - R: `client$user_agent()`
- **Geo-Locale Matching**: Generate Accept-Language headers matching proxy geography
  - `"fr-FR"` -> `"fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"`
  - Node.js: `new Koon({ locale: 'fr-FR' })`
  - Python: `Koon("chrome", locale="fr-FR")`
  - R: `Koon$new("chrome", locale = "fr-FR")`
  - CLI: `koon --locale fr-FR`
- **Structured Errors**: Machine-readable error codes on all errors
  - Format: `[CODE] description` (e.g. `[TIMEOUT] Request timed out`)
  - Codes: `TLS_ERROR`, `HTTP2_ERROR`, `PROXY_ERROR`, `CONNECTION_FAILED`, `TIMEOUT`, `TOO_MANY_REDIRECTS`, etc.
  - Node.js: `err.message.startsWith('[TIMEOUT]')`
  - Python: `KoonError` exception class
- **Connection Info**: Debug connection reuse and TLS resumption
  - `response.tlsResumed` / `response.connectionReused`
- **Custom Redirect Hook**: Intercept redirects before following
  - Node.js: `new Koon({ onRedirect: (status, url, headers) => !url.includes('captcha') })`
  - Python: `Koon("chrome", on_redirect=lambda s,u,h: "captcha" not in u)`
  - R: `Koon$new("chrome", on_redirect = function(s, u, h) !grepl("captcha", u))`
- **Automatic Retry**: Transport-error retry with proxy rotation
  - Node.js: `new Koon({ retries: 3 })`
  - Python: `Koon("chrome", retries=3)`
  - R: `Koon$new("chrome", retries = 3L)`
  - CLI: `koon --retries 3`
- **Clear Cookies**: Empty the cookie jar without resetting connections
  - Node.js: `client.clearCookies()`
  - Python: `client.clear_cookies()`
  - R: `client$clear_cookies()`
- **Bandwidth Tracking**: Per-request and cumulative byte counters
  - `resp.bytesSent`, `resp.bytesReceived` per response
  - `client.totalBytesSent()`, `client.totalBytesReceived()`, `client.resetCounters()`
- **Request Hooks**: `onRequest` / `onResponse` callbacks for logging
  - Node.js: `new Koon({ onRequest: (m, u) => ..., onResponse: (s, u, h) => ... })`
  - Python: `Koon("chrome", on_request=lambda m,u: ..., on_response=lambda s,u,h: ...)`
  - R: `Koon$new("chrome", on_request = function(m, u) ..., on_response = function(s, u, h) ...)`
- **Proxy Rotation**: Round-robin over multiple proxy URLs
  - Node.js: `new Koon({ proxies: ['socks5://a:1080', 'socks5://b:1080'] })`
  - Python: `Koon("chrome", proxies=["socks5://a:1080", "socks5://b:1080"])`
  - R: `Koon$new("chrome", proxies = c("socks5://a:1080", "socks5://b:1080"))`
  - CLI: `koon --proxies socks5://a:1080,socks5://b:1080`
- **Local Address Binding**: Bind outgoing connections to a specific local IP
  - Node.js: `new Koon({ localAddress: '192.168.1.100' })`
  - Python: `Koon("chrome", local_address="192.168.1.100")`
  - R: `Koon$new("chrome", local_address = "192.168.1.100")`
  - CLI: `koon --local-address 192.168.1.100`
- **Ergonomic Response API**
  - `resp.ok` — true when status is 2xx
  - `resp.text()` — decode body as UTF-8
  - `resp.json()` — parse body as JSON
  - `resp.header(name)` — case-insensitive header lookup
- **Per-Request Timeout**: Override constructor timeout per request
  - Node.js: `client.get(url, { timeout: 5000 })`
  - Python: `await client.get(url, timeout=5000)`
- **Python Per-Request Headers**: All Python HTTP methods now accept `headers` and `timeout`
  - `await client.get(url, headers={"Authorization": "Bearer ..."})`
- **CLI**: `--retries`, `--locale`, `--ip-version`, `--local-address`, `-k`/`--ignore-tls-errors`, `--proxies`, `--proxy-header`

### Fixed
- Node.js: Missing Browser enum variants for mobile profiles, OkHttp, and Firefox 148
- R: Missing constructor params (`doh`, `ignore_tls_errors`, `follow_redirects`, `max_redirects`, `cookie_jar`, `session_resumption`)
- R: `koon_browsers()` now lists mobile, OkHttp, and Firefox 148 profiles
- R: `user_agent()` method now exposed in R wrapper
- CLI: `--list-browsers` now shows mobile, OkHttp, and Firefox 148 profiles

## [0.4.5] - 2026-02-22

### Added
- **Per-Request Headers**: All HTTP methods accept optional per-request headers
  - Node.js: `client.get(url, { headers: { Authorization: 'Bearer ...' } })`
  - Python: `await client.get(url, headers={"Authorization": "Bearer ..."})`
  - R: `client$get(url, headers = c(Authorization = "Bearer ..."))`
  - Per-request headers override constructor-level defaults (case-insensitive merge)
- **Chromium CORS Header Ordering**: Fetch/XHR requests now use Chrome's real CORS header order
  - Applied automatically when CORS mode is detected
- **sec-ch-ua GREASE Algorithm**: Real Chromium GREASE brand algorithm, correct for all versions
- **FetchMetadata Auto-Detection**: sec-fetch-* headers automatically corrected for API vs navigation requests
  - Fixes 403 errors from Akamai when using `Origin` or `application/json` with Chromium profiles
- **R Vignettes**: 3 practical vignettes (getting-started, sessions-and-cookies, advanced-usage)

### Fixed
- H2 header wire order for CORS/fetch requests

### Improved
- Comprehensive documentation for Rust, Python, and CLI

## [0.4.4] - 2026-02-22

### Added
- **CI/CD Pipelines**: Automated build + publish on tag push
  - 5 platforms: Windows x64, Linux x64/ARM64, macOS x64/ARM64
- **Published on all platforms**:
  - npm: `npm install koonjs`
  - PyPI: `pip install koon`
  - GitHub Releases: CLI binaries
  - R: `remotes::install_github("scrape-hub/koon", subdir="crates/r")`

### Changed
- npm package renamed to `koonjs`
- Repository migrated to `scrape-hub/koon`

## [0.4.2] - 2026-02-21

### Fixed
- **Safari fingerprint**: Now matches real Safari 18.2 exactly — passes Cloudflare, Canva, Glassdoor, Medium
- **Firefox headers**: Added missing `upgrade-insecure-requests` and `sec-fetch-user` headers
- **Safari headers**: Version-specific header sets matching real browser behavior

## [0.4.1] - 2026-02-21

### Added
- **R Bindings**: R package for browser-impersonating HTTP requests
  - `Koon$new(browser, proxy, timeout, randomize, headers)`
  - `$get()`, `$post()`, `$put()`, `$delete()`, `$patch()`, `$head()`
  - `$save_session()` / `$load_session()` — session persistence
  - `koon_browsers()` — list all available profiles

## [0.4.0] - 2026-02-21

### Added
- **README.md** with usage examples for CLI, Node.js, Python, and Rust
- **npm package** with TypeScript types
- **MIT License**

### Changed
- Internal code refactoring for maintainability

## [0.3.6] - 2026-02-21

### Added
- **CLI Tool**: curl-like command-line interface
  - `koon <url>` — GET with Chrome profile
  - `-b <browser>` — browser selection
  - `-X <METHOD>`, `-d <data>`, `-H "Key: Value"`, `--proxy <url>`
  - `-o <file>`, `-v`, `--json`
  - `--randomize`, `--doh <provider>`
  - `--save-session` / `--load-session`
  - `--export-profile`, `--list-browsers`, `--profile <file>`
  - `koon proxy` — start local MITM proxy server

### Fixed
- Truncated response bodies in proxy mode
- Deflate decompression for zlib-wrapped streams

## [0.3.5] - 2026-02-21

### Added
- **Local MITM Proxy Server**: Route traffic through koon's fingerprinted TLS/HTTP2 stack
  - `HeaderMode::Impersonate` — replace headers with profile headers
  - `HeaderMode::Passthrough` — keep original headers, only fingerprint TLS/H2
  - Auto-generated CA certificate with per-domain leaf certs
  - Node.js: `KoonProxy` class
  - Python: `KoonProxy` class

## [0.3.4] - 2026-02-21

### Added
- **Session Save/Load**: Persist cookies + TLS sessions across restarts
  - Node.js: `saveSession()`, `loadSession(json)`, `saveSessionToFile()`, `loadSessionFromFile()`
  - Python: `save_session()`, `load_session()`, `save_session_to_file()`, `load_session_from_file()`

## [0.3.3] - 2026-02-19

### Fixed
- All browser fingerprints now match real browser captures exactly
  - Chrome 131-145, Firefox 135-147, Safari 15.6-18.3, Edge 145: JA4, JA3N, Akamai verified

## [0.3.2] - 2026-02-19

### Added
- **HTTP/2 GOAWAY Handling**: Transparent retry on fresh connection when server sends GOAWAY
- **Multipart Form-Data**: `postMultipart()` / `post_multipart()` for file uploads
- **Streaming Response Body**: `requestStreaming()` for large downloads without full buffering
  - Node.js: `KoonStreamingResponse` with `nextChunk()`, `collect()`
  - Python: `KoonStreamingResponse` with `next_chunk()`, `async for chunk in resp`

## [0.3.1] - 2026-02-19

### Added
- **DNS-over-HTTPS**: `randomize`, `session_resumption`, `doh` options in Node.js and Python
- **ECH Retry**: Automatic retry with server-provided ECH configs

### Changed
- Connection pool: 90s TTL, max 256 entries (matching Chrome behavior)

## [0.3.0] - 2026-02-19

### Added
- **TLS Session Resumption**: Automatic session caching for faster reconnects
- **Fingerprint Randomization**: `randomize` option for subtle per-client uniqueness
- **DNS-over-HTTPS**: Encrypted DNS with Cloudflare or Google
- **Real ECH** (Encrypted Client Hello): From DNS HTTPS records, with GREASE fallback
- **150+ Browser Profiles**:
  - Chrome 131-145 (Windows/macOS/Linux)
  - Firefox 135-147 (Windows/macOS/Linux)
  - Safari 15.6-18.3 (macOS)
  - Edge 131-145 (Windows/macOS)
  - Opera 124-127 (Windows/macOS/Linux)

## [0.2.0] - 2026-02-19

### Added
- **HTTP/2 Header Field Order**: Headers sent in exact browser-specific order
- **HTTP/3 (QUIC) Support**: Alt-Svc discovery, transport parameter fingerprinting, connection pooling

## [0.1.0] - 2026-02-19

### Added
- **TLS Fingerprinting**: JA3/JA4 fingerprint control via BoringSSL
- **HTTP/2 Fingerprinting**: Settings order, pseudo-header order, stream dependency
- **HTTP/1.1**: Header-order-preserving requests
- **WebSocket (wss://)**: Over fingerprinted TLS
- **Cookie Jar**: Domain/path matching, Secure/HttpOnly/SameSite
- **Connection Pool**: H2 multiplexed + H1.1 keep-alive
- **Redirect Following**: 301-308 with configurable max
- **Response Decompression**: gzip, deflate, brotli, zstd
- **Proxy**: HTTP CONNECT + SOCKS5
- **JSON Profile System**: Export/import/customize profiles
- **Node.js Bindings**: Full API via napi-rs
- **Python Bindings**: Full async API via PyO3
