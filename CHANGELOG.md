# Changelog

All notable changes to koon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-09-30

### Added

- Responses name the bot protection that answered instead of the page:
  `blockedBy` in Node, `blocked_by` in Python, R and Rust (also as a function
  for streaming responses), in the CLI's `--json` output and in `-v`.

### Fixed

- Python: the project page on PyPI showed `../../README.md` instead of the
  README.

## [1.0.1] - 2026-09-29

### Fixed

- R: `remotes::install_github()` failed. On Windows the package now builds in
  `%LOCALAPPDATA%\koon-r` (`KOON_R_TARGET_DIR` to change).
- R: callbacks failed on R before 4.5 ("koon_run_callback() not found").

### Added

- R: prebuilt packages for Windows and macOS (Apple silicon), no Rust needed.
- Python: `koon.__version__`.

## [1.0.0] - 2026-09-28

This release rebuilds koon's fingerprints against real browser traffic:
Chrome, Firefox, Safari, Edge, Opera, Brave, Samsung Internet and OkHttp are
now reproduced on every layer a server can check: TLS, HTTP/2 frames, QUIC
and HTTP/3, DNS, and the request headers of every kind of request. It also
reworks the Rust API, parts of the bindings, and the file formats.

### Breaking changes

Upgrading from 0.8.1:

- Files written by koon 0.8 are rejected. Export custom profiles again
  (`koon --export-profile`, `exportProfile()`) and reapply your edits, save
  sessions again, and delete the MITM proxy's `koon-ca.pem` and
  `koon-ca-key.pem` so it generates a new CA for you to trust.
- Profile names without an OS now resolve to Windows instead of macOS,
  which was the default from 0.7.0 through 0.8.1. Add `-macos`
  (`chrome-macos`) to keep the old profile. Safari still defaults to macOS.
- `randomize` is removed from all bindings and the CLI.
- Streaming responses in Python and Node now deliver the decoded body by
  default, matching buffered responses and the CLI. Pass `decode=False` /
  `{ decode: false }` for the raw bytes.
- A hook that throws or raises now fails its request with that error;
  previously the error was only logged and the request went on regardless.
  `onRedirect` still follows the redirect unless it returns `false`.
- Node's byte counters (`bytesSent`, `bytesReceived`) are plain `number`
  instead of `BigInt`.
- Python's `Koon` methods now start the request only when awaited, so a
  call made without `await` sends nothing.
- The CLI exits with curl's own exit codes instead of exit code 1 for every
  error.
- The MITM proxy now refuses to bind a non-loopback `listen_addr` unless
  `allow_non_loopback` is set. New `auth` (HTTP Basic) and `max_connections`
  (default 512) options are available in the CLI, Node and Python.
- A failed TLS handshake now fails with `TLS_ERROR` instead of
  `CONNECTION_FAILED`.
- Invalid header names and values now fail the request with
  `INVALID_HEADER` instead of being silently dropped.
- Rust: `send` and `send_streaming`, taking `RequestOptions`, replace the
  `request_with_headers`, `request_with_headers_and_proxy`,
  `request_streaming`, `request_streaming_with_headers` and
  `request_streaming_with_headers_and_proxy` methods.
  `Chrome::version(154, Os::Windows)` replaces per-version constructors
  such as `Chrome::v154_windows()`. Hooks now return `Result`, and
  `ProxyServerConfig.client` replaces its separate `profile` and
  `timeout_secs` fields. The `Quic`, `Http3`, `Proxy`, `InvalidHeader`,
  `Body`, `ConnectionFailed`, `Protocol`, `Config`, `InvalidArgument` and
  `Dns` variants of `Error` now carry a `(message, source)` pair and expose
  the cause through `source()` (`Display` is unchanged). Some profile
  fields and API types were renamed or given different types.

### Added

#### Browsers and versions

- **Chrome** 153 to 155, **Firefox** 155 to 157, **Edge** 152 to 154 and
  **Opera** 135 and 136, plus **Safari** 15.6, 16.1, 16.6, 17.6, 18.0 to
  18.6, 26.0 and 27.0: profiles for the current stable release of each, on
  every platform it ships on.
- **Brave** (`brave153`, `brave154`, covering Brave 1.95 and 1.96) on
  Windows, macOS, Linux and Android: Chrome's TLS and HTTP/2 fingerprint
  without the trust_anchors extension, plus Brave's own `sec-gpc` header,
  reduced client hints and per-site Accept-Language.
- **Samsung Internet** 29 and 30 (`samsung`, Chromium 136 and 143) on
  Android, with the device values of a real Galaxy phone; no zstd, no
  HTTP/3.
- **Opera for Android** 102 (`opera-mobile`) and **Edge for Android** 131 to
  154 (`edge-mobile`), plus Android profiles for Chrome Mobile, Firefox
  Mobile (which report the device's actual Android release in their
  User-Agent) and OkHttp 4 and 5.

koon now ships 357 profiles in total. List them with `koon --list-browsers`
or `browsers()` in the bindings.

#### Fingerprint fidelity

- **TLS**: Chromium 152 and later fills the trust_anchors extension with
  the IDs of the Chrome Root Store its release ships, and puts a GREASE
  value first in its signature algorithms. Chrome 151 and later also runs
  Google's server-padding field trial: about 6% of clients, chosen once
  per client, ask the server to pad its own handshake. koon enrolls the
  same way, and `server_padding` pins the group instead of leaving it to
  chance.
- **HTTP/2**, frame by frame: stream IDs, HEADERS priorities, window
  updates, each browser's HPACK encoder, TLS record layout, PING timing
  and how the connection closes, all per browser family.
- **HTTP/3 and QUIC**: koon's QUIC and HTTP/3 implementation reproduces
  Chrome's, Firefox's and Safari's QUIC stacks, including the ClientHello,
  transport parameters, packet layout, ACK timing, 0-RTT and QUIC
  version 2 (Firefox 155 and later), SETTINGS, QPACK and header rules. The
  QUIC JA4 matches the real browsers', on both a full and a resumed
  handshake.
- **Safari** now follows three network-stack generations instead of the
  Safari version number: Sonoma (macOS 12 through 15.0, iOS 16 and 17),
  Sequoia (macOS 15.1 and later, iOS 18), and Tahoe (macOS 26 and 27,
  iOS 26 and 27). Each profile reproduces the generation its actual OS
  release ships, HTTP/3 included from macOS 13 and iOS 17 on (macOS 12 has
  none). `SETTINGS_ENABLE_PUSH` still varies within Sonoma: macOS 14,
  macOS 15.0 and iOS 17 send it explicitly with a value of 0, while
  macOS 12, macOS 13 and iOS 16.x send no such setting at all.
- **HTTP/3 discovery from DNS**: like real browsers, koon now queries the
  target's DNS HTTPS record before the first connection (over plain DNS or
  DoH) and goes straight to QUIC when it lists `h3`. Previously the first
  request to a host always went over TCP. Real ECH now comes from the same
  record, over both TCP and QUIC; Safari and OkHttp still send no ECH,
  matching the real clients.
- **WebSockets** can now open over HTTP/2 (RFC 8441), the way Chrome, Edge,
  Opera, Firefox and Safari 26 and later do it; OkHttp and older Safari
  versions still use HTTP/1.1.
- **Request headers** now follow each browser's order and casing per kind
  of request (navigation, form post, fetch, subresource, WebSocket, plain
  `http://`), including where cookies, Referer, Origin and your own
  headers land.
- **Client hints**: Chromium browsers now send the device hints (memory,
  pixel ratio, viewport) and network hints of real devices when an origin
  asks for them, via ALPS, `Accept-CH` or `Critical-CH`. They are cached
  per origin, up to 10,000 entries, with the least recently used evicted
  first.

#### Features

- **`koon verify`** checks that your installed koon still produces the
  real browsers' fingerprints, by connecting to tls.browserleaks.com and
  quic.browserleaks.com and comparing JA4, JA3N, JA3 and the Akamai HTTP/2
  fingerprint (it works through a proxy too, and exits with code 20 on a
  mismatch). The same check is available as `verify()` in Python and Node,
  and as `koon_core::verify` in Rust.
- **Drop-in adapters** add koon's fingerprint to existing code with a
  one-line change: `koon.httpx.KoonTransport` and `AsyncKoonTransport` for
  httpx, `koon.requests.Session` and `KoonAdapter` for requests, and
  `koonFetch()` for Node's fetch API.
- **HTTPS proxies**: an `https://` proxy URL now speaks TLS to the proxy,
  instead of sending the CONNECT request and its credentials in plain
  text as 0.8.1 did. `proxy_ca_certs` and `ignore_proxy_tls_errors` are
  available in every binding, `--proxy-cacert` and
  `--ignore-proxy-tls-errors` in the CLI.
- **Per-request options** ([#4](https://github.com/scrape-hub/koon/issues/4)):
  override headers, proxy, timeout, redirects and hooks for a single call
  instead of the whole client (`send`/`send_streaming` with
  `RequestOptions` in Rust).
- **Request headers on the response** ([#2](https://github.com/scrape-hub/koon/issues/2)):
  `request_headers`/`requestHeaders` on a response shows exactly what was
  sent for the final request, as it went on the wire.
- **`max_response_body`** caps a decompressed response body at 100 MiB by
  default, so an unbounded or malicious response, including a
  decompression bomb, fails the request with `Error::Body` instead of
  filling memory. Set it to `0` to disable the cap: `--max-response-body`
  (CLI), `maxResponseBody` (Node), `max_response_body` (Python and R).
- **`server_padding`** pins the group of Chrome, Edge and Opera 151+'s
  `PqcBandwidthExperiment` server-padding trial (`none`, or a byte count)
  instead of letting koon draw one per client: `--server-padding` in the
  CLI (shared with `koon verify`), `serverPadding` in Node,
  `server_padding` in Python and R.
- **Cookie import and export** ([#5](https://github.com/scrape-hub/koon/issues/5)):
  `set_cookies()`/`cookies()` read and write cookies in Playwright/CDP
  format, validated the way a browser validates them. Contributed by
  @privatenumber.
- **Plain `http://` URLs** ([#3](https://github.com/scrape-hub/koon/issues/3))
  now send the header set browsers use for insecure origins, and `ws://`
  WebSockets are supported too.
- **Streaming** request bodies no longer need to be buffered in memory
  (`Body::stream`; the CLI streams `-d @file` from disk). `KoonSync`
  supports streaming as well, and a streaming response can be released
  before it finishes.
- **`shutdown()`** ends HTTP/3 connections the way a browser does when it
  quits.
- **`resolve`** pins a hostname to a fixed address, like curl's
  `--resolve`.
- **`SSLKEYLOGFILE`** is now supported for TCP, QUIC and DoH connections,
  for decrypting traffic in Wireshark.
- **Profile API**: `version(major, Os)` constructors, public `Os` and
  `Browser` enums, `BrowserProfile::names()` and `ContentDecoder`.
  `koon_core::ConnectionOptions` assembles a client's proxy, DoH, locale,
  retry and TLS settings into one struct, shared by the CLI and every
  binding.
- **Bindings**: Node gets `Koon.browsers()`, header pairs and `Headers`
  objects, and async-iterable streaming responses. Python gets
  `koon.browsers()`, context managers, `py.typed`, picklable errors and
  `KoonInvalidArgument`. R gets `$close()`, `$shutdown()`, classed
  conditions and a testthat suite. The npm packages, Python wheels and
  GitHub Release now ship third-party license notices.
- **CLI**: new `-F`/`--form`, `-I`/`--head`, `-i`/`--include` and
  `-f`/`--fail` flags. curl's `-L`, `-s`, `-S` and `--compressed` are
  accepted without changing behavior, so a curl command line copied as is
  still runs.

### Changed

- **Default OS**: profile names without an OS now resolve to Windows
  rather than macOS, since it is the more common desktop platform. Safari
  still defaults to macOS, and mobile browsers to Android or iOS.
- **Rust API**: streaming responses now follow redirects and apply
  backpressure, and `HttpResponse::text()` returns a `Cow<str>`. Hooks
  return `Result`, and a hook's error fails the request without a retry.
  See Breaking changes for the renamed methods and the new `Error`
  variants.
- **Profile JSON**: an unknown or misspelled field now fails with that
  field's name instead of being silently ignored. `danger_accept_invalid_certs`
  is no longer read from JSON, so a shared profile file can no longer
  disable certificate verification.
- **Certificate verification** now uses one root store for every profile:
  Mozilla's roots plus every trust anchor of the embedded Chrome Root
  Stores.
- **Connection behavior now matches Chrome**: parallel requests to the
  same origin share one new HTTP/2 or HTTP/3 connection, QUIC races TCP
  instead of always going first, a broken HTTP/3 alternative backs off and
  recovers on its own, and DNS results are cached for 60 seconds.
- **OkHttp** profiles are now `okhttp/5.5.0` and `okhttp/4.12.0`, with the
  headers, HTTP/2 behavior and ClientHello of OkHttp running on Android 14
  and later.
- **MITM proxy**: `ProxyServerConfig.client` now takes every connection
  option. Its default `Impersonate` mode forwards the client's own request
  headers, so cookies, auth headers and form posts work as expected, and
  request and response bodies stream instead of being buffered.
- **Errors**: new codes `PROTOCOL_ERROR`, `BODY_ERROR`,
  `COOKIE_JAR_DISABLED`, `INVALID_COOKIE`, `INVALID_ARGUMENT` and
  `HOOK_ERROR`. Non-ASCII header values are now allowed.
- **Performance**: BoringSSL now builds fully optimized on every platform,
  cutting the CPU time of a Windows TLS 1.3 handshake from 3.7 ms to
  1.1 ms (release builds use `opt-level = 3`). Response bodies are copied
  less, and large ones are decoded off the async runtime; a QUIC
  connection to an ECH-supporting origin now reuses the client's shared
  TLS context instead of rebuilding one.
- **Bindings**: Node uses plain `number` byte counters, stable
  `headers`/`body` objects, fractional timeouts and stricter argument
  checks. Python's `Koon` methods are coroutines, `KoonSync` is now a
  native implementation that releases the GIL, works inside a running
  event loop and responds to Ctrl+C, and timeouts accept floats. R's
  `timeout = 0` now means no timeout, timeouts accept fractions, and
  `koon_browsers()` returns full profile names. The CLI uses curl's exit
  codes, `--timeout` takes fractions, `-o` writes the file as the body
  arrives, and `-v` masks proxy credentials in its output.
- **R install from GitHub**: the package now ships its `Cargo.lock`, so
  `remotes::install_github()` builds with the dependency versions koon was
  tested with instead of whatever is newest at install time.

### Removed

- **`randomize`** is gone: it produced fingerprints no real browser sends,
  which made clients using it easier to single out, not harder.
- **Files from koon 0.8**: profile JSON, session files and MITM CA
  certificates written by 0.8 are rejected, with an error that says what
  to do instead.
- **Rust**: the per-version profile constructors such as `v154_windows()`,
  `latest_android()`, `latest_ios()`, `OkHttp::v4()` and `v5()`, the
  `request_with_headers`, `request_with_headers_and_proxy`,
  `request_streaming`, `request_streaming_with_headers` and
  `request_streaming_with_headers_and_proxy` methods, `AlpsProtocol`, a few
  `QuicConfig` fields the stack now decides on its own, and internal types
  that are no longer public (`TlsConnector`, `SessionCache`,
  `Multipart::content_type()`).
- **`CertAuthority`** is now crate-internal: everything a caller could do
  with the MITM proxy's CA is available through `ProxyServer` instead
  (`ca_cert_path()`, `ca_cert_pem()`).

### Security

- **Multipart header injection**: field names and filenames passed to
  `Multipart`/`post_multipart()` are now escaped before they go into the
  `Content-Disposition` header. Before this fix, CR, LF and `"` went
  through unescaped, so a caller-controlled name or filename (for example,
  a user's uploaded filename) could inject extra part headers into the
  request body. This affected every released version through 0.8.1.
- **DNS-over-HTTPS responses** are now capped at a DNS message's maximum
  size and read under a single timeout, so a misbehaving DoH server can no
  longer hang a lookup or grow memory without limit.

### Fixed

- **Chrome 152** lacked the trust_anchors extension, so its JA4 was wrong.
- **Firefox's ClientHello** had several mismatches, now fixed: `server_name`
  was out of place in the pinned extension order, which produced the wrong
  JA3 for every request to a hostname; resumed handshakes still sent
  `session_ticket`; it offered two key shares instead of three; ECH GREASE
  used BoringSSL's shape instead of NSS's; and Firefox 154 still offered
  cipher `0xc00a`. Its QUIC ClientHello no longer repeats the ffdhe groups
  from the TCP one.
- **OkHttp's ClientHello** used values from another TLS library; it now
  sends OkHttp's own (no 3DES, `psk_key_exchange_modes`, TLS 1.3
  resumption, and each version's own cipher order).
- **Firefox 147 and later** now weights Accept-Language in 0.1 steps,
  matching real Firefox.
- **Safari on iOS 26** reports the frozen OS version real Safari sends
  (`18_6` or `18_7`) instead of the actual iOS version.
- **Request headers**: fixed the header order for each browser; POSTs and
  other unsafe methods are now sent as a fetch() request with an Origin
  header; a GET with a non-HTML `Accept` header is now treated as a
  fetch() too; `sec-fetch-site` is now derived correctly from Referer and
  Origin; and HTTP/1.1 header casing was corrected.
- **Safari before fetch metadata** (`safari156`, `safari160`, `safari161`,
  covering macOS 12/13 and iOS 16.0/16.1) wrongly sent the
  macOS-14-and-later header order and `Sec-Fetch-*` headers on
  subresources, fetch(), form posts and its WebSocket handshake, even
  though these releases never send fetch metadata. A fetch()/XHR request
  without an explicit `Accept` header also kept the navigation's
  `text/html` instead of `*/*`.
- **WebSocket handshakes** now follow the browser's own (Origin, cookies,
  fetch metadata); sending and receiving no longer block each other, and
  the socket closes properly on the server's Close frame.
- **Multipart and content decoding**: the multipart body now uses the
  browser's boundary format, and decoding now handles empty encoded
  bodies, stacked and upper-case encodings, truncated bodies and both
  `deflate` variants correctly.
- **Retries** no longer repeat a request that may already have been
  processed. A POST partway through a redirect chain used to be resent;
  retries now work correctly per redirect hop.
- **Timeouts** now cover the whole request, including the TLS handshake,
  the proxy connection and the body.
- **Redirects** now follow the Fetch Standard.
- **Proxy and ECH**: a retry after an ECH failure could bypass the proxy,
  and DoH/ECH lookups ran from the local IP even when a proxy was
  configured. A host's ECH config also lived in one shared, per-client map
  rather than following the connection, so two connections to the same
  host starting close together could race on or clear each other's entry;
  each connection now carries its own.
- **Connections**: TLS session tickets are now scoped to origin and proxy
  (previously one ticket was shared across an entire proxy rotation);
  Happy Eyeballs now tries all resolved addresses; `local_address` and
  `ip_version` had several fixes; and a dead pooled connection is now
  detected before it is reused.
- **HTTP/3**: Chromium 150 and later profiles could not set up an HTTP/3
  connection at all. Also fixed: bodies truncated by an empty DATA frame
  (seen from Cloudflare), 1xx responses, IPv6, `local_address` and
  `danger_accept_invalid_certs` over QUIC, a roughly 1-second handshake
  delay on Windows, and lost first packets on small-MTU paths.
- **Cookie jar**: fixed public-suffix and prefix checks, date formats and
  RFC 6265bis parsing; a manual `Cookie` header is now merged with the jar.
- **Profile names**: an unsupported browser/OS combination used to
  silently fall back to a macOS profile; it now fails with an error.
- **`tlsResumed`** ([#1](https://github.com/scrape-hub/koon/issues/1)) now
  reports the connection that actually carried the request.
- **MITM proxy**: fixed long hostnames and IP literals, pipelining,
  session resumption, and certificates that strict verifiers accept. A
  stalled client socket no longer blocks a connection forever, unbounded
  connections now time out and are capped by `max_connections`, and the
  leaf-certificate cache evicts the least recently used entry, not an
  arbitrary one, once it reaches its 10,000-host limit.
- **Bindings**: Node's `ws.receive()` used to block `send()`. Python's
  `bytes_received` was always 0. R had fixes to error handling, interrupts
  and binary bodies, and previously failed to install on Linux and macOS
  without the OpenSSL development files. The CLI used to abort on binary
  output to the Windows console.

## Earlier versions

Versions 0.4.4 to 0.8.1 were released as 0.x on PyPI and npm. 1.0.0 replaces
them; the breaking changes above list everything needed to upgrade from
0.8.1.
