//! Captured header-order tables.
//!
//! Pure data: every `CHROMIUM_NAV`/`FIREFOX_*`/`OKHTTP*`/`SAFARI_*` order, consumed by `order.rs`.

/// Marks where headers set by the caller (and not listed) go.
pub(super) const CUSTOM: &str = "<custom>";

/// Chromium navigation/form submission (Chrome 153); hints in Chromium's own order, `ACCEPT_CH`
/// additions follow `accept` (see [`AddedHints`](super::AddedHints)).
pub(super) const CHROMIUM_NAV: &[&str] = &[
    "content-length",
    "cache-control",
    CUSTOM,
    "device-memory",
    "sec-ch-device-memory",
    "dpr",
    "sec-ch-dpr",
    "viewport-width",
    "sec-ch-viewport-width",
    "sec-ch-viewport-height",
    "rtt",
    "downlink",
    "ect",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-full-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-form-factors",
    "sec-ch-prefers-color-scheme",
    "sec-ch-prefers-reduced-motion",
    "sec-ch-prefers-reduced-transparency",
    "upgrade-insecure-requests",
    "content-type",
    "user-agent",
    "origin",
    "accept",
    "sec-gpc",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "priority",
];

/// Headers Chromium appends after Blink's header map on `fetch()`/subresource requests (Chrome
/// 153/155); Cookie precedes Priority except on HTTP/1.1.
pub(super) const CHROMIUM_NETWORK_TAIL: &[&str] = &[
    "accept",
    "sec-gpc",
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "priority",
];

/// Firefox navigation/form submission (Firefox 156); Cookie holds its slot on every protocol,
/// Alt-Used only over HTTP/3.
pub(super) const FIREFOX_NAV: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "alt-used",
    "content-type",
    "content-length",
    "origin",
    "referer",
    CUSTOM,
    "connection",
    "cookie",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "priority",
    "te",
];

/// Firefox `fetch()` (Firefox 155-157); Referer first, then the page's own headers, Cookie as in
/// [`FIREFOX_NAV`]. Also used for `XMLHttpRequest`/sendBeacon, whose Referer-after-Origin order a
/// request can't be told apart from.
pub(super) const FIREFOX_CORS: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "alt-used",
    "referer",
    CUSTOM,
    "content-type",
    "content-length",
    "origin",
    "connection",
    "cookie",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "priority",
    "te",
];

/// `OkHttp` (4.12.0/5.5.0): the application's headers, then `BridgeInterceptor`'s; Host/Connection
/// only reach the wire on HTTP/1.1.
pub(super) const OKHTTP: &[&str] = &[
    CUSTOM,
    "content-type",
    "content-length",
    "host",
    "connection",
    "accept-encoding",
    "cookie",
    "user-agent",
];

/// Headers `OkHttp` adds only when the application has not set them itself.
pub(super) const OKHTTP_IF_ABSENT: &[&str] = &["connection", "accept-encoding", "user-agent"];

/// Safari on macOS 14/iOS 17 (`CFNetwork` hash order, changes per header set present): navigation
/// GET without Referer; see [`SAFARI_SONOMA_GET_REFERER`]/[`SAFARI_SONOMA_BODY`] for the other
/// captured sets.
pub(super) const SAFARI_SONOMA_GET: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "cookie",
    "accept-encoding",
    "sec-fetch-mode",
    "user-agent",
    "accept-language",
    "sec-fetch-dest",
    CUSTOM,
];

/// Safari on macOS 14 and iOS 17: a GET with a Referer.
pub(super) const SAFARI_SONOMA_GET_REFERER: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "cookie",
    "sec-fetch-dest",
    "accept-language",
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "accept-encoding",
    CUSTOM,
];

/// Safari on macOS 14/iOS 17: a request with a body, form submission or `fetch()`.
pub(super) const SAFARI_SONOMA_BODY: &[&str] = &[
    "content-type",
    "accept",
    "sec-fetch-site",
    "accept-language",
    "accept-encoding",
    "sec-fetch-mode",
    "origin",
    "user-agent",
    "referer",
    "content-length",
    "sec-fetch-dest",
    "cookie",
    CUSTOM,
];

/// Safari on macOS 14/iOS 17 over HTTP/3: a GET without Referer, with `priority`, in a different
/// hash order than HTTP/2.
pub(super) const SAFARI_SONOMA_H3_GET: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "cookie",
    "priority",
    "sec-fetch-mode",
    "user-agent",
    "accept-language",
    "sec-fetch-dest",
    "accept-encoding",
    CUSTOM,
];

/// Safari on macOS 14/iOS 17 over HTTP/3: a GET with a Referer (navigations, `fetch()` and
/// subresources alike).
pub(super) const SAFARI_SONOMA_H3_GET_REFERER: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "priority",
    "accept-encoding",
    "sec-fetch-mode",
    "accept-language",
    "user-agent",
    "referer",
    "cookie",
    "sec-fetch-dest",
    CUSTOM,
];

/// Safari on macOS 14/iOS 17 over HTTP/3, a body request: the HTTP/2 layout with `priority` after
/// `sec-fetch-site`.
pub(super) const SAFARI_SONOMA_H3_BODY: &[&str] = &[
    "content-type",
    "accept",
    "sec-fetch-site",
    "priority",
    "accept-language",
    "accept-encoding",
    "sec-fetch-mode",
    "origin",
    "user-agent",
    "referer",
    "content-length",
    "sec-fetch-dest",
    "cookie",
    CUSTOM,
];

/// Safari before fetch metadata (macOS 12/13 and iOS 16.0/16.1, `fetch_metadata: false`): a first
/// navigation, no cookie and no referer yet: the same order the profile's own navigation template
/// already uses. Captured from macOS 12.5, 12.6 (Safari 15.6.1) and 13.0/13.6 and the iOS 16.0/16.1
/// simulators; identical over HTTP/2 and HTTP/3 (the header set, and so the hash order, does not
/// change with the transport here: unlike the fetch-metadata tables above, this state never adds a
/// `priority` header).
pub(super) const SAFARI_SONOMA_LEGACY_FIRST: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    CUSTOM,
];

/// Safari before fetch metadata: a repeated navigation, with a cookie but no referer.
pub(super) const SAFARI_SONOMA_LEGACY_GET: &[&str] = &[
    "cookie",
    "accept",
    "user-agent",
    "accept-language",
    "accept-encoding",
    CUSTOM,
];

/// Safari before fetch metadata: any GET with a referer (`fetch()`, subresources, a link click),
/// the four request kinds only differ in `accept`'s value, not its position.
pub(super) const SAFARI_SONOMA_LEGACY_GET_REFERER: &[&str] = &[
    "cookie",
    "accept",
    "accept-encoding",
    "user-agent",
    "accept-language",
    "referer",
    CUSTOM,
];

/// Safari before fetch metadata: a request with a body (`fetch()`/XHR or a form submission).
pub(super) const SAFARI_SONOMA_LEGACY_BODY: &[&str] = &[
    "accept",
    "content-type",
    "origin",
    "cookie",
    "content-length",
    "accept-language",
    "user-agent",
    "referer",
    "accept-encoding",
    CUSTOM,
];

/// Safari from macOS 15/iOS 18 on: navigations, `fetch()` and subresource GETs; a cross-origin
/// `fetch()` (has an Origin) uses [`SAFARI_CORS_GET`] instead.
pub(super) const SAFARI_GET: &[&str] = &[
    "sec-fetch-dest",
    "user-agent",
    "accept",
    "referer",
    "sec-fetch-site",
    "sec-fetch-mode",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari from macOS 15/iOS 18 on: the cross-origin `fetch()` GET (has an Origin).
pub(super) const SAFARI_CORS_GET: &[&str] = &[
    "sec-fetch-site",
    "accept",
    "origin",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari from macOS 15/iOS 18 on: body requests, form submissions and `fetch()` to macOS's own
/// origin; iOS and cross-origin use [`SAFARI_BODY_SITE_FIRST`].
pub(super) const SAFARI_BODY: &[&str] = &[
    "accept",
    "content-type",
    "origin",
    "sec-fetch-site",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "content-length",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari on iOS 18+, and macOS to another origin: [`SAFARI_BODY`] with `sec-fetch-site` before
/// `origin`.
pub(super) const SAFARI_BODY_SITE_FIRST: &[&str] = &[
    "accept",
    "content-type",
    "sec-fetch-site",
    "origin",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "content-length",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari from macOS 15/iOS 18 on: the CORS preflight, an OPTIONS with `Content-Length: 0`.
pub(super) const SAFARI_PREFLIGHT: &[&str] = &[
    "origin",
    "sec-fetch-site",
    "access-control-request-method",
    "access-control-request-headers",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "content-length",
    "accept",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari on plain http (HTTP/1.1, no fetch metadata): a navigation typed into the address bar.
pub(super) const SAFARI_HTTP_NAVIGATE: &[&str] = &[
    "user-agent",
    "upgrade-insecure-requests",
    "accept",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari on plain http: a navigation from a page.
pub(super) const SAFARI_HTTP_NAVIGATE_REFERER: &[&str] = &[
    "user-agent",
    "accept",
    "upgrade-insecure-requests",
    "referer",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari on plain http: `fetch()` and subresource GETs.
pub(super) const SAFARI_HTTP_GET: &[&str] = &[
    "referer",
    "accept",
    "user-agent",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari on plain http: `fetch()` with a body.
pub(super) const SAFARI_HTTP_BODY: &[&str] = &[
    "user-agent",
    "accept",
    "content-type",
    "referer",
    "origin",
    "content-length",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

/// Safari on plain http: a form submission.
pub(super) const SAFARI_HTTP_FORM: &[&str] = &[
    "accept",
    "origin",
    "content-type",
    "upgrade-insecure-requests",
    "user-agent",
    "referer",
    "content-length",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];
