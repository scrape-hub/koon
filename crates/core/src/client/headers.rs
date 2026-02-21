use http::{HeaderName, HeaderValue};

/// Build an HTTP header map from profile/custom/extra headers with cookie injection.
///
/// Consolidates the repeated header-building pattern used across H2, H1, and WebSocket.
/// - `authority`: `Some(host)` for H1/WS (inserts Host header), `None` for H2
/// - `keepalive`: `true` for H1 (inserts Connection: keep-alive)
/// - `skip`: lowercase header names to skip from profile_headers (e.g. `["host", "cookie"]`)
///
/// Headers are sorted to match profile order before returning.
pub(super) fn build_request_headers(
    profile_headers: &[(String, String)],
    custom_headers: &[(String, String)],
    extra_headers: &[(String, String)],
    cookie_header: Option<&str>,
    skip: &[&str],
    authority: Option<&str>,
    keepalive: bool,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();

    // Host header (H1/WS only)
    if let Some(auth) = authority {
        if let Ok(hv) = HeaderValue::from_str(auth) {
            headers.insert(http::header::HOST, hv);
        }
    }

    // Profile headers
    for (name, value) in profile_headers {
        let lower = name.to_lowercase();
        if skip.iter().any(|s| *s == lower.as_str()) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(hn, hv);
        }
    }

    // Custom headers (override profile defaults)
    for (name, value) in custom_headers {
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(hn, hv);
        }
    }

    // Extra headers (override custom, e.g. multipart content-type)
    for (name, value) in extra_headers {
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(hn, hv);
        }
    }

    // Cookie from jar
    if let Some(cookie_val) = cookie_header {
        if let Ok(hv) = HeaderValue::from_str(cookie_val) {
            headers.insert(http::header::COOKIE, hv);
        }
    }

    // Connection: keep-alive (H1 only)
    if keepalive {
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
    }

    // Sort to match profile order (critical for fingerprinting)
    sort_headers_by_profile(&mut headers, profile_headers);

    headers
}

/// Sort headers to match the profile's header order.
/// Headers listed in the profile are inserted first in profile order,
/// then any remaining headers (custom, cookie) are appended.
pub(super) fn sort_headers_by_profile(
    headers: &mut http::HeaderMap,
    profile_order: &[(String, String)],
) {
    let mut sorted = http::HeaderMap::with_capacity(headers.keys_len());

    // 1. Headers in profile order
    for (name, _) in profile_order {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            if let Some(val) = headers.remove(&hn) {
                sorted.insert(hn, val);
            }
        }
    }

    // 2. Remaining headers (custom, cookie, etc.)
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            sorted.insert(name, value);
        }
    }

    std::mem::swap(headers, &mut sorted);
}
