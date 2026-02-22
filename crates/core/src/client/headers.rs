use http::{HeaderName, HeaderValue, Uri};

/// Build an HTTP header map from profile/custom/extra headers with cookie injection.
///
/// Consolidates the repeated header-building pattern used across H2, H1, and WebSocket.
/// - `authority`: `Some(host)` for H1/WS (inserts Host header), `None` for H2
/// - `keepalive`: `true` for H1 (inserts Connection: keep-alive)
/// - `skip`: lowercase header names to skip from profile_headers (e.g. `["host", "cookie"]`)
/// - `request_url`: the target URI, used for auto-detecting sec-fetch-* headers
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
    request_url: Option<&Uri>,
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
        if skip.contains(&lower.as_str()) {
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

    // Auto-detect sec-fetch-* metadata (only if user didn't explicitly set sec-fetch-mode)
    let user_set_fetch_mode = custom_headers
        .iter()
        .chain(extra_headers.iter())
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-fetch-mode"));
    let cors_detected = if !user_set_fetch_mode {
        auto_detect_fetch_metadata(&mut headers, request_url)
    } else {
        false
    };

    // Sort to match profile/cors order (critical for fingerprinting)
    // Chromium cors requests have a different header order than navigation requests.
    let is_chromium = profile_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-ch-ua"));
    if cors_detected && is_chromium {
        sort_headers_chromium_cors(&mut headers);
    } else {
        sort_headers_by_profile(&mut headers, profile_headers);
    }

    headers
}

/// Automatically adjust sec-fetch-* headers based on request context.
///
/// When a profile sets sec-fetch-mode: navigate (Chrome/Edge/Opera default), but the
/// request contains an Origin header or API content-type, the sec-fetch-* values are
/// corrected to match what a real browser would send for a fetch/XHR request.
///
/// This prevents Akamai from detecting the inconsistency between navigate + Origin.
fn auto_detect_fetch_metadata(headers: &mut http::HeaderMap, request_url: Option<&Uri>) -> bool {
    // Only applies if the profile set sec-fetch-mode (Chrome/Edge/Opera)
    if !headers.contains_key("sec-fetch-mode") {
        return false;
    }

    let has_origin = headers.contains_key("origin");
    let is_api_content = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.starts_with("application/json")
                || ct.starts_with("application/x-www-form-urlencoded")
                || ct.contains("multipart/form-data")
        });

    if has_origin || is_api_content {
        // Switch from navigate to cors/fetch mode
        headers.insert(
            HeaderName::from_static("sec-fetch-mode"),
            HeaderValue::from_static("cors"),
        );
        headers.insert(
            HeaderName::from_static("sec-fetch-dest"),
            HeaderValue::from_static("empty"),
        );
        // sec-fetch-user: ?1 is only valid for navigate
        headers.remove("sec-fetch-user");
        // upgrade-insecure-requests is only sent for navigation, not fetch/XHR
        headers.remove("upgrade-insecure-requests");
        // Fix priority: u=0 (navigation) → u=1 (fetch)
        if headers
            .get("priority")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|p| p.contains("u=0"))
        {
            headers.insert(
                HeaderName::from_static("priority"),
                HeaderValue::from_static("u=1, i"),
            );
        }

        if has_origin {
            // Compute sec-fetch-site from Origin vs request URL
            let origin_value = headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if let (Some(url), Some(origin)) = (request_url, origin_value) {
                let site = compute_fetch_site(url, &origin);
                headers.insert(
                    HeaderName::from_static("sec-fetch-site"),
                    HeaderValue::from_static(site),
                );
            }
        } else {
            // API content-type without Origin → same-origin
            headers.insert(
                HeaderName::from_static("sec-fetch-site"),
                HeaderValue::from_static("same-origin"),
            );
        }

        true
    } else {
        false
    }
}

/// Compute the sec-fetch-site value by comparing the request URL with the Origin header.
///
/// Returns "same-origin", "same-site", or "cross-site".
fn compute_fetch_site(request_url: &Uri, origin_value: &str) -> &'static str {
    let Ok(origin_uri) = origin_value.parse::<Uri>() else {
        return "cross-site";
    };

    let req_scheme = request_url.scheme_str().unwrap_or("");
    let req_host = request_url.host().unwrap_or("");
    let req_port = request_url
        .port_u16()
        .unwrap_or(if req_scheme == "https" { 443 } else { 80 });

    let origin_scheme = origin_uri.scheme_str().unwrap_or("");
    let origin_host = origin_uri.host().unwrap_or("");
    let origin_port = origin_uri
        .port_u16()
        .unwrap_or(if origin_scheme == "https" { 443 } else { 80 });

    // Same-origin: scheme + host + port all match
    if req_scheme == origin_scheme && req_host == origin_host && req_port == origin_port {
        return "same-origin";
    }

    // Same-site: same scheme + same registrable domain
    if req_scheme == origin_scheme && same_registrable_domain(req_host, origin_host) {
        return "same-site";
    }

    "cross-site"
}

/// Check if two hostnames share the same registrable domain (eTLD+1 approximation).
fn same_registrable_domain(host1: &str, host2: &str) -> bool {
    let d1 = registrable_domain(host1);
    let d2 = registrable_domain(host2);
    !d1.is_empty() && d1 == d2
}

/// Extract the approximate registrable domain (last two labels) from a hostname.
///
/// e.g., "api.shop.example.com" → "example.com", "example.com" → "example.com"
fn registrable_domain(host: &str) -> &str {
    let bytes = host.as_bytes();
    let mut last_dot = None;
    let mut second_last_dot = None;
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'.' {
            if last_dot.is_none() {
                last_dot = Some(i);
            } else {
                second_last_dot = Some(i);
                break;
            }
        }
    }
    match second_last_dot {
        Some(pos) => &host[pos + 1..],
        None => host,
    }
}

/// Header order for Chromium-based browsers in CORS/fetch mode.
///
/// When Chrome makes a fetch() or XHR request (as opposed to a navigation),
/// headers appear in a different order than the navigation profile. This list
/// includes slots for common API headers (content-type, origin, referer, cookie)
/// that are absent from the navigation profile but must appear at specific
/// positions to avoid Akamai fingerprint mismatches.
const CHROMIUM_CORS_ORDER: &[&str] = &[
    "content-length",
    "sec-ch-ua",
    "content-type",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "user-agent",
    "accept",
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

/// Sort headers for Chromium CORS/fetch requests.
///
/// Uses a hardcoded order that matches real Chrome fetch() behavior.
/// Any headers not in the list (app-specific custom headers like Authorization,
/// ama-client-facts, etc.) are appended after the known headers.
fn sort_headers_chromium_cors(headers: &mut http::HeaderMap) {
    let mut sorted = http::HeaderMap::with_capacity(headers.keys_len());

    // 1. Known headers in Chrome CORS order
    for &name in CHROMIUM_CORS_ORDER {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            if let Some(val) = headers.remove(&hn) {
                sorted.insert(hn, val);
            }
        }
    }

    // 2. Remaining headers (app-specific custom headers)
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            sorted.insert(name, value);
        }
    }

    std::mem::swap(headers, &mut sorted);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registrable_domain() {
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("api.example.com"), "example.com");
        assert_eq!(registrable_domain("api.shop.example.com"), "example.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn test_compute_fetch_site_same_origin() {
        let url: Uri = "https://api.example.com/v1/data".parse().unwrap();
        assert_eq!(compute_fetch_site(&url, "https://api.example.com"), "same-origin");
    }

    #[test]
    fn test_compute_fetch_site_same_site() {
        let url: Uri = "https://api.example.com/v1/data".parse().unwrap();
        assert_eq!(compute_fetch_site(&url, "https://www.example.com"), "same-site");
    }

    #[test]
    fn test_compute_fetch_site_cross_site() {
        let url: Uri = "https://api.example.com/v1/data".parse().unwrap();
        assert_eq!(compute_fetch_site(&url, "https://other.com"), "cross-site");
    }

    #[test]
    fn test_compute_fetch_site_different_scheme() {
        let url: Uri = "https://example.com/path".parse().unwrap();
        assert_eq!(compute_fetch_site(&url, "http://example.com"), "cross-site");
    }

    #[test]
    fn test_auto_detect_with_origin() {
        // Chrome-like profile headers with sec-fetch-mode: navigate
        let profile_headers = vec![
            ("sec-fetch-mode".into(), "navigate".into()),
            ("sec-fetch-site".into(), "none".into()),
            ("sec-fetch-dest".into(), "document".into()),
            ("sec-fetch-user".into(), "?1".into()),
        ];
        let custom_headers = vec![("Origin".into(), "https://shop.example.com".into())];
        let url: Uri = "https://api.example.com/v1/cart".parse().unwrap();

        let headers = build_request_headers(
            &profile_headers,
            &custom_headers,
            &[],
            None,
            &[],
            None,
            false,
            Some(&url),
        );

        assert_eq!(headers.get("sec-fetch-mode").unwrap(), "cors");
        assert_eq!(headers.get("sec-fetch-dest").unwrap(), "empty");
        assert_eq!(headers.get("sec-fetch-site").unwrap(), "same-site");
        assert!(headers.get("sec-fetch-user").is_none());
    }

    #[test]
    fn test_auto_detect_without_origin_navigate_preserved() {
        let profile_headers = vec![
            ("sec-fetch-mode".into(), "navigate".into()),
            ("sec-fetch-site".into(), "none".into()),
            ("sec-fetch-dest".into(), "document".into()),
            ("sec-fetch-user".into(), "?1".into()),
        ];
        let url: Uri = "https://example.com/page".parse().unwrap();

        let headers = build_request_headers(
            &profile_headers,
            &[],
            &[],
            None,
            &[],
            None,
            false,
            Some(&url),
        );

        assert_eq!(headers.get("sec-fetch-mode").unwrap(), "navigate");
        assert_eq!(headers.get("sec-fetch-site").unwrap(), "none");
        assert_eq!(headers.get("sec-fetch-dest").unwrap(), "document");
        assert_eq!(headers.get("sec-fetch-user").unwrap(), "?1");
    }

    #[test]
    fn test_auto_detect_with_json_content_type() {
        let profile_headers = vec![
            ("sec-fetch-mode".into(), "navigate".into()),
            ("sec-fetch-site".into(), "none".into()),
            ("sec-fetch-dest".into(), "document".into()),
        ];
        let custom_headers = vec![("content-type".into(), "application/json".into())];
        let url: Uri = "https://api.example.com/data".parse().unwrap();

        let headers = build_request_headers(
            &profile_headers,
            &custom_headers,
            &[],
            None,
            &[],
            None,
            false,
            Some(&url),
        );

        assert_eq!(headers.get("sec-fetch-mode").unwrap(), "cors");
        assert_eq!(headers.get("sec-fetch-dest").unwrap(), "empty");
        assert_eq!(headers.get("sec-fetch-site").unwrap(), "same-origin");
    }

    #[test]
    fn test_user_override_skips_auto_detect() {
        let profile_headers = vec![
            ("sec-fetch-mode".into(), "navigate".into()),
            ("sec-fetch-site".into(), "none".into()),
        ];
        let custom_headers = vec![
            ("Origin".into(), "https://other.com".into()),
            ("sec-fetch-mode".into(), "no-cors".into()),
        ];
        let url: Uri = "https://api.example.com/data".parse().unwrap();

        let headers = build_request_headers(
            &profile_headers,
            &custom_headers,
            &[],
            None,
            &[],
            None,
            false,
            Some(&url),
        );

        // User explicitly set sec-fetch-mode → auto-detection skipped
        assert_eq!(headers.get("sec-fetch-mode").unwrap(), "no-cors");
    }

    #[test]
    fn test_no_sec_fetch_in_profile_skips_auto_detect() {
        // Firefox-like profile without sec-fetch-* headers
        let profile_headers = vec![
            ("accept".into(), "text/html".into()),
            ("user-agent".into(), "Mozilla/5.0".into()),
        ];
        let custom_headers = vec![("Origin".into(), "https://example.com".into())];
        let url: Uri = "https://api.example.com/data".parse().unwrap();

        let headers = build_request_headers(
            &profile_headers,
            &custom_headers,
            &[],
            None,
            &[],
            None,
            false,
            Some(&url),
        );

        // No sec-fetch-mode in profile → nothing to auto-detect
        assert!(headers.get("sec-fetch-mode").is_none());
    }
}
