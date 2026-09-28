use http::{Method, Uri};

use super::support::{Request, names};
use crate::client::headers::fetch_metadata::compute_fetch_site;
use crate::client::headers::{Family, HeaderInput, Protocol, build, header_value};
use crate::client::headers::{build_websocket, build_websocket_h2};
use crate::profile::{BrowserProfile, Chrome, Firefox};

fn build_for(
    profile: &BrowserProfile,
    protocol: Protocol,
    method: Method,
    url: &str,
    request: &[(&str, &str)],
    cookie: Option<&str>,
    body_len: Option<usize>,
) -> Vec<(String, String)> {
    Request {
        protocol,
        headers: request,
        cookie,
        body_len,
        ..Request::new(profile, method, url)
    }
    .build()
}

fn value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    header_value(headers, name)
}
#[test]
fn test_family_detection() {
    assert_eq!(Family::of(&Chrome::latest()), Family::Chromium);
    assert_eq!(Family::of(&Firefox::latest()), Family::Firefox);
    // Without its family and client hints, a Chromium profile looks like Safari; the profile's own
    // family wins.
    let mut custom = Chrome::latest();
    custom.headers.retain(|(k, _)| !k.starts_with("sec-ch-ua"));
    assert_eq!(Family::of(&custom), Family::Chromium);
    custom.header_family = None;
    assert_eq!(Family::of(&custom), Family::Safari);
}

/// Chrome and Firefox add no Origin header; sec-fetch-site derives from the Referer's page.
#[test]
fn test_navigation_with_referer_derives_fetch_site() {
    for p in [Chrome::latest(), Firefox::latest()] {
        let site = |referer: &str| {
            let h = build_for(
                &p,
                Protocol::Http2,
                Method::GET,
                "https://www.example.com/page",
                &[("Referer", referer)],
                None,
                None,
            );
            assert_eq!(value(&h, "origin"), None);
            assert_eq!(value(&h, "sec-fetch-mode"), Some("navigate"));
            value(&h, "sec-fetch-site").unwrap().to_string()
        };
        assert_eq!(site("https://www.example.com/other"), "same-origin");
        assert_eq!(site("https://shop.example.com/"), "same-site");
        assert_eq!(site("https://www.google.com/"), "cross-site");
        // A Referer that names no page leaves the typed navigation.
        assert_eq!(site("about:blank"), "none");
    }
}

/// A fetch() with a Referer but no Origin derives sec-fetch-site from the Referer instead of
/// same-origin; an Origin still wins.
#[test]
fn test_fetch_with_referer_derives_fetch_site() {
    let p = Chrome::latest();
    let fetch = |headers: &[(&str, &str)]| {
        let mut request = vec![("Accept", "application/json")];
        request.extend_from_slice(headers);
        build_for(
            &p,
            Protocol::Http2,
            Method::GET,
            "https://api.example.com/v1",
            &request,
            None,
            None,
        )
    };
    let h = fetch(&[("Referer", "https://www.shop.test/cart")]);
    assert_eq!(value(&h, "sec-fetch-mode"), Some("cors"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("cross-site"));
    assert_eq!(value(&h, "origin"), None);
    let h = fetch(&[("Referer", "https://www.example.com/")]);
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-site"));
    let h = fetch(&[]);
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    let h = fetch(&[
        ("Origin", "https://api.example.com"),
        ("Referer", "https://www.shop.test/cart"),
    ]);
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));

    // A POST without an Origin gets the one of the Referer's page.
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::POST,
        "https://api.example.com/v1",
        &[
            ("Content-Type", "application/json"),
            ("Referer", "https://www.shop.test:8443/cart"),
        ],
        None,
        Some(2),
    );
    assert_eq!(value(&h, "origin"), Some("https://www.shop.test:8443"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("cross-site"));
}

// Orders below: Chrome 153 and Firefox 156, HTTP/2 and HTTP/1.1 over TLS.

#[test]
fn test_chrome_navigation_with_cookie_and_referer_h2() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("Referer", "https://example.com/other")],
        Some("a=1"),
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority"
        ]
    );
}

#[test]
fn test_chrome_navigation_with_cookie_h1() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http1,
        Method::GET,
        "https://example.com/",
        &[],
        Some("a=1"),
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "Host",
            "Connection",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests",
            "User-Agent",
            "Accept",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-User",
            "Sec-Fetch-Dest",
            "Accept-Encoding",
            "Accept-Language",
            "Cookie"
        ]
    );
}

#[test]
fn test_chrome_fetch_post_json() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::POST,
        "https://example.com/api",
        &[
            ("Content-Type", "application/json"),
            ("Origin", "https://example.com"),
        ],
        Some("a=1"),
        Some(2),
    );
    assert_eq!(
        names(&h),
        vec![
            "content-length",
            "sec-ch-ua-platform",
            "user-agent",
            "sec-ch-ua",
            "content-type",
            "sec-ch-ua-mobile",
            "accept",
            "origin",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority"
        ]
    );
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
}

#[test]
fn test_chrome_fetch_custom_headers() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/api",
        &[
            ("sec-fetch-mode", "cors"),
            ("X-Zeta", "1"),
            ("Authorization", "Bearer t"),
            ("X-Alpha", "2"),
        ],
        None,
        None,
    );
    assert_eq!(
        names(&h)[..6],
        [
            "x-zeta",
            "x-alpha",
            "sec-ch-ua-platform",
            "authorization",
            "user-agent",
            "sec-ch-ua"
        ]
    );
    assert_eq!(value(&h, "sec-fetch-dest"), Some("empty"));
    assert_eq!(value(&h, "accept"), Some("*/*"));
}

#[test]
fn test_chrome_form_post() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::POST,
        "https://example.com/form-submit",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "https://example.com"),
            ("Referer", "https://example.com/form"),
        ],
        Some("a=1"),
        Some(7),
    );
    assert_eq!(
        names(&h),
        vec![
            "content-length",
            "cache-control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "content-type",
            "user-agent",
            "origin",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority"
        ]
    );
    assert_eq!(value(&h, "cache-control"), Some("max-age=0"));
    assert_eq!(value(&h, "sec-fetch-mode"), Some("navigate"));
}

#[test]
fn test_firefox_navigation_with_cookie_and_referer_h2() {
    let f = Firefox::latest();
    let h = build_for(
        &f,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("Referer", "https://example.com/other")],
        Some("a=1"),
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "referer",
            "cookie",
            "upgrade-insecure-requests",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "priority",
            "te"
        ]
    );
}

#[test]
fn test_firefox_navigation_with_cookie_h1() {
    let f = Firefox::latest();
    let h = build_for(
        &f,
        Protocol::Http1,
        Method::GET,
        "https://example.com/",
        &[],
        Some("a=1"),
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Connection",
            "Cookie",
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Priority"
        ]
    );
}

// HTTP/3 orders: Chrome 153 and Firefox 156 against www.google.com.

/// Headers of an HTTP/3 request on a connection to the Alt-Svc alternative `alt_used`.
fn build_h3(
    profile: &BrowserProfile,
    url: &str,
    request: &[(&str, &str)],
    cookie: Option<&str>,
    alt_used: Option<&str>,
) -> Vec<(String, String)> {
    Request {
        protocol: Protocol::Http3,
        headers: request,
        cookie,
        alt_used,
        ..Request::new(profile, Method::GET, url)
    }
    .build()
}

/// Chrome's encoder splits the cookie into one field per cookie (see `client::h3`).
#[test]
fn test_chrome_h3_cookie_before_priority() {
    let p = Chrome::latest();
    let h = build_h3(
        &p,
        "https://www.google.com/",
        &[("Referer", "https://www.google.com/")],
        Some("SEARCH_SAMESITE=CgQI; AEC=Aaa9; __Secure-ENID=Cu8B"),
        Some("www.google.com"),
    );
    assert_eq!(
        names(&h),
        vec![
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority"
        ]
    );
    assert_eq!(
        value(&h, "cookie"),
        Some("SEARCH_SAMESITE=CgQI; AEC=Aaa9; __Secure-ENID=Cu8B")
    );
    // Chrome sends no Alt-Used.
    assert_eq!(value(&h, "alt-used"), None);
}

#[test]
fn test_chrome_h3_fetch_cookie_before_priority() {
    let p = Chrome::latest();
    let h = build_h3(
        &p,
        "https://www.google.com/api",
        &[("sec-fetch-mode", "cors")],
        Some("a=1;b=2"),
        None,
    );
    let n = names(&h);
    assert_eq!(
        n[n.len() - 4..],
        ["accept-encoding", "accept-language", "cookie", "priority"]
    );
}

#[test]
fn test_firefox_h3_navigation_sends_alt_used_and_no_te() {
    let f = Firefox::latest();
    let h = build_h3(
        &f,
        "https://www.google.com/robots.txt",
        &[],
        None,
        Some("www.google.com"),
    );
    assert_eq!(
        names(&h),
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "alt-used",
            "upgrade-insecure-requests",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "priority"
        ]
    );
    assert_eq!(value(&h, "alt-used"), Some("www.google.com"));
}

#[test]
fn test_firefox_h3_fetch_keeps_one_cookie_before_fetch_metadata() {
    let f = Firefox::latest();
    let h = build_h3(
        &f,
        "https://www.google.com/shared_dict",
        &[
            ("sec-fetch-mode", "cors"),
            ("Referer", "https://www.google.com/"),
        ],
        Some("SEARCH_SAMESITE=CgQI; AEC=Aaa9"),
        Some("www.google.com"),
    );
    // The captured fetch has no Priority; koon's carries Firefox's u=4, last.
    let without_priority: Vec<&str> = names(&h).into_iter().filter(|n| *n != "priority").collect();
    assert_eq!(
        without_priority,
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "alt-used",
            "referer",
            "cookie",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site"
        ]
    );
    assert_eq!(value(&h, "cookie"), Some("SEARCH_SAMESITE=CgQI; AEC=Aaa9"));
    assert_eq!(value(&h, "te"), None);
}

#[test]
fn test_firefox_alt_used_only_on_h3_and_with_an_alternative() {
    let f = Firefox::latest();
    let h = build_h3(&f, "https://example.com/", &[], None, None);
    assert_eq!(value(&h, "alt-used"), None);
    // HTTP/2 keeps `te: trailers`, the cookie before the fetch metadata.
    let h2 = build_for(
        &f,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[],
        Some("a=1"),
        None,
    );
    assert_eq!(value(&h2, "te"), Some("trailers"));
    assert_eq!(names(&h2).last(), Some(&"te"));
    let pos = |name| names(&h2).iter().position(|n| *n == name).unwrap();
    assert_eq!(pos("cookie") + 1, pos("upgrade-insecure-requests"));
}

#[test]
fn test_firefox_fetch_custom_headers_keep_insertion_order() {
    let f = Firefox::latest();
    let h = build_for(
        &f,
        Protocol::Http2,
        Method::GET,
        "https://example.com/api",
        &[
            ("sec-fetch-mode", "cors"),
            ("Referer", "https://example.com/page"),
            ("X-Zeta", "1"),
            ("Authorization", "Bearer t"),
            ("X-Alpha", "2"),
        ],
        Some("a=1"),
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "referer",
            "x-zeta",
            "authorization",
            "x-alpha",
            "cookie",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "priority",
            "te"
        ]
    );
    assert_eq!(value(&h, "priority"), Some("u=4"));
}

#[test]
fn test_firefox_form_post() {
    let f = Firefox::latest();
    let h = build_for(
        &f,
        Protocol::Http2,
        Method::POST,
        "https://example.com/form-submit",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "https://example.com"),
            ("Referer", "https://example.com/form"),
        ],
        Some("a=1"),
        Some(7),
    );
    assert_eq!(
        names(&h),
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "content-type",
            "content-length",
            "origin",
            "referer",
            "cookie",
            "upgrade-insecure-requests",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "priority",
            "te"
        ]
    );
}

#[test]
fn test_websocket_handshakes() {
    let ws: Uri = "wss://example.com/ws".parse().unwrap();
    let http: Uri = "https://example.com/ws".parse().unwrap();
    let h = build_websocket(&Chrome::latest(), &ws, &http, "KEY", Some("a=1"), &[], &[]);
    assert_eq!(
        names(&h),
        vec![
            "Host",
            "Connection",
            "Pragma",
            "Cache-Control",
            "User-Agent",
            "Upgrade",
            "Origin",
            "Sec-WebSocket-Version",
            "Accept-Encoding",
            "Accept-Language",
            "Cookie",
            "Sec-WebSocket-Key"
        ]
    );
    assert_eq!(value(&h, "origin"), Some("https://example.com"));

    let h = build_websocket(&Firefox::latest(), &ws, &http, "KEY", Some("a=1"), &[], &[]);
    assert_eq!(
        names(&h),
        vec![
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Sec-WebSocket-Version",
            "Origin",
            "Sec-WebSocket-Key",
            "Connection",
            "Cookie",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Pragma",
            "Cache-Control",
            "Upgrade"
        ]
    );
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
}

/// The extended CONNECT layouts (Chrome 153, Firefox 156), `sec-websocket-extensions` left out
/// since koon offers none.
#[test]
fn test_websocket_h2_handshakes() {
    let ws: Uri = "wss://example.com/ws".parse().unwrap();
    let http: Uri = "https://example.com/ws".parse().unwrap();
    let protocol = [("Sec-WebSocket-Protocol".to_string(), "chat".to_string())];
    let h = build_websocket_h2(&Chrome::latest(), &ws, &http, Some("a=1"), &[], &protocol);
    assert_eq!(
        names(&h),
        vec![
            "pragma",
            "cache-control",
            "user-agent",
            "origin",
            "sec-websocket-version",
            "accept-encoding",
            "accept-language",
            "cookie",
            "sec-websocket-protocol"
        ]
    );
    assert_eq!(value(&h, "origin"), Some("https://example.com"));

    let h = build_websocket_h2(&Firefox::latest(), &ws, &http, Some("a=1"), &[], &protocol);
    assert_eq!(
        names(&h),
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-websocket-version",
            "origin",
            "sec-websocket-protocol",
            "cookie",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "pragma",
            "cache-control"
        ]
    );

    // Connection-specific caller headers cannot go out over HTTP/2.
    let caller = [
        ("Connection".to_string(), "close".to_string()),
        ("TE".to_string(), "trailers".to_string()),
        ("X-Token".to_string(), "t".to_string()),
    ];
    let h = build_websocket_h2(&Chrome::latest(), &ws, &http, None, &caller, &[]);
    assert_eq!(names(&h).last(), Some(&"x-token"));
    assert!(value(&h, "connection").is_none() && value(&h, "te").is_none());
}

#[test]
fn test_chrome_http1_starts_with_host_and_connection() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http1,
        Method::GET,
        "https://example.com:8443/x",
        &[],
        None,
        None,
    );
    assert_eq!(h[0], ("Host".to_string(), "example.com:8443".to_string()));
    assert_eq!(h[1], ("Connection".to_string(), "keep-alive".to_string()));
    assert!(names(&h).contains(&"sec-ch-ua"));
    assert!(names(&h).contains(&"User-Agent"));
}

#[test]
fn test_chrome_post_without_body_sends_zero_length() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::POST,
        "https://example.com/",
        &[],
        None,
        None,
    );
    assert_eq!(value(&h, "content-length"), Some("0"));
    let f = Firefox::latest();
    let h = build_for(
        &f,
        Protocol::Http2,
        Method::POST,
        "https://example.com/",
        &[],
        None,
        None,
    );
    assert_eq!(value(&h, "content-length"), None);
}

#[test]
fn test_cors_detection_with_json() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::POST,
        "https://api.example.com/data",
        &[
            ("content-type", "application/json"),
            ("origin", "https://www.example.com"),
        ],
        None,
        Some(2),
    );
    assert_eq!(value(&h, "sec-fetch-mode"), Some("cors"));
    assert_eq!(value(&h, "sec-fetch-dest"), Some("empty"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-site"));
    assert_eq!(value(&h, "accept"), Some("*/*"));
    assert_eq!(value(&h, "priority"), Some("u=1, i"));
    assert!(value(&h, "sec-fetch-user").is_none());
    assert!(value(&h, "upgrade-insecure-requests").is_none());
    assert_eq!(h[0].0, "content-length");
}

#[test]
fn test_form_post_stays_navigation() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::POST,
        "https://example.com/login",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("origin", "https://example.com"),
        ],
        None,
        Some(10),
    );
    assert_eq!(value(&h, "sec-fetch-mode"), Some("navigate"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    assert_eq!(value(&h, "sec-fetch-user"), Some("?1"));
}

#[test]
fn test_same_site_uses_public_suffix_list() {
    let url: Uri = "https://a.co.uk/".parse().unwrap();
    assert_eq!(compute_fetch_site(&url, "https://b.co.uk"), "cross-site");
    let url: Uri = "https://x.github.io/".parse().unwrap();
    assert_eq!(
        compute_fetch_site(&url, "https://y.github.io"),
        "cross-site"
    );
    let url: Uri = "https://api.example.com/".parse().unwrap();
    assert_eq!(
        compute_fetch_site(&url, "https://www.example.com"),
        "same-site"
    );
    let url: Uri = "https://example.com/".parse().unwrap();
    assert_eq!(compute_fetch_site(&url, "http://example.com"), "cross-site");
}

#[test]
fn test_user_fetch_mode_disables_detection() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[
            ("Origin", "https://other.com"),
            ("sec-fetch-mode", "no-cors"),
        ],
        None,
        None,
    );
    assert_eq!(value(&h, "sec-fetch-mode"), Some("no-cors"));
}

#[test]
fn test_caller_header_replaces_template_value_in_place() {
    let p = Chrome::latest();
    let base = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[],
        None,
        None,
    );
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("Accept-Language", "de-DE")],
        None,
        None,
    );
    assert_eq!(names(&base), names(&h));
    assert_eq!(value(&h, "accept-language"), Some("de-DE"));
}

#[test]
fn test_custom_headers_keep_caller_order() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("x-zeta", "1"), ("x-alpha", "2"), ("x-mid", "3")],
        None,
        None,
    );
    let n = names(&h);
    let pos = |k| n.iter().position(|x| *x == k).unwrap();
    assert!(pos("x-zeta") < pos("x-alpha") && pos("x-alpha") < pos("x-mid"));
}

#[test]
fn test_manual_cookie_merges_with_jar() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("Cookie", "session=manual; b=2")],
        Some("session=jar; c=3"),
        None,
    );
    assert_eq!(value(&h, "cookie"), Some("session=manual; b=2; c=3"));
}

#[test]
fn test_insecure_context_headers() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http1,
        Method::GET,
        "http://example.com/",
        &[],
        None,
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "Host",
            "Connection",
            "Upgrade-Insecure-Requests",
            "User-Agent",
            "Accept",
            "Accept-Encoding",
            "Accept-Language"
        ]
    );
    assert_eq!(value(&h, "accept-encoding"), Some("gzip, deflate"));

    let f = Firefox::latest();
    let h = build_for(
        &f,
        Protocol::Http1,
        Method::GET,
        "http://example.com/",
        &[],
        None,
        None,
    );
    assert_eq!(
        names(&h),
        vec![
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Connection",
            "Upgrade-Insecure-Requests",
            "Priority"
        ]
    );

    // Loopback is a secure context.
    let h = build_for(
        &p,
        Protocol::Http1,
        Method::GET,
        "http://127.0.0.1:8080/",
        &[],
        None,
        None,
    );
    assert!(value(&h, "sec-fetch-mode").is_some());
}

#[test]
fn test_h2_drops_connection_specific_headers() {
    let p = Chrome::latest();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("Connection", "close"), ("Host", "evil"), ("TE", "gzip")],
        None,
        None,
    );
    for name in ["connection", "host", "te"] {
        assert!(value(&h, name).is_none(), "{name}");
    }
}

// A request with an unsafe method comes from a page, never the address bar: fetch() unless it's a
// form POST, always with an Origin.

#[test]
fn test_chrome_post_without_content_type_is_a_same_origin_fetch() {
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::POST,
        "https://example.com/api",
        &[],
        Some("a=1"),
        Some(2),
    );
    assert_eq!(
        names(&h),
        vec![
            "content-length",
            "sec-ch-ua-platform",
            "user-agent",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "accept",
            "origin",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority"
        ]
    );
    assert_eq!(value(&h, "origin"), Some("https://example.com"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    assert_eq!(value(&h, "sec-fetch-mode"), Some("cors"));
    assert_eq!(value(&h, "accept"), Some("*/*"));
}

#[test]
fn test_firefox_post_without_content_type_is_a_same_origin_fetch() {
    let h = build_for(
        &Firefox::latest(),
        Protocol::Http2,
        Method::POST,
        "https://example.com/api",
        &[],
        Some("a=1"),
        Some(2),
    );
    assert_eq!(
        names(&h),
        vec![
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "content-length",
            "origin",
            "cookie",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "priority",
            "te"
        ]
    );
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    assert_eq!(value(&h, "priority"), Some("u=4"));
}

#[test]
fn test_form_post_without_origin_gets_its_own() {
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::POST,
        "https://example.com/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        None,
        Some(3),
    );
    let n = names(&h);
    let pos = |k| n.iter().position(|x| *x == k).unwrap();
    assert!(pos("user-agent") < pos("origin") && pos("origin") < pos("accept"));
    assert_eq!(value(&h, "origin"), Some("https://example.com"));
    assert_eq!(value(&h, "sec-fetch-mode"), Some("navigate"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    assert_eq!(value(&h, "sec-fetch-user"), Some("?1"));
}

#[test]
fn test_own_origin_serialization() {
    for (url, origin) in [
        ("http://127.0.0.1:8080/x", "http://127.0.0.1:8080"),
        ("https://example.com:443/x", "https://example.com"),
        ("https://example.com:8443/x", "https://example.com:8443"),
        ("http://[::1]:3000/", "http://[::1]:3000"),
    ] {
        let h = build_for(
            &Firefox::latest(),
            Protocol::Http1,
            Method::DELETE,
            url,
            &[],
            None,
            None,
        );
        assert_eq!(value(&h, "origin"), Some(origin), "{url}");
    }
    // GET and HEAD have none; a caller Origin is kept as is.
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[],
        None,
        None,
    );
    assert_eq!(value(&h, "origin"), None);
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::PUT,
        "https://api.example.com/",
        &[("Origin", "https://www.example.com")],
        None,
        None,
    );
    assert_eq!(value(&h, "origin"), Some("https://www.example.com"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-site"));
}

#[test]
fn test_delete_is_a_fetch() {
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::DELETE,
        "https://example.com/item/1",
        &[],
        None,
        None,
    );
    assert_eq!(value(&h, "sec-fetch-mode"), Some("cors"));
    assert_eq!(value(&h, "sec-fetch-dest"), Some("empty"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    assert!(value(&h, "sec-fetch-user").is_none());
    assert_eq!(value(&h, "origin"), Some("https://example.com"));
}

#[test]
fn test_get_with_non_html_accept_is_a_fetch() {
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::GET,
        "https://example.com/api",
        &[("Accept", "application/json")],
        None,
        None,
    );
    // fetch()'s own Accept is in Blink's header map: it takes the bucket sec-ch-ua would take,
    // moving it one on.
    assert_eq!(
        names(&h),
        vec![
            "sec-ch-ua-platform",
            "user-agent",
            "accept",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority"
        ]
    );
    assert_eq!(value(&h, "accept"), Some("application/json"));
    assert_eq!(value(&h, "sec-fetch-mode"), Some("cors"));
    assert_eq!(value(&h, "sec-fetch-dest"), Some("empty"));
    assert_eq!(value(&h, "sec-fetch-site"), Some("same-origin"));
    assert_eq!(value(&h, "priority"), Some("u=1, i"));

    let h = build_for(
        &Firefox::latest(),
        Protocol::Http2,
        Method::HEAD,
        "https://example.com/api",
        &[("Accept", "*/*")],
        None,
        None,
    );
    assert_eq!(value(&h, "sec-fetch-mode"), Some("cors"));
    assert!(value(&h, "upgrade-insecure-requests").is_none());

    // An Accept that lists HTML is still a navigation.
    let h = build_for(
        &Chrome::latest(),
        Protocol::Http2,
        Method::GET,
        "https://example.com/",
        &[("Accept", "text/html,*/*;q=0.8")],
        None,
        None,
    );
    assert_eq!(value(&h, "sec-fetch-mode"), Some("navigate"));
    assert_eq!(value(&h, "accept"), Some("text/html,*/*;q=0.8"));
}

// OkHttp: the application's headers, then Content-Type, Content-Length, Host, Connection,
// Accept-Encoding, Cookie, User-Agent.

#[test]
fn test_okhttp_http1_layout() {
    let p = crate::profile::OkHttp::latest();
    let h = build_for(
        &p,
        Protocol::Http1,
        Method::POST,
        "https://api.example.com/v1",
        &[("X-Api-Key", "k"), ("Content-Type", "application/json")],
        Some("a=1"),
        Some(2),
    );
    assert_eq!(
        h,
        [
            ("X-Api-Key", "k"),
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
            ("Host", "api.example.com"),
            ("Connection", "Keep-Alive"),
            ("Accept-Encoding", "gzip"),
            ("Cookie", "a=1"),
            ("User-Agent", "okhttp/5.5.0"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[test]
fn test_okhttp_application_headers_stay_in_place() {
    let p = crate::profile::OkHttp::latest();
    let h = build_for(
        &p,
        Protocol::Http1,
        Method::GET,
        "https://api.example.com/v1",
        &[
            ("X-A", "1"),
            ("User-Agent", "MyApp/2.0"),
            ("Range", "bytes=0-99"),
        ],
        None,
        None,
    );
    assert_eq!(
        names(&h),
        vec!["X-A", "User-Agent", "Range", "Host", "Connection"]
    );
    assert_eq!(value(&h, "user-agent"), Some("MyApp/2.0"));
}

#[test]
fn test_okhttp_http2_layout() {
    let p = crate::profile::OkHttp::version(4).unwrap();
    let h = build_for(
        &p,
        Protocol::Http2,
        Method::PUT,
        "https://api.example.com/v1",
        &[("Content-Type", "text/plain")],
        Some("a=1"),
        None,
    );
    assert_eq!(
        h,
        [
            ("content-type", "text/plain"),
            ("content-length", "0"),
            ("accept-encoding", "gzip"),
            ("cookie", "a=1"),
            ("user-agent", "okhttp/4.12.0"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[test]
fn test_okhttp_plain_http_through_proxy() {
    let p = crate::profile::OkHttp::latest();
    let uri: Uri = "http://example.test/x".parse().unwrap();
    let proxy = [("Proxy-Authorization".to_string(), "Basic x".to_string())];
    let h = build(&HeaderInput {
        profile: &p,
        protocol: Protocol::Http1,
        method: &Method::GET,
        uri: &uri,
        body_len: None,
        client_headers: &[],
        request_headers: &[],
        cookie: None,
        proxy_headers: Some(&proxy),
        alt_used: None,
        client_hints: None,
        accept_ch_frame: None,
        restarted: false,
    });
    assert_eq!(
        names(&h),
        vec![
            "Proxy-Authorization",
            "Host",
            "Connection",
            "Accept-Encoding",
            "User-Agent"
        ]
    );
    assert_eq!(value(&h, "accept-encoding"), Some("gzip"));
}

#[test]
fn test_okhttp_websocket_handshake() {
    let p = crate::profile::OkHttp::latest();
    let ws: Uri = "ws://example.com/ws".parse().unwrap();
    let http: Uri = "http://example.com/ws".parse().unwrap();
    let caller = [("X-Token".to_string(), "t".to_string())];
    let h = build_websocket(&p, &ws, &http, "KEY", Some("a=1"), &[], &caller);
    assert_eq!(
        names(&h),
        vec![
            "X-Token",
            "Upgrade",
            "Connection",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Host",
            "Accept-Encoding",
            "Cookie",
            "User-Agent"
        ]
    );
    // Not a browser: no Origin, and no secure-context rule.
    assert_eq!(value(&h, "accept-encoding"), Some("gzip"));
}

#[test]
fn test_websocket_insecure_context_and_cookie_merge() {
    let ws: Uri = "ws://example.com/ws".parse().unwrap();
    let http: Uri = "http://example.com/ws".parse().unwrap();
    let client = [("Cookie".to_string(), "a=1; b=2".to_string())];
    let request = [("Cookie".to_string(), "b=3".to_string())];
    let h = build_websocket(
        &Chrome::latest(),
        &ws,
        &http,
        "KEY",
        Some("c=4; a=9"),
        &client,
        &request,
    );
    assert_eq!(value(&h, "accept-encoding"), Some("gzip, deflate"));
    // Pairwise like `build`: request cookies win, then the jar's others.
    assert_eq!(value(&h, "cookie"), Some("a=1; b=3; c=4"));
    assert_eq!(value(&h, "origin"), Some("http://example.com"));
}
