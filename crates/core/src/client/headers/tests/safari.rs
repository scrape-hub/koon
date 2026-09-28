//! Safari's request headers against the captures of real Safari (see `profile::safari`).

use http::{Method, Uri};

use super::support::{Request, names};
use crate::client::headers::{
    HeaderInput, Protocol, build, build_websocket, build_websocket_h2, header_value,
};
use crate::profile::{BrowserProfile, Os, Safari};

const PAGE: &str = "https://koon-capture.test/start?auto=1";

fn safari(version: &str, os: Os) -> BrowserProfile {
    Safari::version(version, os).unwrap()
}

fn request(
    profile: &BrowserProfile,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    cookie: Option<&str>,
    body_len: Option<usize>,
) -> Vec<(String, String)> {
    request_on(
        Protocol::Http2,
        profile,
        method,
        path,
        headers,
        cookie,
        body_len,
    )
}

fn request_on(
    protocol: Protocol,
    profile: &BrowserProfile,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    cookie: Option<&str>,
    body_len: Option<usize>,
) -> Vec<(String, String)> {
    let url = format!("https://koon-capture.test{path}");
    Request {
        protocol,
        headers,
        cookie,
        body_len,
        ..Request::new(profile, method, &url)
    }
    .build()
}

const FETCH: &[(&str, &str)] = &[
    ("Accept", "*/*"),
    ("Referer", PAGE),
    ("sec-fetch-mode", "cors"),
    ("sec-fetch-dest", "empty"),
];

const JSON_POST: &[(&str, &str)] = &[
    ("Accept", "*/*"),
    ("Content-Type", "application/json"),
    ("Referer", PAGE),
];

/// Safari on macOS 14 and iOS 17 over HTTP/3: `priority` as from macOS 15 on, headers in a
/// different hash order than over HTTP/2 (unchanged there).
#[test]
fn macos_14_http3_matches_the_capture() {
    for os in [Os::MacOS, Os::Ios] {
        let p = safari("17.0", os);
        let h3 = |method: Method,
                  path: &str,
                  headers: &[(&str, &str)],
                  cookie: Option<&str>,
                  body_len: Option<usize>| {
            request_on(Protocol::Http3, &p, method, path, headers, cookie, body_len)
        };
        let typed = h3(Method::GET, "/start?auto=1", &[], None, None);
        assert_eq!(
            names(&typed),
            [
                "accept",
                "sec-fetch-site",
                "priority",
                "sec-fetch-mode",
                "user-agent",
                "accept-language",
                "sec-fetch-dest",
                "accept-encoding"
            ],
            "{os}"
        );
        assert_eq!(header_value(&typed, "priority"), Some("u=0, i"));
        let again = h3(
            Method::GET,
            "/start?again=1",
            &[],
            Some("kc=1; kc2=2"),
            None,
        );
        assert_eq!(
            names(&again),
            [
                "accept",
                "sec-fetch-site",
                "cookie",
                "priority",
                "sec-fetch-mode",
                "user-agent",
                "accept-language",
                "sec-fetch-dest",
                "accept-encoding"
            ],
            "{os}"
        );

        let get = [
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
        ];
        let fetch = h3(Method::GET, "/api/data?x=1", FETCH, Some("kc=1"), None);
        assert_eq!(names(&fetch), get, "{os}");
        assert_eq!(header_value(&fetch, "priority"), Some("u=3, i"));
        let link = h3(
            Method::GET,
            "/page2",
            &[("Referer", PAGE)],
            Some("kc=1"),
            None,
        );
        assert_eq!(names(&link), get, "{os}");
        assert_eq!(header_value(&link, "priority"), Some("u=0, i"));
        let image = h3(
            Method::GET,
            "/static/i.png",
            &[
                ("Accept", "image/webp,*/*;q=0.5"),
                ("Referer", PAGE),
                ("sec-fetch-mode", "no-cors"),
                ("sec-fetch-dest", "image"),
            ],
            Some("kc=1"),
            None,
        );
        assert_eq!(names(&image), get, "{os}");
        assert_eq!(header_value(&image, "priority"), Some("u=5, i"));

        let post = h3(Method::POST, "/api/post", JSON_POST, Some("kc=1"), Some(9));
        assert_eq!(
            names(&post),
            [
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
                "cookie"
            ],
            "{os}"
        );
        assert_eq!(header_value(&post, "priority"), Some("u=3, i"));

        // HTTP/2 keeps its layout, without priority.
        let typed = request(&p, Method::GET, "/start?auto=1", &[], None, None);
        assert_eq!(header_value(&typed, "priority"), None);
        assert_eq!(names(&typed)[2], "accept-encoding");
    }
}

/// Safari 27 on macOS 27 (same on 26.6.2, and on 15.7.9 without zstd).
#[test]
fn macos_27_matches_the_capture() {
    let p = safari("27.0", Os::MacOS);
    let typed = request(&p, Method::GET, "/start?auto=1", &[], None, None);
    assert_eq!(
        names(&typed),
        [
            "sec-fetch-dest",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "accept-language",
            "priority",
            "accept-encoding"
        ]
    );
    assert_eq!(
        header_value(&typed, "accept-encoding"),
        Some("gzip, deflate, br, zstd")
    );

    let get = [
        "sec-fetch-dest",
        "user-agent",
        "accept",
        "referer",
        "sec-fetch-site",
        "sec-fetch-mode",
        "accept-language",
        "priority",
        "accept-encoding",
        "cookie",
    ];
    let link = request(
        &p,
        Method::GET,
        "/page2",
        &[("Referer", PAGE)],
        Some("kc=1; kc2=2"),
        None,
    );
    assert_eq!(names(&link), get);
    assert_eq!(header_value(&link, "sec-fetch-site"), Some("same-origin"));
    assert_eq!(header_value(&link, "priority"), Some("u=0, i"));

    let fetch = request(&p, Method::GET, "/api/data?x=1", FETCH, Some("kc=1"), None);
    assert_eq!(names(&fetch), get);
    assert_eq!(header_value(&fetch, "priority"), Some("u=3, i"));
    assert_eq!(header_value(&fetch, "sec-fetch-dest"), Some("empty"));

    for (dest, accept, priority) in [
        ("style", "text/css,*/*;q=0.1", "u=1, i"),
        ("script", "*/*", "u=1, i"),
        ("image", "image/webp,*/*;q=0.5", "u=5, i"),
    ] {
        let sub = request(
            &p,
            Method::GET,
            "/static/x",
            &[
                ("Accept", accept),
                ("Referer", PAGE),
                ("sec-fetch-mode", "no-cors"),
                ("sec-fetch-dest", dest),
            ],
            Some("kc=1"),
            None,
        );
        assert_eq!(names(&sub), get, "{dest}");
        assert_eq!(header_value(&sub, "priority"), Some(priority), "{dest}");
    }

    let body = [
        "accept",
        "content-type",
        "origin",
        "sec-fetch-site",
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
    let post = request(
        &p,
        Method::POST,
        "/api/post",
        JSON_POST,
        Some("kc=1"),
        Some(7),
    );
    assert_eq!(names(&post), body);
    assert_eq!(
        header_value(&post, "origin"),
        Some("https://koon-capture.test")
    );
    assert_eq!(header_value(&post, "priority"), Some("u=3, i"));
    let form = request(
        &p,
        Method::POST,
        "/submit",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Referer", PAGE),
        ],
        Some("kc=1"),
        Some(20),
    );
    assert_eq!(names(&form), body);
    assert_eq!(header_value(&form, "sec-fetch-mode"), Some("navigate"));
    assert_eq!(header_value(&form, "priority"), Some("u=0, i"));
}

/// iOS 18.1+ puts `sec-fetch-site` before `origin` in a request with a body.
#[test]
fn ios_body_order() {
    for version in ["18.3", "26.5", "27.0"] {
        let p = safari(version, Os::Ios);
        let post = request(
            &p,
            Method::POST,
            "/api/post",
            JSON_POST,
            Some("kc=1"),
            Some(7),
        );
        assert_eq!(
            names(&post)[..5],
            [
                "accept",
                "content-type",
                "sec-fetch-site",
                "origin",
                "sec-fetch-mode"
            ],
            "{version}"
        );
    }
}

/// Safari before fetch metadata (macOS 12/13, iOS 16.0/16.1, `fetch_metadata: false`): a
/// different hash order than macOS 14/iOS 17 (which already sends fetch metadata), no
/// `sec-fetch-*` and no `priority` at all, and — the bug this fixes — the `Accept: */*` and
/// Origin adjustments for a non-navigation request still apply even though nothing gates them on
/// `sec-fetch-mode` being present. Captured from macOS 12.5, 12.6 (Safari 15.6.1) and 13.0/13.6,
/// and the iOS 16.0/16.1 simulators.
#[test]
fn macos_legacy_matches_the_capture() {
    for os in [Os::MacOS, Os::Ios] {
        let p = safari("16.1", os);
        assert!(
            !p.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-mode")),
            "{os}: profile template should carry no fetch metadata"
        );

        let typed = request(&p, Method::GET, "/start?auto=1", &[], None, None);
        assert_eq!(
            names(&typed),
            ["user-agent", "accept", "accept-language", "accept-encoding"],
            "{os}"
        );

        let again = request(&p, Method::GET, "/start?again=1", &[], Some("kc=1"), None);
        assert_eq!(
            names(&again),
            [
                "cookie",
                "accept",
                "user-agent",
                "accept-language",
                "accept-encoding"
            ],
            "{os}"
        );

        // A link click / fetch() / subresource GET with a Referer: one order regardless of kind.
        let link = request(
            &p,
            Method::GET,
            "/page2",
            &[("Referer", PAGE)],
            Some("kc=1"),
            None,
        );
        assert_eq!(
            names(&link),
            [
                "cookie",
                "accept",
                "accept-encoding",
                "user-agent",
                "accept-language",
                "referer"
            ],
            "{os}"
        );
        assert!(header_value(&link, "sec-fetch-site").is_none(), "{os}");
        assert!(header_value(&link, "priority").is_none(), "{os}");

        // A POST with no caller-supplied Accept/sec-fetch-mode: koon must still detect Cors mode
        // from the method/content-type alone and default Accept to `*/*`, exactly as it does for
        // profiles that do send fetch metadata — this is the fix (the adjustment used to be gated
        // on `sec-fetch-mode` already being in the template).
        let post = request(
            &p,
            Method::POST,
            "/api/post",
            &[("Content-Type", "application/json"), ("Referer", PAGE)],
            Some("kc=1"),
            Some(7),
        );
        assert_eq!(
            names(&post),
            [
                "accept",
                "content-type",
                "origin",
                "cookie",
                "content-length",
                "accept-language",
                "user-agent",
                "referer",
                "accept-encoding"
            ],
            "{os}"
        );
        assert_eq!(header_value(&post, "accept"), Some("*/*"), "{os}");
        assert_eq!(
            header_value(&post, "origin"),
            Some("https://koon-capture.test"),
            "{os}"
        );
        assert!(header_value(&post, "sec-fetch-mode").is_none(), "{os}");
        assert!(header_value(&post, "priority").is_none(), "{os}");

        // Same over HTTP/3 (macOS 13/16.1 has QUIC support without fetch metadata): the header set
        // never gains a `priority` field here, so the order is unchanged by transport.
        if os == Os::MacOS {
            let h3_link = request_on(
                Protocol::Http3,
                &p,
                Method::GET,
                "/page2",
                &[("Referer", PAGE)],
                Some("kc=1"),
                None,
            );
            assert_eq!(names(&h3_link), names(&link));
        }
    }
}

/// macOS 14/iOS 17: a hash order that changes with the set of headers, no `priority`.
#[test]
fn macos_14_matches_the_capture() {
    for os in [Os::MacOS, Os::Ios] {
        let p = safari("17.0", os);
        let typed = request(&p, Method::GET, "/start?auto=1", &[], None, None);
        assert_eq!(
            names(&typed),
            [
                "accept",
                "sec-fetch-site",
                "accept-encoding",
                "sec-fetch-mode",
                "user-agent",
                "accept-language",
                "sec-fetch-dest"
            ]
        );
        let again = request(&p, Method::GET, "/start?again=1", &[], Some("kc=1"), None);
        assert_eq!(
            names(&again),
            [
                "accept",
                "sec-fetch-site",
                "cookie",
                "accept-encoding",
                "sec-fetch-mode",
                "user-agent",
                "accept-language",
                "sec-fetch-dest"
            ]
        );
        let fetch = request(&p, Method::GET, "/api/data?x=1", FETCH, Some("kc=1"), None);
        assert_eq!(
            names(&fetch),
            [
                "accept",
                "sec-fetch-site",
                "cookie",
                "sec-fetch-dest",
                "accept-language",
                "sec-fetch-mode",
                "user-agent",
                "referer",
                "accept-encoding"
            ]
        );
        let post = request(
            &p,
            Method::POST,
            "/api/post",
            JSON_POST,
            Some("kc=1"),
            Some(7),
        );
        assert_eq!(
            names(&post),
            [
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
                "cookie"
            ]
        );
        assert_eq!(header_value(&post, "priority"), None);
    }
}

fn websocket(profile: &BrowserProfile, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let extra: Vec<(String, String)> = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    build_websocket(
        profile,
        &"wss://ws.koon.test/ws".parse().unwrap(),
        &"https://ws.koon.test/ws".parse().unwrap(),
        "dGhlIHNhbXBsZSBub25jZQ==",
        Some("koon=1"),
        &[],
        &extra,
    )
}

/// Safari before fetch metadata (macOS 12/13, iOS 16.0/16.1): no `Sec-Fetch-*` in the WebSocket
/// handshake either, and its own hash order — captured from real Safari 16.0 on macOS 12.6 and the
/// iOS 16.0 simulator.
#[test]
fn websocket_upgrades_before_fetch_metadata_match_the_captures() {
    for os in [Os::MacOS, Os::Ios] {
        let p = safari("16.1", os);
        let plain = websocket(&p, &[]);
        assert_eq!(
            names(&plain),
            [
                "Host",
                "Pragma",
                "Accept",
                "Sec-WebSocket-Key",
                "Sec-WebSocket-Version",
                "Accept-Language",
                "Cache-Control",
                "Accept-Encoding",
                "Origin",
                "User-Agent",
                "Connection",
                "Upgrade",
                "Cookie"
            ],
            "{os}"
        );
        assert_eq!(
            header_value(&plain, "accept-encoding"),
            Some("gzip, deflate")
        );
        assert!(header_value(&plain, "sec-fetch-site").is_none(), "{os}");

        let with_protocol = websocket(&p, &[("Sec-WebSocket-Protocol", "chat, superchat")]);
        assert_eq!(
            names(&with_protocol),
            [
                "Host",
                "Pragma",
                "Accept",
                "Sec-WebSocket-Key",
                "Sec-WebSocket-Version",
                "Sec-WebSocket-Protocol",
                "Cache-Control",
                "Accept-Language",
                "Origin",
                "User-Agent",
                "Connection",
                "Accept-Encoding",
                "Upgrade",
                "Cookie"
            ],
            "{os}"
        );
    }
}

/// Safari's WebSocket upgrades, less Sec-WebSocket-Extensions.
#[test]
fn websocket_upgrades_match_the_captures() {
    let sonoma = websocket(&safari("17.0", Os::MacOS), &[]);
    assert_eq!(
        names(&sonoma),
        [
            "Host",
            "Pragma",
            "Accept",
            "Sec-WebSocket-Key",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Cache-Control",
            "Sec-Fetch-Mode",
            "Accept-Language",
            "Origin",
            "User-Agent",
            "Connection",
            "Accept-Encoding",
            "Upgrade",
            "Sec-Fetch-Dest",
            "Cookie"
        ]
    );
    assert_eq!(
        header_value(&sonoma, "accept-encoding"),
        Some("gzip, deflate")
    );
    assert_eq!(header_value(&sonoma, "sec-fetch-dest"), Some("websocket"));

    let sequoia = websocket(
        &safari("18.3", Os::MacOS),
        &[("Sec-WebSocket-Protocol", "chat, superchat")],
    );
    assert_eq!(
        names(&sequoia),
        [
            "Host",
            "Upgrade",
            "Pragma",
            "Sec-WebSocket-Key",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-Fetch-Mode",
            "Cache-Control",
            "Origin",
            "User-Agent",
            "Connection",
            "Sec-Fetch-Dest",
            "Accept",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie"
        ]
    );
    assert_eq!(header_value(&sequoia, "priority"), Some("u=3, i"));
    assert_eq!(
        header_value(&sequoia, "accept-encoding"),
        Some("gzip, deflate, br")
    );

    let tahoe = safari("27.0", Os::MacOS);
    assert_eq!(
        names(&websocket(&tahoe, &[])),
        [
            "Host",
            "Origin",
            "Pragma",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Sec-Fetch-Mode",
            "User-Agent",
            "Cache-Control",
            "Sec-Fetch-Dest",
            "Accept",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
            "Sec-WebSocket-Key",
            "Connection",
            "Upgrade"
        ]
    );
    let h2 = build_websocket_h2(
        &tahoe,
        &"wss://ws.koon.test/ws".parse().unwrap(),
        &"https://ws.koon.test/ws".parse().unwrap(),
        Some("koon=1"),
        &[],
        &[(
            "Sec-WebSocket-Protocol".to_string(),
            "chat, superchat".to_string(),
        )],
    );
    assert_eq!(
        names(&h2),
        [
            "origin",
            "pragma",
            "sec-fetch-site",
            "sec-websocket-protocol",
            "sec-websocket-version",
            "sec-fetch-mode",
            "user-agent",
            "cache-control",
            "sec-fetch-dest",
            "accept",
            "accept-language",
            "priority",
            "accept-encoding",
            "cookie"
        ]
    );
    assert_eq!(
        header_value(&h2, "accept-encoding"),
        Some("gzip, deflate, br, zstd")
    );
}

fn plain(
    profile: &BrowserProfile,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body_len: Option<usize>,
) -> Vec<(String, String)> {
    let uri: Uri = format!("http://plain.koon.test{path}").parse().unwrap();
    let request: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    build(&HeaderInput {
        profile,
        protocol: Protocol::Http1,
        method: &method,
        uri: &uri,
        body_len,
        client_headers: &[],
        request_headers: &request,
        cookie: Some("pc=1"),
        proxy_headers: None,
        alt_used: None,
        client_hints: None,
        accept_ch_frame: None,
        restarted: false,
    })
}

/// Safari over plain http/1.1: no fetch metadata, Upgrade-Insecure-Requests on navigations and
/// forms, Priority kept, Host first, Connection last.
#[test]
fn plain_http_matches_the_capture() {
    let p = safari("27.0", Os::MacOS);
    let page = "http://plain.koon.test/start?auto=1";
    let typed = plain(&p, Method::GET, "/start?typed=1", &[], None);
    assert_eq!(
        names(&typed),
        [
            "Host",
            "User-Agent",
            "Upgrade-Insecure-Requests",
            "Accept",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
            "Connection"
        ]
    );
    assert_eq!(
        header_value(&typed, "accept-encoding"),
        Some("gzip, deflate")
    );
    assert_eq!(header_value(&typed, "connection"), Some("keep-alive"));
    let link = plain(&p, Method::GET, "/page2", &[("Referer", page)], None);
    assert_eq!(
        names(&link)[1..5],
        [
            "User-Agent",
            "Accept",
            "Upgrade-Insecure-Requests",
            "Referer"
        ]
    );
    let fetch = plain(
        &p,
        Method::GET,
        "/api/data?x=1",
        &[("Accept", "*/*"), ("Referer", page)],
        None,
    );
    assert_eq!(
        names(&fetch),
        [
            "Host",
            "Referer",
            "Accept",
            "User-Agent",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
            "Connection"
        ]
    );
    assert_eq!(header_value(&fetch, "priority"), Some("u=3, i"));
    let post = plain(
        &p,
        Method::POST,
        "/api/post",
        &[
            ("Accept", "*/*"),
            ("Content-Type", "application/json"),
            ("Referer", page),
        ],
        Some(7),
    );
    assert_eq!(
        names(&post),
        [
            "Host",
            "User-Agent",
            "Accept",
            "Content-Type",
            "Referer",
            "Origin",
            "Content-Length",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
            "Connection"
        ]
    );
    let form = plain(
        &p,
        Method::POST,
        "/submit",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Referer", page),
        ],
        Some(20),
    );
    assert_eq!(
        names(&form),
        [
            "Host",
            "Accept",
            "Origin",
            "Content-Type",
            "Upgrade-Insecure-Requests",
            "User-Agent",
            "Referer",
            "Content-Length",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
            "Connection"
        ]
    );
}

/// A cross-origin fetch() GET with its Origin, a cross-origin PUT (the caller's header after
/// Origin) and its preflight.
#[test]
fn cross_origin_requests_match_the_capture() {
    let p = safari("27.0", Os::MacOS);
    let other = "https://koon-capture.test/";
    let get = request(
        &p,
        Method::GET,
        "/api/cors?x=1",
        &[
            ("Accept", "*/*"),
            ("Origin", "https://site.example"),
            ("Referer", other),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "empty"),
            ("sec-fetch-site", "cross-site"),
        ],
        None,
        None,
    );
    assert_eq!(
        names(&get),
        [
            "sec-fetch-site",
            "accept",
            "origin",
            "sec-fetch-mode",
            "user-agent",
            "referer",
            "sec-fetch-dest",
            "accept-language",
            "priority",
            "accept-encoding"
        ]
    );
    let put = request(
        &p,
        Method::PUT,
        "/api/cors-pre?x=1",
        &[
            ("Accept", "*/*"),
            ("Content-Type", "application/json"),
            ("Origin", "https://site.example"),
            ("X-Test", "1"),
            ("Referer", other),
            ("sec-fetch-site", "cross-site"),
        ],
        None,
        Some(2),
    );
    assert_eq!(
        names(&put),
        [
            "accept",
            "content-type",
            "sec-fetch-site",
            "origin",
            "x-test",
            "sec-fetch-mode",
            "user-agent",
            "referer",
            "sec-fetch-dest",
            "content-length",
            "accept-language",
            "priority",
            "accept-encoding"
        ]
    );
    let preflight = request(
        &p,
        Method::OPTIONS,
        "/api/cors-pre?x=1",
        &[
            ("Accept", "*/*"),
            ("Origin", "https://site.example"),
            ("Access-Control-Request-Method", "PUT"),
            ("Access-Control-Request-Headers", "content-type,x-test"),
            ("Referer", other),
            ("sec-fetch-site", "cross-site"),
        ],
        None,
        None,
    );
    assert_eq!(
        names(&preflight),
        [
            "origin",
            "sec-fetch-site",
            "access-control-request-method",
            "access-control-request-headers",
            "sec-fetch-mode",
            "user-agent",
            "referer",
            "sec-fetch-dest",
            "content-length",
            "accept",
            "accept-language",
            "priority",
            "accept-encoding"
        ]
    );
    assert_eq!(header_value(&preflight, "content-length"), Some("0"));
}
