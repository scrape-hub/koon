//! Subresource priorities and the cookie slot over HTTP/2 (Chrome 153, Firefox 156,
//! www.cloudflare.com).

use http::{Method, Uri};

use super::support::{Request, names};
use crate::client::headers::{HeaderInput, Protocol, build, header_value};
use crate::profile::{BrowserProfile, Chrome, Firefox};

fn subresource(
    profile: &BrowserProfile,
    protocol: Protocol,
    mode: &str,
    dest: &str,
    accept: &str,
) -> Vec<(String, String)> {
    let uri: Uri = "https://www.cloudflare.com/asset".parse().unwrap();
    let request: Vec<(String, String)> = [
        ("sec-fetch-mode", mode),
        ("sec-fetch-dest", dest),
        ("Accept", accept),
        ("Referer", "https://www.cloudflare.com/"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    build(&HeaderInput {
        profile,
        protocol,
        method: &Method::GET,
        uri: &uri,
        body_len: None,
        client_headers: &[],
        request_headers: &request,
        cookie: Some("a=1"),
        proxy_headers: None,
        alt_used: None,
        client_hints: None,
        accept_ch_frame: None,
        restarted: false,
    })
}

#[test]
fn chrome_priority_follows_the_destination() {
    let p = Chrome::latest();
    let priority = |mode, dest| {
        header_value(
            &subresource(&p, Protocol::Http2, mode, dest, "*/*"),
            "priority",
        )
        .map(str::to_string)
    };
    assert_eq!(priority("no-cors", "style").as_deref(), Some("u=0"));
    assert_eq!(priority("cors", "font").as_deref(), Some("u=0"));
    assert_eq!(priority("cors", "script").as_deref(), Some("u=1"));
    assert_eq!(priority("no-cors", "image").as_deref(), Some("i"));
    assert_eq!(priority("cors", "empty").as_deref(), Some("u=1, i"));

    // A stylesheet: the cookie before the priority.
    let h = subresource(
        &p,
        Protocol::Http2,
        "no-cors",
        "style",
        "text/css,*/*;q=0.1",
    );
    assert_eq!(
        names(&h),
        [
            "sec-ch-ua-platform",
            "user-agent",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority",
        ]
    );
    // HTTP/3 the same; HTTP/1.1 without priority, the cookie last.
    let h3 = subresource(
        &p,
        Protocol::Http3,
        "no-cors",
        "style",
        "text/css,*/*;q=0.1",
    );
    assert_eq!(names(&h3), names(&h));
    let h1 = subresource(
        &p,
        Protocol::Http1,
        "no-cors",
        "style",
        "text/css,*/*;q=0.1",
    );
    assert_eq!(names(&h1).last(), Some(&"Cookie"));
    assert_eq!(header_value(&h1, "priority"), None);
}

/// Module scripts and fonts load in CORS mode with an Origin Blink sets itself, first in the header
/// list; a same-origin GET fetch() has none.
#[test]
fn chrome_element_cors_loads_lead_with_origin() {
    let p = Chrome::latest();
    let h = subresource(&p, Protocol::Http2, "cors", "script", "*/*");
    assert_eq!(
        names(&h),
        [
            "origin",
            "sec-ch-ua-platform",
            "user-agent",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority",
        ]
    );
    assert_eq!(
        header_value(&h, "origin"),
        Some("https://www.cloudflare.com")
    );
    assert_eq!(header_value(&h, "sec-fetch-site"), Some("same-origin"));
    let font = subresource(&p, Protocol::Http2, "cors", "font", "*/*");
    assert_eq!(names(&font)[0], "origin");
    let fetch = subresource(&p, Protocol::Http2, "cors", "empty", "*/*");
    assert_eq!(header_value(&fetch, "origin"), None);
    // Firefox sends no Origin with same-origin script loads.
    let f = subresource(&Firefox::latest(), Protocol::Http2, "cors", "script", "*/*");
    assert_eq!(header_value(&f, "origin"), None);
}

/// fetch() with a body: Referer, the page's own headers, Content-Length, Origin, in that order.
#[test]
fn firefox_fetch_with_body_puts_referer_first() {
    let fetch = |method: &Method, own: &[(&str, &str)]| {
        let profile = Firefox::latest();
        let mut headers: Vec<(&str, &str)> = own.to_vec();
        headers.push(("Referer", "https://www.cloudflare.com/"));
        let h = Request {
            headers: &headers,
            body_len: Some(847),
            cookie: Some("a=1"),
            ..Request::new(&profile, method.clone(), "https://www.cloudflare.com/api")
        }
        .build();
        names(&h)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<String>>()
    };
    let tail = [
        "cookie",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "priority",
        "te",
    ];
    let head = ["user-agent", "accept", "accept-language", "accept-encoding"];
    let expected = |middle: &[&str]| -> Vec<String> {
        head.iter()
            .chain(middle)
            .chain(&tail)
            .map(|s| s.to_string())
            .collect()
    };
    assert_eq!(
        fetch(&Method::POST, &[("Content-Type", "application/json")]),
        expected(&["referer", "content-type", "content-length", "origin"])
    );
    assert_eq!(
        fetch(
            &Method::PUT,
            &[("x-test", "1"), ("content-type", "application/json")]
        ),
        expected(&[
            "referer",
            "x-test",
            "content-type",
            "content-length",
            "origin"
        ])
    );
}

#[test]
fn firefox_priority_follows_the_destination() {
    let f = Firefox::latest();
    let priority = |mode, dest| {
        header_value(
            &subresource(&f, Protocol::Http2, mode, dest, "*/*"),
            "priority",
        )
        .map(str::to_string)
    };
    assert_eq!(priority("no-cors", "style").as_deref(), Some("u=2"));
    assert_eq!(priority("no-cors", "image").as_deref(), Some("u=5, i"));
    assert_eq!(priority("no-cors", "script"), None);
    assert_eq!(priority("cors", "script"), None);
    assert_eq!(priority("cors", "font"), None);
    assert_eq!(priority("cors", "empty").as_deref(), Some("u=4"));

    // An image: the cookie at its slot, before the fetch metadata, on every protocol.
    let accept = "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5";
    let h = subresource(&f, Protocol::Http2, "no-cors", "image", accept);
    assert_eq!(
        names(&h),
        [
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "referer",
            "cookie",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "priority",
            "te",
        ]
    );
    let h3 = subresource(&f, Protocol::Http3, "no-cors", "image", accept);
    assert_eq!(names(&h3), [&names(&h)[..10], &[][..]].concat());
    // A script: no priority.
    let script = subresource(&f, Protocol::Http2, "no-cors", "script", "*/*");
    let expected = [
        "referer",
        "cookie",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "priority",
        "te",
    ];
    let without_priority: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|n| *n != "priority")
        .collect();
    assert_eq!(names(&script)[4..], without_priority);
    // A caller replaying a parser-blocking `<script src>` passes its `u=2`, which goes to Firefox's
    // slot for the header.
    let replayed = Request {
        headers: &[
            ("Priority", "u=2"),
            ("sec-fetch-mode", "no-cors"),
            ("sec-fetch-dest", "script"),
            ("Accept", "*/*"),
            ("Referer", "https://www.cloudflare.com/"),
        ],
        cookie: Some("a=1"),
        ..Request::new(&f, Method::GET, "https://www.cloudflare.com/s.js")
    }
    .build();
    assert_eq!(names(&replayed)[4..], expected);
    assert_eq!(header_value(&replayed, "priority"), Some("u=2"));
}
