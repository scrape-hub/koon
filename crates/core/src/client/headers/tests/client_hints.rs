//! Client hint layouts, captured from Chrome 153, Edge 153 and Opera 136 on Windows loading
//! www.google.com over HTTP/3. koon sends no x-browser-* headers, which the captures have after
//! `accept`.

use http::{Method, Uri};

use super::support::{Request, names};
use crate::client::client_hints::ClientHintsState;
use crate::client::headers::{Protocol, farble_accept_language, header_value};
use crate::profile::{Chrome, Os};

/// What www.google.com's ALPS asks for (captured ACCEPT_CH frame).
const GOOGLE_ALPS: &str = "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-Prefers-Color-Scheme";

/// What its Accept-CH asks for (the header lines of a response to koon, joined).
const GOOGLE_ACCEPT_CH: &str = "Sec-CH-Prefers-Color-Scheme, Downlink, RTT, Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64";

fn google(
    state: &ClientHintsState,
    method: Method,
    url: &str,
    request: &[(&str, &str)],
    body_len: Option<usize>,
    alps: Option<&str>,
) -> Vec<(String, String)> {
    let profile = Chrome::version(153, Os::Windows).unwrap();
    Request {
        protocol: Protocol::Http3,
        headers: request,
        body_len,
        client_hints: Some(state),
        accept_ch_frame: alps,
        ..Request::new(&profile, method, url)
    }
    .build()
}

/// Chrome 153's first navigation, restarted for the ALPS ACCEPT_CH frame.
#[test]
fn first_navigation_appends_the_alps_hints() {
    let state = ClientHintsState::default();
    let h = google(
        &state,
        Method::GET,
        "https://www.google.com/",
        &[],
        None,
        Some(GOOGLE_ALPS),
    );
    assert_eq!(
        names(&h),
        [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-ch-ua-arch",
            "sec-ch-ua-platform-version",
            "sec-ch-ua-model",
            "sec-ch-ua-bitness",
            "sec-ch-ua-wow64",
            "sec-ch-ua-full-version-list",
            "sec-ch-prefers-color-scheme",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
    let value = |name| header_value(&h, name).unwrap();
    assert_eq!(value("sec-ch-ua-arch"), "\"x86\"");
    assert_eq!(value("sec-ch-ua-platform-version"), "\"19.0.0\"");
    assert_eq!(value("sec-ch-ua-model"), "\"\"");
    assert_eq!(value("sec-ch-ua-bitness"), "\"64\"");
    assert_eq!(value("sec-ch-ua-wow64"), "?0");
    assert_eq!(
        value("sec-ch-ua-full-version-list"),
        "\"Google Chrome\";v=\"153.0.8010.55\", \"Not_A Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"153.0.8010.55\""
    );
    assert_eq!(value("sec-ch-prefers-color-scheme"), "light");
}

/// Edge 153: a navigation after Accept-CH, with the same ALPS frame.
#[test]
fn later_navigation_leads_with_the_persisted_hints() {
    let state = ClientHintsState::default();
    state.persist("https://www.google.com", GOOGLE_ACCEPT_CH);
    let h = google(
        &state,
        Method::GET,
        "https://www.google.com/",
        &[],
        None,
        Some(GOOGLE_ALPS),
    );
    assert_eq!(
        names(&h),
        [
            "rtt",
            "downlink",
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
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
    assert_eq!(
        header_value(&h, "sec-ch-ua-form-factors"),
        Some("\"Desktop\"")
    );
    assert_eq!(
        header_value(&h, "sec-ch-ua-full-version"),
        Some("\"153.0.8010.55\"")
    );
}

/// A first response carrying Accept-CH and Critical-CH: the restarted navigation sends its other
/// headers first and every hint after `accept`, in Chromium's hint order, device hints first.
#[test]
fn critical_ch_restart_puts_the_hints_after_accept() {
    const ACCEPT_CH: &str = "Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Full-Version, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, Device-Memory, Sec-CH-Device-Memory, DPR, Sec-CH-DPR, Viewport-Width, Sec-CH-Viewport-Width, Sec-CH-Prefers-Color-Scheme, ECT, RTT, Downlink";
    let state = ClientHintsState::default();
    state.persist("https://koon-capture.test", ACCEPT_CH);
    let profile = Chrome::version(154, Os::Windows).unwrap();
    let build_for = |restarted| {
        Request {
            cookie: Some("kc=1; kc2=2"),
            client_hints: Some(&state),
            restarted,
            ..Request::new(&profile, Method::GET, "https://koon-capture.test/start")
        }
        .build()
    };
    let hints = [
        "device-memory",
        "sec-ch-device-memory",
        "dpr",
        "sec-ch-dpr",
        "viewport-width",
        "sec-ch-viewport-width",
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
    ];
    let tail = [
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "cookie",
        "priority",
    ];
    let head = ["upgrade-insecure-requests", "user-agent", "accept"];
    let restarted: Vec<&str> = head.iter().chain(&hints).chain(&tail).copied().collect();
    assert_eq!(names(&build_for(true)), restarted);
    // Without a restart the persisted hints lead.
    let persisted: Vec<&str> = hints.iter().chain(&head).chain(&tail).copied().collect();
    assert_eq!(names(&build_for(false)), persisted);
}

/// Chrome 155 on Android after an Accept-CH for the User-Agent, device and network hints: a
/// navigation, a `fetch()` with a JSON body, and an image load (network values differ per request
/// in Chrome).
#[test]
fn chrome_155_android_matches_the_capture() {
    const ACCEPT_CH: &str = "Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Full-Version, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, Device-Memory, Sec-CH-Device-Memory, DPR, Sec-CH-DPR, Viewport-Width, Sec-CH-Viewport-Width, Sec-CH-Prefers-Color-Scheme, ECT, RTT, Downlink";
    let state = ClientHintsState::default();
    state.persist("https://koon-capture.test", ACCEPT_CH);
    let profile = Chrome::version(155, Os::Android).unwrap();
    let build_for = |method: Method, path: &str, request: &[(&str, &str)], body| {
        let url = format!("https://koon-capture.test{path}");
        Request {
            headers: request,
            body_len: body,
            cookie: Some("kc=1"),
            client_hints: Some(&state),
            ..Request::new(&profile, method, &url)
        }
        .build()
    };
    let page = ("Referer", "https://koon-capture.test/start");

    let nav = build_for(Method::GET, "/page2", &[page], None);
    assert_eq!(
        names(&nav)[..10],
        [
            "device-memory",
            "sec-ch-device-memory",
            "dpr",
            "sec-ch-dpr",
            "viewport-width",
            "sec-ch-viewport-width",
            "rtt",
            "downlink",
            "ect",
            "sec-ch-ua"
        ]
    );
    assert_eq!(header_value(&nav, "sec-ch-device-memory"), Some("8"));
    assert_eq!(header_value(&nav, "dpr"), Some("2.25"));
    assert_eq!(header_value(&nav, "viewport-width"), Some("980"));

    let blink = [
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-platform",
        "viewport-width",
        "device-memory",
        "sec-ch-ua",
        "sec-ch-dpr",
        "sec-ch-ua-model",
        "sec-ch-ua-mobile",
        "sec-ch-ua-form-factors",
        "sec-ch-ua-bitness",
        "sec-ch-ua-wow64",
        "sec-ch-ua-arch",
        "sec-ch-ua-full-version",
        "sec-ch-viewport-width",
        "downlink",
        "ect",
        "sec-ch-device-memory",
        "dpr",
        "sec-ch-prefers-color-scheme",
        "user-agent",
        "rtt",
        "sec-ch-ua-platform-version",
    ];
    let post = build_for(
        Method::POST,
        "/api/echo",
        &[("Content-Type", "application/json"), page],
        Some(7),
    );
    let mut expected = vec!["content-length"];
    expected.extend(&blink[..13]);
    expected.push("content-type");
    expected.extend(&blink[13..]);
    expected.extend([
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
    ]);
    assert_eq!(names(&post), expected);
    assert_eq!(header_value(&post, "viewport-width"), Some("448"));

    let image = build_for(
        Method::GET,
        "/static/i.png",
        &[
            ("Sec-Fetch-Mode", "no-cors"),
            ("Sec-Fetch-Dest", "image"),
            (
                "Accept",
                "image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            ),
            page,
        ],
        None,
    );
    let mut expected: Vec<&str> = blink.to_vec();
    expected.extend([
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "referer",
        "accept-encoding",
        "accept-language",
        "cookie",
        "priority",
    ]);
    assert_eq!(names(&image), expected);
}

/// Brave on Windows after an Accept-CH for every hint: it sends only the User-Agent ones, `sec-gpc`
/// after `accept`, and a farbled Accept-Language.
#[test]
fn brave_154_matches_the_capture() {
    const ACCEPT_CH: &str = "Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Full-Version, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, Device-Memory, Sec-CH-Device-Memory, DPR, Sec-CH-DPR, Viewport-Width, Sec-CH-Viewport-Width, Sec-CH-Prefers-Color-Scheme, ECT, RTT, Downlink";
    let state = ClientHintsState::default();
    state.persist("https://koon-capture.test", ACCEPT_CH);
    let profile = crate::profile::Brave::version(154, Os::Windows).unwrap();
    let build_for = |method: Method, url: &str, request: &[(&str, &str)], body| {
        Request {
            headers: request,
            body_len: body,
            cookie: Some("kc=1"),
            client_hints: Some(&state),
            ..Request::new(&profile, method, url)
        }
        .build()
    };
    let page = ("Referer", "https://koon-capture.test/page2");
    let tail = [
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "referer",
        "accept-encoding",
        "accept-language",
        "cookie",
        "priority",
    ];

    let nav = build_for(
        Method::GET,
        "https://koon-capture.test/start?again=1",
        &[],
        None,
    );
    assert_eq!(
        names(&nav),
        [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-arch",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "sec-ch-ua-model",
            "sec-ch-ua-bitness",
            "sec-ch-ua-wow64",
            "sec-ch-ua-full-version-list",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-gpc",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "cookie",
            "priority",
        ]
    );
    assert_eq!(header_value(&nav, "sec-ch-ua-model"), Some("\"\""));
    assert_eq!(
        header_value(&nav, "sec-ch-ua-full-version-list"),
        Some(
            "\"Chromium\";v=\"154.0.0.0\", \"Brave\";v=\"154.0.0.0\", \"Not A(Brand\";v=\"99.0.0.0\""
        )
    );
    let language = header_value(&nav, "accept-language").unwrap().to_string();
    let q = language.strip_prefix("en-US,en;q=0.").unwrap();
    assert!(["5", "6", "7", "8", "9"].contains(&q), "{language}");

    // A fetch: Blink's map with the User-Agent hints, then accept and sec-gpc.
    let fetch = build_for(
        Method::GET,
        "https://koon-capture.test/api/data?x=1",
        &[("sec-fetch-mode", "cors"), ("Accept", "*/*"), page],
        None,
    );
    let mut expected = vec![
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-platform",
        "sec-ch-ua",
        "sec-ch-ua-bitness",
        "sec-ch-ua-model",
        "sec-ch-ua-mobile",
        "sec-ch-ua-wow64",
        "sec-ch-ua-arch",
        "user-agent",
        "sec-ch-ua-platform-version",
        "accept",
        "sec-gpc",
    ];
    expected.extend(tail);
    assert_eq!(names(&fetch), expected);
    assert_eq!(
        header_value(&fetch, "accept-language"),
        Some(language.as_str())
    );

    let post = build_for(
        Method::POST,
        "https://koon-capture.test/api/post",
        &[("Content-Type", "application/json"), page],
        Some(7),
    );
    assert_eq!(
        names(&post)[..15],
        [
            "content-length",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-platform",
            "sec-ch-ua",
            "sec-ch-ua-bitness",
            "sec-ch-ua-model",
            "sec-ch-ua-mobile",
            "sec-ch-ua-wow64",
            "sec-ch-ua-arch",
            "user-agent",
            "content-type",
            "sec-ch-ua-platform-version",
            "accept",
            "sec-gpc",
            "origin",
        ]
    );

    // Another site, another client: a q value of 0.5 to 0.9 each.
    let values: std::collections::HashSet<String> = (0..40)
        .map(|_| {
            let state = ClientHintsState::default();
            let uri: Uri = "https://example.com/".parse().unwrap();
            let mut headers = vec![("accept-language".to_string(), "en-US,en".to_string())];
            farble_accept_language(&mut headers, &state, &uri);
            headers[0].1.clone()
        })
        .collect();
    assert!(values.len() > 1, "{values:?}");
    assert!(values.iter().all(|v| v.len() == "en-US,en;q=0.5".len()));
}

/// Samsung Internet sends no zstd and reports no network estimate: `rtt` 100/`downlink` 10 on
/// navigations, 0/10 on subresources; device hints are the Galaxy A33 5G's.
#[test]
fn samsung_30_matches_the_capture() {
    const ACCEPT_CH: &str = "ECT, RTT, Downlink, Sec-CH-UA-Full-Version, Sec-CH-UA-Model,             Sec-CH-UA-Platform-Version, Viewport-Width, Sec-CH-Viewport-Height, DPR, Device-Memory";
    let state = ClientHintsState::default();
    state.persist("https://koon-capture.test", ACCEPT_CH);
    let profile = crate::profile::Samsung::latest();
    let build_for = |url: &str, request: &[(&str, &str)]| {
        Request {
            headers: request,
            client_hints: Some(&state),
            ..Request::new(&profile, Method::GET, url)
        }
        .build()
    };
    let nav = build_for("https://koon-capture.test/page2", &[]);
    assert_eq!(
        header_value(&nav, "accept-encoding"),
        Some("gzip, deflate, br")
    );
    assert_eq!(header_value(&nav, "rtt"), Some("100"));
    assert_eq!(header_value(&nav, "downlink"), Some("10"));
    assert_eq!(header_value(&nav, "ect"), Some("4g"));
    assert_eq!(
        header_value(&nav, "sec-ch-ua-full-version"),
        Some("\"143.0.7499.194\"")
    );
    let fetch = build_for(
        "https://koon-capture.test/api/data",
        &[("sec-fetch-mode", "cors")],
    );
    assert_eq!(header_value(&fetch, "rtt"), Some("0"));
    assert_eq!(header_value(&fetch, "downlink"), Some("10"));
    assert_eq!(header_value(&nav, "sec-ch-ua-model"), Some("\"SM-A336B\""));
    assert_eq!(
        header_value(&fetch, "sec-ch-ua-platform-version"),
        Some("\"15.0.0\"")
    );
    for request in [&nav, &fetch] {
        assert_eq!(header_value(request, "dpr"), Some("2.8125"));
        assert_eq!(header_value(request, "device-memory"), Some("4"));
    }
    assert_eq!(header_value(&nav, "viewport-width"), Some("980"));
    assert_eq!(header_value(&nav, "sec-ch-viewport-height"), Some("1738"));
    assert_eq!(header_value(&fetch, "viewport-width"), Some("384"));
    assert_eq!(header_value(&fetch, "sec-ch-viewport-height"), Some("681"));
}

/// Edge 153: a fetch and a POST with a Content-Type, in Blink's hash order, with `downlink` moving
/// behind Content-Type.
#[test]
fn same_origin_fetch_carries_the_hints_in_blinks_order() {
    let state = ClientHintsState::default();
    state.persist("https://www.google.com", GOOGLE_ACCEPT_CH);
    let referer = ("Referer", "https://www.google.com/");
    let h = google(
        &state,
        Method::GET,
        "https://www.google.com/async/hpba",
        &[("sec-fetch-mode", "cors"), referer],
        None,
        None,
    );
    assert_eq!(
        names(&h),
        [
            "downlink",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-platform",
            "sec-ch-ua",
            "sec-ch-ua-bitness",
            "sec-ch-ua-model",
            "sec-ch-ua-mobile",
            "sec-ch-ua-form-factors",
            "sec-ch-ua-wow64",
            "sec-ch-ua-arch",
            "sec-ch-ua-full-version",
            "sec-ch-prefers-color-scheme",
            "user-agent",
            "rtt",
            "sec-ch-ua-platform-version",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );

    let h = google(
        &state,
        Method::POST,
        "https://www.google.com/gen_204",
        &[
            ("sec-fetch-mode", "no-cors"),
            ("Content-Type", "text/plain;charset=UTF-8"),
            referer,
        ],
        Some(0),
        None,
    );
    assert_eq!(
        names(&h),
        [
            "content-length",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-platform",
            "sec-ch-ua",
            "sec-ch-ua-bitness",
            "sec-ch-ua-model",
            "sec-ch-ua-mobile",
            "sec-ch-ua-form-factors",
            "sec-ch-ua-wow64",
            "sec-ch-ua-arch",
            "sec-ch-ua-full-version",
            "content-type",
            "downlink",
            "sec-ch-prefers-color-scheme",
            "user-agent",
            "rtt",
            "sec-ch-ua-platform-version",
            "accept",
            "origin",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "referer",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
    assert_eq!(header_value(&h, "origin"), Some("https://www.google.com"));
}

/// Hints go only to the origin that asked, over secure contexts.
#[test]
fn hints_stay_with_their_origin() {
    let state = ClientHintsState::default();
    state.persist("https://www.google.com", GOOGLE_ACCEPT_CH);
    let high_entropy = |h: &[(String, String)]| {
        h.iter()
            .filter(|(k, _)| {
                k.starts_with("sec-ch-ua-") && k != "sec-ch-ua-mobile" && k != "sec-ch-ua-platform"
            })
            .count()
    };
    // Another origin, a cross-origin fetch, an insecure origin: none.
    let other = google(&state, Method::GET, "https://example.com/", &[], None, None);
    assert_eq!(high_entropy(&other), 0);
    let cross = google(
        &state,
        Method::GET,
        "https://www.google.com/api",
        &[
            ("sec-fetch-mode", "cors"),
            ("Referer", "https://www.youtube.com/"),
        ],
        None,
        None,
    );
    assert_eq!(high_entropy(&cross), 0);
    let plain = google(
        &state,
        Method::GET,
        "http://www.google.com/",
        &[],
        None,
        Some(GOOGLE_ALPS),
    );
    assert!(plain.iter().all(|(k, _)| !k.starts_with("sec-ch-")));

    // A caller's value replaces koon's in place.
    let h = google(
        &state,
        Method::GET,
        "https://www.google.com/",
        &[("Sec-CH-UA-Model", "\"custom\"")],
        None,
        None,
    );
    assert_eq!(header_value(&h, "sec-ch-ua-model"), Some("\"custom\""));
    assert_eq!(
        h.iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("sec-ch-ua-model"))
            .count(),
        1
    );
}
