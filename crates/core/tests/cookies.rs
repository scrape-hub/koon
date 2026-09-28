//! Integration tests for the cookie jar's public API: `Client::set_cookies`/
//! `Client::cookies` (issue #5 import/export), and cross-cutting behaviour
//! of `CookieJar` that's easiest to exercise through the whole crate's
//! public surface rather than as a `cookie.rs` unit test.
//!
//! No network access required.

use koon_core::*;
use std::time::{Duration, SystemTime};

fn imported_cookie(name: &str, domain: &str, host_only: bool) -> Cookie {
    Cookie {
        name: name.to_string(),
        value: "v".to_string(),
        domain: domain.to_string(),
        path: "/".to_string(),
        secure: true,
        http_only: false,
        expires: None,
        same_site: SameSite::Lax,
        host_only,
        creation_time: SystemTime::now(),
    }
}

#[test]
fn set_cookies_then_cookies_roundtrips_through_client() {
    let client = Client::new(Chrome::latest()).unwrap();
    client
        .set_cookies(vec![
            imported_cookie("a", "example.com", true),
            imported_cookie("b", "example.com", false),
        ])
        .unwrap();

    let exported = client.cookies();
    assert_eq!(exported.len(), 2);
    assert!(exported.iter().any(|c| c.name == "a" && c.host_only));
    assert!(exported.iter().any(|c| c.name == "b" && !c.host_only));

    let session = client.save_session().unwrap();
    assert!(session.contains("\"a\""));
    assert!(session.contains("\"b\""));

    client.clear_cookies();
    assert!(client.cookies().is_empty());

    client.load_session(&session).unwrap();
    assert_eq!(client.cookies().len(), 2);
}

#[test]
fn session_file_of_koon_0_8_is_rejected() {
    // koon 0.8 wrote cookies without `creation_time` and keyed TLS sessions
    // by bare hostname.
    let cookies = r#"{
  "cookies": [
    {
      "name": "sid",
      "value": "abc123",
      "domain": "example.com",
      "path": "/",
      "secure": true,
      "http_only": true,
      "expires": null,
      "same_site": "lax",
      "host_only": true
    }
  ],
  "tls_sessions": {}
}"#;
    let tickets = r#"{
  "cookies": [],
  "tls_sessions": {
    "example.com": "MIIBVQIBAQICAwQEAhMBBCA="
  }
}"#;
    let client = Client::new(Chrome::latest()).unwrap();
    for (session, expected) in [
        (cookies, "missing field `creation_time`"),
        (tickets, "invalid TLS session key `example.com`"),
    ] {
        let err = client.load_session(session).unwrap_err();
        assert_eq!(err.code(), "JSON_ERROR");
        assert!(err.to_string().contains(expected), "{err}");
    }
    assert!(client.cookies().is_empty());
}

#[test]
fn session_with_out_of_range_timestamps_loads_without_panicking() {
    let client = Client::new(Chrome::latest()).unwrap();
    let session = r#"{"cookies": [{
        "name": "sid", "value": "1", "domain": "example.com", "path": "/",
        "secure": false, "http_only": false, "same_site": "lax", "host_only": true,
        "expires": 18446744073709551615, "creation_time": 18446744073709551615
    }]}"#;
    client.load_session(session).unwrap();
    let cookies = client.cookies();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].expires, None);
}

#[test]
fn cookie_jar_direct_json_roundtrip_preserves_creation_order() {
    let mut jar = CookieJar::new();
    let url: http::Uri = "https://example.com/a".parse().unwrap();

    jar.store_from_response(
        &url,
        &[("set-cookie".to_string(), "first=1; Path=/".to_string())],
    );
    std::thread::sleep(Duration::from_millis(10));
    jar.store_from_response(
        &url,
        &[("set-cookie".to_string(), "second=2; Path=/".to_string())],
    );

    let json = jar.to_json().unwrap();
    let restored = CookieJar::from_json(&json).unwrap();
    let header = restored.cookie_header(&url).unwrap();

    // Same path length ("/") for both, so ordering must follow creation
    // time, which the roundtrip must have preserved.
    let first_pos = header.find("first=1").unwrap();
    let second_pos = header.find("second=2").unwrap();
    assert!(
        first_pos < second_pos,
        "creation-time order should survive a JSON roundtrip: {header}"
    );
}

#[test]
fn total_cookie_cap_evicts_oldest_across_domains() {
    // The global cap (3300) applies across domains, on top of the
    // per-domain cap (180) that `cookie.rs`'s own unit tests cover. Spread
    // cookies across many single-cookie domains so only the global cap
    // triggers.
    let client = Client::new(Chrome::latest()).unwrap();
    let total = 3305;

    let base = SystemTime::now();
    let cookies: Vec<Cookie> = (0..total)
        .map(|i| {
            let mut cookie = imported_cookie(&format!("c{i}"), &format!("d{i}.example.com"), true);
            cookie.creation_time = base + Duration::from_millis(i as u64);
            cookie
        })
        .collect();
    client.set_cookies(cookies).unwrap();

    let stored = client.cookies();
    assert_eq!(stored.len(), 3300, "global cap should have been enforced");

    // Oldest (lowest index) cookies must be the ones evicted.
    assert!(!stored.iter().any(|c| c.name == "c0"));
    assert!(stored.iter().any(|c| c.name == format!("c{}", total - 1)));
}

#[test]
fn host_only_and_domain_cookie_with_same_name_coexist_via_import() {
    let client = Client::new(Chrome::latest()).unwrap();
    client
        .set_cookies(vec![
            imported_cookie("sid", "example.com", true),
            imported_cookie("sid", "example.com", false),
        ])
        .unwrap();

    assert_eq!(client.cookies().len(), 2);
}

#[test]
fn cookie_params_roundtrip_keeps_host_only_and_domain_cookies_apart() {
    let client = Client::new(Chrome::latest()).unwrap();
    client
        .set_cookie_params(vec![
            CookieParams {
                name: "sid".into(),
                value: "host".into(),
                domain: Some("example.com".into()),
                expires: Some(2_000_000_000.0),
                same_site: Some("strict".into()),
                ..CookieParams::default()
            },
            CookieParams {
                name: "sid".into(),
                value: "domain".into(),
                domain: Some(".example.com".into()),
                ..CookieParams::default()
            },
        ])
        .unwrap();

    let session = client.save_session().unwrap();
    let restored = Client::new(Chrome::latest()).unwrap();
    restored.load_session(&session).unwrap();

    let mut exported = restored.cookie_params();
    exported.sort_by(|a, b| a.value.cmp(&b.value));
    assert_eq!(exported[0].domain.as_deref(), Some(".example.com"));
    assert_eq!(exported[0].expires, Some(-1.0));
    assert_eq!(exported[1].domain.as_deref(), Some("example.com"));
    assert_eq!(exported[1].expires, Some(2_000_000_000.0));
    assert_eq!(exported[1].same_site.as_deref(), Some("Strict"));
}
