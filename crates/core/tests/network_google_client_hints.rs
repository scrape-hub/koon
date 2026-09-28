//! Network-required tests (`--ignored`) of client hints against
//! www.google.com (the offline equivalents against a local server live in
//! `tests/client_hints.rs`).

use koon_core::*;

/// www.google.com asks for client hints in its ALPS data and with
/// Accept-CH: the first navigation carries the ALPS ones after `accept`,
/// the next one all it asked for, at the front (as captured from Chrome
/// 153, Edge 153 and Opera 136).
#[tokio::test]
#[ignore]
async fn google_client_hints_over_http3() {
    // www.google.com's DNS HTTPS record lists h3, so with `https_rr` the
    // fetch below would already open QUIC and the navigation resume it with
    // 0-RTT, sending before the ALPS data arrives (as Chromium does, see
    // `H3Conn::accept_ch`). Alt-Svc only keeps the navigation on the first,
    // fully handshaken QUIC connection this test is about.
    let mut profile = Chrome::version(153, Os::Windows).unwrap();
    profile.quic.as_mut().unwrap().https_rr = false;
    let client = Client::new(profile).unwrap();
    // A fetch learns the HTTP/3 alternative without remembering Accept-CH.
    let fetch = client
        .send(
            http::Method::GET,
            "https://www.google.com/generate_204",
            Body::empty(),
            RequestOptions {
                headers: vec![("sec-fetch-mode".into(), "cors".into())],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(fetch.status, 204);
    client.close();

    let navigation = client.get("https://www.google.com/").await.unwrap();
    assert_eq!(navigation.version, "h3");
    let sent = |name: &str| {
        navigation
            .request_headers
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case(name))
    };
    // The hints of the ALPS ACCEPT_CH frame, appended after `accept`.
    assert_eq!(
        sent("sec-ch-ua-arch"),
        sent("accept").map(|p| p + 1),
        "{:?}",
        navigation.request_headers
    );
    assert_eq!(sent("rtt"), None);
}

#[tokio::test]
#[ignore]
async fn google_client_hints() {
    for profile in [
        Chrome::version(153, Os::Windows).unwrap(),
        Edge::version(153, Os::Windows).unwrap(),
        Opera::version(136, Os::Windows).unwrap(),
    ] {
        let client = Client::new(profile).unwrap();
        let first = client.get("https://www.google.com/").await.unwrap();
        let sent = |r: &HttpResponse, name: &str| {
            r.request_headers
                .iter()
                .position(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        let (arch, accept) = (sent(&first, "sec-ch-ua-arch"), sent(&first, "accept"));
        assert!(
            arch.is_some() && arch > accept,
            "{:?}",
            first.request_headers
        );
        assert_eq!(sent(&first, "rtt"), None);

        let second = client.get("https://www.google.com/").await.unwrap();
        let (rtt, ua) = (sent(&second, "rtt"), sent(&second, "user-agent"));
        assert!(rtt.is_some() && rtt < ua, "{:?}", second.request_headers);
        assert!(sent(&second, "sec-ch-ua-full-version").is_some());
        assert!(sent(&second, "sec-ch-ua-form-factors").is_some());
    }
}
