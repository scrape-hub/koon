//! Network-required tests (`--ignored`) of connection reuse and HTTP/3
//! discovery against real servers.

use koon_core::*;
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn connection_pool_reuse() {
    let client = Client::new(Chrome::latest()).unwrap();

    let start = std::time::Instant::now();
    let resp1 = client.get("https://httpbin.org/get").await.unwrap();
    let first_duration = start.elapsed();
    assert_eq!(resp1.status, 200);

    // The second request should reuse the connection (significantly faster).
    let start = std::time::Instant::now();
    let resp2 = client.get("https://httpbin.org/get").await.unwrap();
    let second_duration = start.elapsed();
    assert_eq!(resp2.status, 200);

    // Generous threshold since network latency varies.
    assert!(
        second_duration < first_duration || second_duration < Duration::from_secs(3),
        "Second request should be fast (pool reuse): first={first_duration:?}, second={second_duration:?}"
    );
}

#[tokio::test]
#[ignore]
async fn timeout() {
    let client = Client::builder(Chrome::latest())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    // httpbin.org/delay/10 waits 10s — should time out.
    let result = client.get("https://httpbin.org/delay/10").await;
    assert!(result.is_err(), "Should timeout after 2s on 10s delay");
}

#[tokio::test]
#[ignore]
async fn http3_via_alt_svc() {
    // Google advertises h3 via Alt-Svc too, but also publishes a DNS HTTPS
    // record with `alpn=h3` (like most of Google's own domains), so a
    // default profile reaches HTTP/3 on its very first connection through
    // `https_rr` instead — see `http3_via_dns_https_record` for that. This
    // test isolates the older, still-real Alt-Svc-only mechanism (used
    // whenever a browser's own profile has it off, or as a fallback where no
    // HTTPS record is reachable) by turning `https_rr` off: the first
    // request then goes over h2, a new connection afterwards uses HTTP/3.
    let mut profile = Chrome::latest();
    profile.quic.as_mut().unwrap().https_rr = false;
    let client = Client::new(profile).unwrap();
    let url = "https://www.google.com/generate_204";
    let first = client.get(url).await.unwrap();
    assert_eq!(first.version, "h2");
    client.close();
    let second = client.get(url).await.unwrap();
    assert_eq!(second.status, 204);
    assert_eq!(second.version, "h3", "expected HTTP/3 after Alt-Svc");
    assert!(second.request_headers[0].0 == ":method");
    let third = client.get(url).await.unwrap();
    assert_eq!(third.version, "h3");
    assert!(third.connection_reused);
}

/// The default profile (`https_rr` on) reaches HTTP/3 on its very first
/// connection to a host it never talked to before, from the DNS HTTPS
/// record alone — no Alt-Svc round trip needed (see `http3_via_alt_svc` for
/// the older, Alt-Svc-only mechanism this complements, and
/// `tests/https_rr.rs` for the offline, non-network version of this same
/// check).
#[tokio::test]
#[ignore]
async fn http3_via_dns_https_record() {
    let client = Client::new(Chrome::latest()).unwrap();
    let first = client
        .get("https://www.google.com/generate_204")
        .await
        .unwrap();
    assert_eq!(first.status, 204);
    assert_eq!(
        first.version, "h3",
        "expected HTTP/3 on the first connection, from the DNS HTTPS record"
    );
}
