//! Connection handling against real servers (network required, run with
//! `--ignored`): sharing a connection among parallel requests, HTTP/3
//! bodies outliving the pool's handle on their connection, streamed HTTP/3
//! uploads and 0-RTT on resumed HTTP/3 connections.

use std::time::Duration;

use http::Method;
use koon_core::client::Body;
use koon_core::{Chrome, Client, Firefox, RequestOptions};

#[tokio::test]
#[ignore]
async fn parallel_requests_to_a_known_http2_origin_share_one_connection() {
    let client = Client::new(Chrome::latest()).unwrap();
    let url = "https://www.google.com/generate_204";
    // Learn that the origin is multiplexed, then start over without a
    // pooled connection.
    client.get(url).await.unwrap();
    client.close();

    let (a, b, c, d, e, f) = tokio::join!(
        client.get(url),
        client.get(url),
        client.get(url),
        client.get(url),
        client.get(url),
        client.get(url)
    );
    let new_connections = [a, b, c, d, e, f]
        .into_iter()
        .map(|r| r.unwrap())
        .filter(|r| !r.connection_reused)
        .count();
    assert_eq!(
        new_connections, 1,
        "the others wait for the first connection"
    );
}

#[tokio::test]
#[ignore]
async fn http3_body_survives_the_pool_dropping_its_connection() {
    let client = Client::new(Chrome::latest()).unwrap();
    let url = "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.js";
    // The first response advertises HTTP/3; the next connection uses it.
    client.head(url).await.unwrap();
    client.close();

    let mut resp = client
        .send_streaming(Method::GET, url, None, RequestOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.version, "h3");
    let length: Option<usize> = resp
        .headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok());
    // The pool lets go of the connection while the body is in flight.
    client.close();
    let mut total = 0;
    while let Some(chunk) = resp.next_chunk().await {
        total += chunk.expect("the body outlives the pool's handle").len();
    }
    assert!(total > 10_000, "read {total} bytes");
    if let Some(length) = length {
        assert_eq!(total, length);
    }
}

#[tokio::test]
#[ignore]
async fn http3_sends_a_streamed_body() {
    let client = Client::new(Chrome::latest()).unwrap();
    let url = "https://www.google.com/generate_204";
    client.head(url).await.unwrap();
    client.close();

    // 1 MiB of unknown length. Whatever the server answers, the request
    // goes out over HTTP/3 and gets a response.
    let chunk = bytes::Bytes::from(vec![b'x'; 64 * 1024]);
    let pieces = futures_util::stream::iter((0..16).map(move |_| Ok(chunk.clone())));
    let response = client.post(url, Body::stream(pieces)).await.unwrap();
    assert_eq!(response.version, "h3");
    assert!(response.status >= 200, "{}", response.status);
}

/// A resumed HTTP/3 connection sends its GET as 0-RTT data, as Chrome and
/// Firefox do; the server taking the early data is reported as a resumed
/// TLS session.
#[tokio::test]
#[ignore]
async fn http3_resumed_connection_sends_the_request_as_0rtt() {
    for profile in [Chrome::latest(), Firefox::latest()] {
        let client = Client::new(profile).unwrap();
        let url = "https://www.google.com/generate_204";
        // www.google.com's DNS HTTPS record lists h3 (`QuicConfig::https_rr`):
        // the first request already makes a full QUIC handshake.
        let full = client.get(url).await.unwrap();
        assert_eq!(full.version, "h3");
        assert!(!full.tls_resumed);
        // The server sends its session tickets after the handshake.
        tokio::time::sleep(Duration::from_secs(1)).await;
        client.close();

        let resumed = client.get(url).await.unwrap();
        assert_eq!(resumed.status, 204);
        assert_eq!(resumed.version, "h3");
        assert!(
            resumed.tls_resumed,
            "the server did not take the 0-RTT data"
        );
        assert!(!resumed.connection_reused);
    }
}
