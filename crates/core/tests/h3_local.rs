//! Offline HTTP/3 tests against local QUIC servers (quinn with quinn-btls,
//! h3): requests over HTTP/3, resumed connections that send their request
//! as 0-RTT data, a server that rejects that data, and how the client ends
//! its connections.
//!
//! A UDP relay (`common::h3::Relay`) sits between koon and the servers
//! where a test needs to see what the client sends: the 0-RTT packets and
//! the QUIC version are visible in the packet header without decryption.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use common::h3::{H3Server, QUIC_V2, Relay, h3_server, h3_server_with_versions, zero_rtt_bytes};
use h3_quinn::quinn;
use koon_core::{BrowserProfile, Chrome, Client, Firefox, RequestOptions, StreamingResponse};

const HOST: &str = "h3.koon.test";

/// A full HTTP/3 connection, a resumed one that sends its request as 0-RTT
/// data, and one to a server that rejects that data.
async fn zero_rtt_roundtrip(mut profile: BrowserProfile) {
    let (cert, key) = common::leaf(HOST);
    let first = h3_server(cert.clone(), key.clone());
    let second = h3_server(cert, key);
    let relay = Relay::start(first.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");

    // The first response advertises HTTP/3.
    let tcp = client.get(&url).await.unwrap();
    assert_ne!(tcp.version, "h3");
    client.close();

    let full = client.get(&url).await.unwrap();
    assert_eq!((full.status, full.version.as_str()), (200, "h3"));
    assert_eq!(full.body, b"ok"[..]);
    assert!(!full.tls_resumed);
    assert_eq!(relay.last_client().zero_rtt, 0);
    // The server sends its session ticket after the handshake.
    relay.wait_until_quiet().await;
    client.close();

    // Resumed: SETTINGS and the request go out as 0-RTT data (the request
    // headers alone are well over 300 bytes, SETTINGS below 100).
    let resumed = client.get(&url).await.unwrap();
    assert_eq!((resumed.status, resumed.version.as_str()), (200, "h3"));
    assert!(resumed.tls_resumed);
    let early = relay.last_client().zero_rtt;
    assert!(early > 300, "{early} bytes of 0-RTT data");
    assert_eq!(first.requests.load(Ordering::SeqCst), 2);
    client.close();

    // Another server cannot resume the session and rejects the 0-RTT data;
    // the request goes out again once the handshake is complete.
    relay.switch_to(second.addr);
    let rejected = client.get(&url).await.unwrap();
    assert_eq!((rejected.status, rejected.version.as_str()), (200, "h3"));
    assert_eq!(rejected.body, b"ok"[..]);
    assert!(!rejected.tls_resumed);
    let early = relay.last_client().zero_rtt;
    assert!(early > 300, "{early} bytes of 0-RTT data");
    assert_eq!(second.requests.load(Ordering::SeqCst), 1);

    // The connection carries on in 1-RTT.
    let again = client.get(&url).await.unwrap();
    assert_eq!((again.status, again.version.as_str()), (200, "h3"));
    assert!(again.connection_reused);
    assert_eq!(second.requests.load(Ordering::SeqCst), 2);
    relay.wait_until_quiet().await;
    client.close();

    // A request with an unsafe method waits for the handshake of a resumed
    // connection: only SETTINGS go out as 0-RTT data.
    let post = client.post(&url, "x").await.unwrap();
    assert_eq!((post.status, post.version.as_str()), (200, "h3"));
    assert!(post.tls_resumed);
    let early = relay.last_client().zero_rtt;
    assert!(early > 0 && early < 150, "{early} bytes of 0-RTT data");
    assert_eq!(second.requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn chrome_zero_rtt_accepted_and_rejected() {
    zero_rtt_roundtrip(Chrome::latest()).await;
}

#[tokio::test]
async fn firefox_zero_rtt_accepted_and_rejected() {
    zero_rtt_roundtrip(Firefox::latest()).await;
}

/// Chrome's close at shutdown: a transport CONNECTION_CLOSE with NO_ERROR
/// and "70:net error".
fn chrome_shutdown(close: &quinn::ConnectionError) {
    match close {
        quinn::ConnectionError::ConnectionClosed(close) => {
            assert_eq!(close.error_code, quinn::TransportErrorCode::NO_ERROR);
            assert_eq!(&close.reason[..], b"70:net error");
        }
        other => panic!("{other:?}"),
    }
}

/// Firefox's close: an application CONNECTION_CLOSE with H3_NO_ERROR and no
/// reason phrase.
fn firefox_close(close: &quinn::ConnectionError) {
    match close {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, quinn::VarInt::from_u32(0x100));
            assert!(close.reason.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

/// `Client::close` ends the idle HTTP/3 connections as the browser does at
/// shutdown, and so does dropping the client. A connection whose response
/// is still being read ends as when the pool drops it once the response is
/// done (`on_drop`; `None` discards it without a packet, as Chrome does).
async fn closes_connections(
    mut profile: BrowserProfile,
    shutdown: fn(&quinn::ConnectionError),
    on_drop: Option<fn(&quinn::ConnectionError)>,
) {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let tcp_port = common::alt_svc_server(HOST, server.addr.port()).await;
    profile.tls.danger_accept_invalid_certs = true;
    let build = || {
        Client::builder(profile.clone())
            .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
            .resolve(HOST, server.addr)
            .build()
            .unwrap()
    };
    let url = format!("https://{HOST}:{tcp_port}/");

    let client = build();
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    assert_eq!(client.get(&url).await.unwrap().version, "h3");
    client.close();
    shutdown(&server.closes(1).await[0]);

    // Dropped with an idle connection.
    assert_eq!(client.get(&url).await.unwrap().version, "h3");
    drop(client);
    shutdown(&server.closes(2).await[1]);

    // Closed, then dropped, while a response is being read.
    let client = build();
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    let mut closes = 2;
    let mut response = stream(&client, &url).await;
    client.close();
    closes = read_then_drop(&server, response, closes, on_drop).await;
    response = stream(&client, &url).await;
    drop(client);
    read_then_drop(&server, response, closes, on_drop).await;
}

/// Read the response on a connection the client let go of, drop it, and
/// check how the connection ends. Returns the number of closes seen.
async fn read_then_drop(
    server: &H3Server,
    mut response: StreamingResponse,
    closes: usize,
    on_drop: Option<fn(&quinn::ConnectionError)>,
) -> usize {
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.closes.lock().unwrap().len(), closes);
    assert_eq!(response.next_chunk().await.unwrap().unwrap(), b"ok");
    drop(response);
    match on_drop {
        Some(on_drop) => {
            on_drop(&server.closes(closes + 1).await[closes]);
            closes + 1
        }
        None => {
            // Discarded without a packet: the connection answers nothing any
            // more, not even a PING.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let connection = server.last_connection();
            let acks = connection.stats().frame_rx.acks;
            connection.ping();
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(connection.stats().frame_rx.acks, acks);
            assert_eq!(server.closes.lock().unwrap().len(), closes);
            closes
        }
    }
}

async fn stream(client: &Client, url: &str) -> StreamingResponse {
    let response = client
        .send_streaming(
            http::Method::GET,
            url,
            Vec::new(),
            RequestOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(response.version, "h3");
    response
}

#[tokio::test]
async fn chrome_closes_connections() {
    closes_connections(Chrome::latest(), chrome_shutdown, None).await;
}

#[tokio::test]
async fn firefox_closes_connections() {
    closes_connections(Firefox::latest(), firefox_close, Some(firefox_close)).await;
}

/// `Client::shutdown` ends the HTTP/3 connections at once, one with a
/// response still being read included, and returns once the close is sent.
async fn shutdown_closes_at_once(
    mut profile: BrowserProfile,
    shutdown: fn(&quinn::ConnectionError),
) {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let tcp_port = common::alt_svc_server(HOST, server.addr.port()).await;
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, server.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    assert_ne!(client.get(&url).await.unwrap().version, "h3");

    let response = stream(&client, &url).await;
    let started = std::time::Instant::now();
    client.shutdown().await;
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "{:?}",
        started.elapsed()
    );
    shutdown(&server.closes(1).await[0]);
    drop(response);

    // The client stays usable.
    assert_eq!(client.get(&url).await.unwrap().version, "h3");
}

#[tokio::test]
async fn chrome_shutdown_closes_at_once() {
    shutdown_closes_at_once(Chrome::latest(), chrome_shutdown).await;
}

#[tokio::test]
async fn firefox_shutdown_closes_at_once() {
    shutdown_closes_at_once(Firefox::latest(), firefox_close).await;
}

/// The close `Client::shutdown` waited for reaches the server although the
/// client's runtime stops right after, as when the process exits.
#[tokio::test]
async fn shutdown_close_outlives_the_runtime() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let tcp_port = common::alt_svc_server(HOST, server.addr.port()).await;
    let h3_addr = server.addr;
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut profile = Chrome::latest();
            profile.tls.danger_accept_invalid_certs = true;
            let client = Client::builder(profile)
                .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
                .resolve(HOST, h3_addr)
                .build()
                .unwrap();
            let url = format!("https://{HOST}:{tcp_port}/");
            assert_ne!(client.get(&url).await.unwrap().version, "h3");
            assert_eq!(client.get(&url).await.unwrap().version, "h3");
            client.shutdown().await;
        });
        runtime.shutdown_background();
    })
    .await
    .unwrap();
    chrome_shutdown(&server.closes(1).await[0]);
}

/// A streamed upload that finishes before the server answers with an
/// interim 103 and then the final response.
#[tokio::test]
async fn streamed_upload_then_early_hints() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let tcp_port = common::alt_svc_server(HOST, server.addr.port()).await;
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, server.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    client.close();

    let chunks = vec![
        Ok::<_, std::io::Error>(Bytes::from_static(b"first ")),
        Ok(Bytes::from_static(b"second")),
    ];
    let body = koon_core::Body::stream(futures_util::stream::iter(chunks));
    let options = RequestOptions {
        headers: vec![("x-early-hints".into(), "1".into())],
        ..RequestOptions::default()
    };
    let response = client
        .send(http::Method::POST, &url, body, options)
        .await
        .unwrap();
    assert_eq!((response.status, response.version.as_str()), (200, "h3"));
    assert_eq!(response.body, b"ok"[..]);
}

/// A request a new HTTP/3 connection rejects unprocessed goes out again
/// over TCP, as in Chrome, POST included; the alternative is then broken.
#[tokio::test]
async fn rejected_request_falls_back_to_tcp() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let tcp_port = common::alt_svc_server(HOST, server.addr.port()).await;
    let mut profile = Firefox::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, server.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    client.close();

    let options = RequestOptions {
        headers: vec![("x-reject".into(), "1".into())],
        ..RequestOptions::default()
    };
    let response = client
        .send(http::Method::POST, &url, "x", options)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_ne!(response.version, "h3");
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    // Broken now: the next request goes over TCP without trying QUIC.
    client.close();
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

/// A server that prefers QUIC version 2 switches Firefox's connection to it
/// (compatible version negotiation, RFC 9368), and the next connection
/// resumes in version 2 and sends its request as 0-RTT data: neqo starts in
/// the version of its resumption token.
#[tokio::test]
async fn firefox_follows_a_switch_to_version_2_and_resumes_in_it() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server_with_versions(cert, key, Some(vec![QUIC_V2, 1]));
    let relay = Relay::start(server.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    let mut profile = Firefox::latest();
    profile.tls.danger_accept_invalid_certs = true;
    // quinn switches only when the first Initial holds the whole
    // ClientHello, which it does without the ML-KEM key share.
    let quic_tls = profile.quic.as_mut().unwrap().tls.as_mut().unwrap();
    quic_tls.curves = "X25519:P-256".into();
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    client.close();

    // Started in version 1, switched to version 2.
    let full = client.get(&url).await.unwrap();
    assert_eq!((full.status, full.version.as_str()), (200, "h3"));
    assert!(!full.tls_resumed);
    let versions = relay.last_client().versions();
    assert_eq!(versions[0], 1, "{versions:x?}");
    assert!(versions.contains(&QUIC_V2), "{versions:x?}");
    // The server sends its session ticket after the handshake.
    relay.wait_until_quiet().await;
    client.close();

    // Resumed in version 2, the request in 0-RTT packets of version 2.
    let resumed = client.get(&url).await.unwrap();
    assert_eq!((resumed.status, resumed.version.as_str()), (200, "h3"));
    assert!(resumed.tls_resumed);
    let last = relay.last_client();
    assert!(
        last.versions().iter().all(|v| *v == QUIC_V2),
        "{:x?}",
        last.versions()
    );
    assert!(last.zero_rtt > 300, "{} bytes of 0-RTT data", last.zero_rtt);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
}

/// Firefox up to 154 offers version 1 only: a server that prefers version 2
/// keeps the connection in version 1, and the next one resumes in version 1.
#[tokio::test]
async fn firefox_154_stays_on_version_1() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server_with_versions(cert, key, Some(vec![QUIC_V2, 1]));
    let relay = Relay::start(server.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    let mut profile = Firefox::version(154, koon_core::Os::Windows).unwrap();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    client.close();

    let full = client.get(&url).await.unwrap();
    assert_eq!((full.status, full.version.as_str()), (200, "h3"));
    let versions = relay.last_client().versions();
    assert!(versions.iter().all(|v| *v == 1), "{versions:x?}");
    relay.wait_until_quiet().await;
    client.close();

    let resumed = client.get(&url).await.unwrap();
    assert_eq!((resumed.status, resumed.version.as_str()), (200, "h3"));
    assert!(resumed.tls_resumed);
    let versions = relay.last_client().versions();
    assert!(versions.iter().all(|v| *v == 1), "{versions:x?}");
}

#[test]
fn counts_coalesced_zero_rtt_packets() {
    // An Initial (empty token, 2-byte payload) followed by a 0-RTT packet,
    // then zero padding.
    let mut datagram = vec![0xc0, 0, 0, 0, 1, 1, 0xaa, 0, 0, 2, 0xbb, 0xcc];
    datagram.extend_from_slice(&[0xd0, 0, 0, 0, 1, 1, 0xaa, 0, 1, 0xdd]);
    datagram.extend_from_slice(&[0; 8]);
    assert_eq!(zero_rtt_bytes(&datagram), 10);
}

/// Safari uses HTTP/3 once Alt-Svc offers it; a resumed connection sends
/// only its SETTINGS as 0-RTT data and the request after the handshake
/// (captured from Safari 26.6.2 and 27.0 on macOS 26.6.2).
#[tokio::test]
async fn safari_sends_no_request_in_zero_rtt() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let relay = Relay::start(server.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    let mut profile = koon_core::Safari::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");

    let tcp = client.get(&url).await.unwrap();
    assert_ne!(tcp.version, "h3");
    client.close();
    let full = client.get(&url).await.unwrap();
    assert_eq!((full.status, full.version.as_str()), (200, "h3"));
    assert!(!full.tls_resumed);
    relay.wait_until_quiet().await;
    client.close();

    let resumed = client.get(&url).await.unwrap();
    assert_eq!((resumed.status, resumed.version.as_str()), (200, "h3"));
    assert!(resumed.tls_resumed);
    let early = relay.last_client().zero_rtt;
    assert!(early > 0 && early < 150, "{early} bytes of 0-RTT data");
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
}

/// Safari before 26 offers no TLS session over QUIC either: every
/// connection is a full handshake without 0-RTT (captured from Safari on
/// macOS 14.7 to 15.7 and iOS 17.5 to 18.5, also within one session).
#[tokio::test]
async fn safari_before_26_resumes_no_quic_session() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let relay = Relay::start(server.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    let mut profile = koon_core::Safari::version("18.5", koon_core::Os::MacOS).unwrap();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");

    let tcp = client.get(&url).await.unwrap();
    assert_ne!(tcp.version, "h3");
    client.close();
    let first = client.get(&url).await.unwrap();
    assert_eq!((first.status, first.version.as_str()), (200, "h3"));
    relay.wait_until_quiet().await;
    client.close();

    let second = client.get(&url).await.unwrap();
    assert_eq!((second.status, second.version.as_str()), (200, "h3"));
    assert!(!second.tls_resumed);
    assert_eq!(relay.last_client().zero_rtt, 0);
}

/// Safari on macOS 15.1 and 15.2 and iOS 18.0 to 18.2 ignores Alt-Svc
/// (captured: no QUIC packet, even with TCP to the server failing), so its
/// profiles stay on HTTP/2.
#[tokio::test]
async fn safari_18_2_ignores_alt_svc() {
    let (cert, key) = common::leaf(HOST);
    let server = h3_server(cert, key);
    let relay = Relay::start(server.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    let mut profile = koon_core::Safari::version("18.2", koon_core::Os::MacOS).unwrap();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    for _ in 0..3 {
        let response = client.get(&url).await.unwrap();
        assert_eq!(response.status, 200);
        assert_ne!(response.version, "h3");
        client.close();
    }
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

/// Safari leaves a connection it no longer uses to the idle timeout and
/// closes its connections at shutdown with H3_NO_ERROR.
#[tokio::test]
async fn safari_closes_connections() {
    closes_connections(koon_core::Safari::latest(), firefox_close, None).await;
}
