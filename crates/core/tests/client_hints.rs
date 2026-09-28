//! Offline tests of Chromium's client hints against local HTTP/2 and
//! HTTP/3 servers: the ACCEPT_CH frame of the server's ALPS data, Accept-CH
//! persisted for later navigations, and Critical-CH.

mod common;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use btls::ssl::{AlpnError, SslRef};
use bytes::Bytes;
use koon_core::{BrowserProfile, Chrome, Client, Firefox, Os};
use tokio::net::TcpListener;

unsafe extern "C" {
    // btls wraps it without the settings data.
    fn SSL_add_application_settings(
        ssl: *mut std::ffi::c_void,
        proto: *const u8,
        proto_len: usize,
        settings: *const u8,
        settings_len: usize,
    ) -> std::ffi::c_int;
}

/// An HTTP/2 ACCEPT_CH frame (type 0x89) with one entry.
fn accept_ch_frame(origin: &str, value: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend((origin.len() as u16).to_be_bytes());
    payload.extend(origin.as_bytes());
    payload.extend((value.len() as u16).to_be_bytes());
    payload.extend(value.as_bytes());
    let len = payload.len();
    let mut frame = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x89,
        0,
        0,
        0,
        0,
        0,
    ];
    frame.extend(payload);
    frame
}

/// Status and headers of the response to the `n`th request (from 0) for
/// a path.
type Respond = Arc<dyn Fn(usize, &str) -> (u16, Vec<(&'static str, &'static str)>) + Send + Sync>;

/// A server's answer: 200 with these headers for every request.
fn always(headers: Vec<(&'static str, &'static str)>) -> Respond {
    Arc::new(move |_, _| (200, headers.clone()))
}

/// An HTTP/2 server on 127.0.0.1 that answers every request with 200 and
/// the headers `respond` gives, and sends ACCEPT_CH for its origin with the
/// value `alps` as its ALPS data. Returns the port and the number of
/// requests answered.
async fn server(alps: Option<&str>, respond: Respond) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let alps = alps.map(|value| accept_ch_frame(&format!("https://127.0.0.1:{port}"), value));

    let (cert, key) = common::leaf("127.0.0.1");
    let mut builder = common::tls_acceptor_builder(&cert, &key);
    builder.set_alpn_select_callback(move |ssl: &mut SslRef, offered| {
        if let Some(alps) = &alps {
            ssl.set_alps_use_new_codepoint(true);
            // SAFETY: in the foreign-types pattern, &mut SslRef is the SSL
            // pointer; BoringSSL copies both buffers.
            let ret = unsafe {
                SSL_add_application_settings(
                    ssl as *mut SslRef as *mut std::ffi::c_void,
                    b"h2".as_ptr(),
                    2,
                    alps.as_ptr(),
                    alps.len(),
                )
            };
            assert_eq!(ret, 1);
        }
        btls::ssl::select_next_proto(b"\x02h2", offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let count = Arc::new(AtomicUsize::new(0));
    let answered = count.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            let (respond, answered) = (respond.clone(), answered.clone());
            tokio::spawn(async move {
                if Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                let Ok(mut h2) = http2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut sender))) = h2.accept().await {
                    let n = answered.fetch_add(1, Ordering::SeqCst);
                    let (status, headers) = respond(n, request.uri().path());
                    let mut response = http::Response::builder().status(status);
                    for (name, value) in headers {
                        response = response.header(name, value);
                    }
                    let mut send = sender
                        .send_response(response.body(()).unwrap(), false)
                        .unwrap();
                    send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                }
            });
        }
    });
    (port, count)
}

fn client(mut profile: BrowserProfile) -> Client {
    profile.tls.danger_accept_invalid_certs = true;
    Client::new(profile).unwrap()
}

/// The header names of a request, without the pseudo-headers.
fn names(headers: &[(String, String)]) -> Vec<&str> {
    headers
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| !k.starts_with(':'))
        .collect()
}

fn value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Chromium restarts a navigation whose connection's ALPS data carries an
/// ACCEPT_CH frame for its origin before sending it, with the hints
/// appended after `accept`: the first request already has them.
#[tokio::test]
async fn alps_accept_ch_frame_adds_hints_to_the_first_navigation() {
    let (port, _) = server(
        Some("Sec-CH-UA-Arch, Sec-CH-UA-WoW64, Sec-CH-UA-Model"),
        always(Vec::new()),
    )
    .await;
    let client = client(Chrome::version(153, Os::Windows).unwrap());
    let response = client
        .get(&format!("https://127.0.0.1:{port}/"))
        .await
        .unwrap();
    assert_eq!(response.version, "h2");
    let sent = &response.request_headers;
    assert_eq!(
        names(sent),
        [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-ch-ua-arch",
            "sec-ch-ua-model",
            "sec-ch-ua-wow64",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
    assert_eq!(value(sent, "sec-ch-ua-arch"), Some("\"x86\""));
    assert_eq!(value(sent, "sec-ch-ua-model"), Some("\"\""));
    assert_eq!(value(sent, "sec-ch-ua-wow64"), Some("?0"));

    // The frame is not remembered: a fetch() gets the default hints only.
    let fetch = client
        .send(
            http::Method::GET,
            &format!("https://127.0.0.1:{port}/api"),
            koon_core::Body::empty(),
            koon_core::RequestOptions {
                headers: vec![("sec-fetch-mode".into(), "cors".into())],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(value(&fetch.request_headers, "sec-ch-ua-arch"), None);
}

/// Accept-CH of a navigation response: later navigations to the origin and
/// its same-origin fetches carry the hints, in Chromium's order.
#[tokio::test]
async fn accept_ch_applies_to_later_requests_to_the_origin() {
    let (port, _) = server(
        None,
        always(vec![
            ("accept-ch", "Sec-CH-UA-Platform-Version"),
            ("accept-ch", "Sec-CH-UA-Full-Version-List, RTT"),
        ]),
    )
    .await;
    let client = client(Chrome::version(153, Os::Windows).unwrap());
    let url = format!("https://127.0.0.1:{port}/");
    let first = client.get(&url).await.unwrap();
    assert_eq!(value(&first.request_headers, "rtt"), None);

    let second = client.get(&url).await.unwrap();
    let sent = &second.request_headers;
    assert_eq!(
        names(sent)[..7],
        [
            "rtt",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "sec-ch-ua-full-version-list",
            "upgrade-insecure-requests",
        ]
    );
    assert_eq!(value(sent, "rtt"), Some("100"));
    assert_eq!(
        value(sent, "sec-ch-ua-platform-version"),
        Some("\"19.0.0\"")
    );

    // Cross-origin fetches from its pages get the default hints only.
    let options = |origin: &str| koon_core::RequestOptions {
        headers: vec![
            ("sec-fetch-mode".into(), "cors".into()),
            ("Referer".into(), format!("{origin}/page")),
        ],
        ..Default::default()
    };
    let fetch = client
        .send(
            http::Method::GET,
            &url,
            koon_core::Body::empty(),
            options(&format!("https://127.0.0.1:{port}")),
        )
        .await
        .unwrap();
    assert!(value(&fetch.request_headers, "sec-ch-ua-platform-version").is_some());
    let cross = client
        .send(
            http::Method::GET,
            &url,
            koon_core::Body::empty(),
            options("https://other.test"),
        )
        .await
        .unwrap();
    assert_eq!(
        value(&cross.request_headers, "sec-ch-ua-platform-version"),
        None
    );
}

/// Critical-CH next to Accept-CH: a navigation that lacked one of those
/// hints goes out again with it, once.
#[tokio::test]
async fn critical_ch_sends_the_navigation_again() {
    let (port, count) = server(
        None,
        always(vec![
            ("accept-ch", "Sec-CH-UA-Model, Sec-CH-UA-Bitness"),
            ("critical-ch", "Sec-CH-UA-Model"),
        ]),
    )
    .await;
    let client = client(Chrome::version(153, Os::Windows).unwrap());
    let response = client
        .get(&format!("https://127.0.0.1:{port}/"))
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(
        value(&response.request_headers, "sec-ch-ua-model"),
        Some("\"\"")
    );
    assert_eq!(
        value(&response.request_headers, "sec-ch-ua-bitness"),
        Some("\"64\"")
    );

    // The hints are known now: no second request.
    client
        .get(&format!("https://127.0.0.1:{port}/next"))
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

/// A Critical-CH restart starts the navigation over from its first URL, as
/// Chromium's `CriticalClientHintsThrottle` resets it.
#[tokio::test]
async fn critical_ch_restarts_from_the_first_url() {
    let paths: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let seen = paths.clone();
    let (port, _) = server(
        None,
        Arc::new(move |_, path| {
            seen.lock().unwrap().push(path.to_string());
            match path {
                "/start" => (302, vec![("location", "/page")]),
                _ => (
                    200,
                    vec![
                        ("accept-ch", "Sec-CH-UA-Model"),
                        ("critical-ch", "Sec-CH-UA-Model"),
                    ],
                ),
            }
        }),
    )
    .await;
    let client = client(Chrome::version(153, Os::Windows).unwrap());
    let response = client
        .get(&format!("https://127.0.0.1:{port}/start"))
        .await
        .unwrap();
    assert_eq!(
        *paths.lock().unwrap(),
        ["/start", "/page", "/start", "/page"]
    );
    assert!(response.url.ends_with("/page"));
    assert_eq!(
        value(&response.request_headers, "sec-ch-ua-model"),
        Some("\"\"")
    );
}

/// An HTTP/3 ACCEPT_CH frame (type 0x89, varint lengths) with one entry.
fn h3_accept_ch_frame(origin: &str, value: &str) -> Vec<u8> {
    fn varint(v: usize, out: &mut Vec<u8>) {
        if v < 64 {
            out.push(v as u8);
        } else {
            out.extend(((v as u16) | 0x4000).to_be_bytes());
        }
    }
    let mut payload = Vec::new();
    varint(origin.len(), &mut payload);
    payload.extend(origin.as_bytes());
    varint(value.len(), &mut payload);
    payload.extend(value.as_bytes());
    let mut frame = Vec::new();
    varint(0x89, &mut frame);
    varint(payload.len(), &mut frame);
    frame.extend(payload);
    frame
}

/// Over HTTP/3 the ALPS data comes with the QUIC handshake: the first
/// request on a new connection carries the hints it asks for.
#[tokio::test]
async fn http3_alps_accept_ch_frame_adds_hints() {
    const HOST: &str = "h3.koon.test";
    let (cert, key) = common::leaf(HOST);
    let alps: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
    let h3 = common::h3::h3_server_with_alps(cert, key, alps.clone());
    let tcp_port = common::alt_svc_server(HOST, h3.addr.port()).await;
    *alps.lock().unwrap() = h3_accept_ch_frame(
        &format!("https://{HOST}:{tcp_port}"),
        "Sec-CH-UA-Arch, Sec-CH-UA-Bitness",
    );

    let mut profile = Chrome::version(153, Os::Windows).unwrap();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, h3.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    // The first response advertises HTTP/3.
    let tcp = client.get(&url).await.unwrap();
    assert_ne!(tcp.version, "h3");
    client.close();

    let response = client.get(&url).await.unwrap();
    assert_eq!(response.version, "h3");
    let sent = names(&response.request_headers);
    let position = |name| sent.iter().position(|n| *n == name).unwrap();
    assert_eq!(position("sec-ch-ua-arch"), position("accept") + 1);
    assert_eq!(position("sec-ch-ua-bitness"), position("accept") + 2);
    assert_eq!(
        value(&response.request_headers, "sec-ch-ua-arch"),
        Some("\"x86\"")
    );
}

/// Firefox sends no client hints, whatever the server asks for.
#[tokio::test]
async fn firefox_ignores_client_hint_requests() {
    let (port, count) = server(
        Some("Sec-CH-UA-Arch"),
        always(vec![
            ("accept-ch", "Sec-CH-UA-Model"),
            ("critical-ch", "Sec-CH-UA-Model"),
        ]),
    )
    .await;
    let client = client(Firefox::latest());
    let url = format!("https://127.0.0.1:{port}/");
    client.get(&url).await.unwrap();
    let response = client.get(&url).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert!(
        response
            .request_headers
            .iter()
            .all(|(k, _)| !k.starts_with("sec-ch-"))
    );
}
