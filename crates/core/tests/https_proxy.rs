//! Offline tests of `https://` proxies: a local TLS proxy with a
//! certificate from a throwaway CA, which speaks CONNECT and answers
//! absolute-form requests itself, and a plain HTTP server addressed as an
//! `https://` proxy.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use btls::ssl::Ssl;
use http::Method;
use koon_core::client::Body;
use koon_core::{CertAuthority, Chrome, Client, ClientBuilder, Error, RequestOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod common;

/// A throwaway CA. Its files are deleted right away: the CA works from
/// memory.
fn new_ca(name: &str) -> CertAuthority {
    let dir = common::temp_dir(&format!("https-proxy-{name}"));
    CertAuthority::load_or_generate(dir.path().to_path_buf()).unwrap()
}

/// A TLS acceptor with a certificate for `host` from `ca`.
fn acceptor(ca: &CertAuthority, host: &str) -> Arc<btls::ssl::SslAcceptor> {
    let (cert, key) = ca.get_or_create_leaf(host).unwrap();
    Arc::new(common::tls_acceptor_builder(&cert, &key).build())
}

/// Read one HTTP request head, byte by byte so nothing after it is taken.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => head.push(byte[0]),
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// A TLS proxy on 127.0.0.1 with a certificate from `ca`. CONNECT opens a
/// tunnel to the address named; any other request is answered by the
/// proxy itself with "proxied". Records each request line.
async fn tls_proxy(ca: &CertAuthority) -> (String, Arc<Mutex<Vec<String>>>) {
    tls_proxy_on(ca, "127.0.0.1").await
}

/// [`tls_proxy`] on the loopback address `ip`, with a certificate for it.
async fn tls_proxy_on(ca: &CertAuthority, ip: &str) -> (String, Arc<Mutex<Vec<String>>>) {
    let acceptor = acceptor(ca, ip);
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let lines = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            let lines = lines.clone();
            tokio::spawn(async move {
                if Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                let Some(head) = read_head(&mut tls).await else {
                    return;
                };
                let line = head.lines().next().unwrap_or_default().to_string();
                lines.lock().unwrap().push(line.clone());
                let target = line
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split(' ').next());
                if let Some(target) = target {
                    let Ok(mut upstream) = TcpStream::connect(target).await else {
                        let _ = tls.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return;
                    };
                    tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                } else {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nproxied",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    (format!("https://{addr}"), seen)
}

/// An HTTPS origin on 127.0.0.1 with a certificate from `ca`; answers
/// "origin".
async fn tls_origin(ca: &CertAuthority) -> u16 {
    let acceptor = acceptor(ca, "127.0.0.1");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            tokio::spawn(async move {
                if Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                if read_head(&mut tls).await.is_some() {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\norigin",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    port
}

/// What a plain HTTP server received on each connection.
type Received = Arc<Mutex<Vec<Vec<u8>>>>;

/// A plain HTTP server, as an HTTP proxy reacts to a ClientHello: it
/// answers the first bytes with 400. Keeps everything each connection
/// sent until the client closed it.
async fn plain_http_proxy() -> (u16, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Received = Arc::default();
    let all = received.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let all = all.clone();
            tokio::spawn(async move {
                let mut bytes = vec![0u8; 16 * 1024];
                let n = tcp.read(&mut bytes).await.unwrap_or(0);
                bytes.truncate(n);
                let _ = tcp
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ =
                    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut bytes)).await;
                all.lock().unwrap().push(bytes);
            });
        }
    });
    (port, received)
}

fn builder_with_proxy(proxy: &str) -> ClientBuilder {
    Client::builder(Chrome::latest()).proxy(proxy).unwrap()
}

fn proxy_error(result: Result<koon_core::HttpResponse, Error>) -> String {
    match result {
        Err(Error::Proxy(msg, _)) => msg,
        Err(e) => panic!("expected a proxy error, got {e}"),
        Ok(resp) => panic!("expected a proxy error, got status {}", resp.status),
    }
}

#[tokio::test]
async fn an_untrusted_proxy_certificate_is_rejected() {
    let ca = new_ca("untrusted");
    let (proxy, seen) = tls_proxy(&ca).await;

    let client = builder_with_proxy(&proxy).build().unwrap();
    let msg = proxy_error(client.get("http://example.test/").await);
    assert!(msg.starts_with("TLS to proxy failed"), "{msg}");
    assert!(msg.contains("CERTIFICATE_VERIFY_FAILED"), "{msg}");

    // Skipping origin verification does not cover the proxy.
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .proxy(&proxy)
        .unwrap()
        .build()
        .unwrap();
    let msg = proxy_error(client.get("http://example.test/").await);
    assert!(msg.contains("CERTIFICATE_VERIFY_FAILED"), "{msg}");

    assert!(
        seen.lock().unwrap().is_empty(),
        "no request reached the proxy"
    );
}

#[tokio::test]
async fn proxy_ca_certs_are_trusted_for_the_proxy_only() {
    let ca = new_ca("trusted");
    let (proxy, seen) = tls_proxy(&ca).await;
    let origin = tls_origin(&ca).await;
    let ca_pem = ca.ca_cert_pem().unwrap();

    let client = builder_with_proxy(&proxy)
        .proxy_ca_certs(&ca_pem)
        .unwrap()
        .build()
        .unwrap();
    // http:// goes to the proxy in absolute form, inside the TLS connection.
    let resp = client.get("http://example.test/x").await.unwrap();
    assert_eq!(resp.text(), "proxied");
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        "GET http://example.test/x HTTP/1.1"
    );

    // The origin's certificate comes from the same CA, which is trusted for
    // the proxy only.
    let origin_url = format!("https://127.0.0.1:{origin}/");
    match client.get(&origin_url).await {
        Err(Error::Tls(e)) => assert!(e.to_string().contains("CERTIFICATE_VERIFY_FAILED"), "{e}"),
        Err(e) => panic!("expected the origin's TLS to fail, got {e}"),
        Ok(resp) => panic!("the origin was trusted: {}", resp.status),
    }
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        &format!("CONNECT 127.0.0.1:{origin} HTTP/1.1")
    );

    // A bundle of several certificates; TLS to the origin inside the
    // tunnel inside TLS to the proxy.
    let mut bundle = new_ca("other").ca_cert_pem().unwrap();
    bundle.extend_from_slice(&ca_pem);
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .proxy(&proxy)
        .unwrap()
        .proxy_ca_certs(&bundle)
        .unwrap()
        .build()
        .unwrap();
    let resp = client.get(&origin_url).await.unwrap();
    assert_eq!(resp.text(), "origin");
}

#[tokio::test]
async fn accepting_invalid_proxy_certificates_leaves_origins_verified() {
    let ca = new_ca("insecure");
    let (proxy, seen) = tls_proxy(&ca).await;
    let origin = tls_origin(&ca).await;

    let client = builder_with_proxy(&proxy)
        .danger_accept_invalid_proxy_certs(true)
        .build()
        .unwrap();
    let resp = client.get("http://example.test/").await.unwrap();
    assert_eq!(resp.text(), "proxied");
    match client.get(&format!("https://127.0.0.1:{origin}/")).await {
        Err(Error::Tls(e)) => assert!(e.to_string().contains("CERTIFICATE_VERIFY_FAILED"), "{e}"),
        Err(e) => panic!("expected the origin's TLS to fail, got {e}"),
        Ok(resp) => panic!("the origin was trusted: {}", resp.status),
    }

    // An https:// proxy given for one request only.
    let client = Client::builder(Chrome::latest())
        .danger_accept_invalid_proxy_certs(true)
        .build()
        .unwrap();
    let options = RequestOptions {
        proxy: Some(proxy.clone()),
        ..Default::default()
    };
    let resp = client
        .send(
            Method::GET,
            "http://example.test/once",
            Body::empty(),
            options,
        )
        .await
        .unwrap();
    assert_eq!(resp.text(), "proxied");
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        "GET http://example.test/once HTTP/1.1"
    );
}

#[tokio::test]
async fn an_ipv6_literal_proxy_is_verified_by_its_address() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("no IPv6 loopback: skipped");
        return;
    }
    let ca = new_ca("ipv6");
    let (proxy, _) = tls_proxy_on(&ca, "::1").await;
    assert!(proxy.starts_with("https://[::1]:"), "{proxy}");
    let client = builder_with_proxy(&proxy)
        .proxy_ca_certs(&ca.ca_cert_pem().unwrap())
        .unwrap()
        .build()
        .unwrap();
    let resp = client.get("http://example.test/").await.unwrap();
    assert_eq!(resp.text(), "proxied");
}

#[tokio::test]
async fn a_plain_http_proxy_addressed_as_https_gets_a_hint() {
    let (port, received) = plain_http_proxy().await;
    let client = builder_with_proxy(&format!("https://user:pass@127.0.0.1:{port}"))
        .max_retries(2)
        .build()
        .unwrap();

    for url in ["http://example.test/secret", "https://example.test/secret"] {
        let msg = proxy_error(client.get(url).await);
        assert_eq!(
            msg,
            format!(
                "proxy 127.0.0.1:{port} answered in plain HTTP; use http:// instead of https:// for this proxy"
            )
        );
    }

    // Each attempt (two requests, two retries each) sent a ClientHello and
    // nothing in plain text: no CONNECT, no target, no credentials.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.lock().unwrap().len() < 6 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let received = received.lock().unwrap();
    assert_eq!(received.len(), 6);
    for bytes in received.iter() {
        assert_eq!(bytes.first(), Some(&0x16), "a TLS handshake record");
        for plain in [
            &b"CONNECT"[..],
            b"GET ",
            b"example.test",
            b"secret",
            b"Proxy-Authorization",
            b"dXNlcjpwYXNz",
        ] {
            assert!(
                !bytes.windows(plain.len()).any(|w| w == plain),
                "{} went to the proxy in plain text",
                String::from_utf8_lossy(plain)
            );
        }
    }
}

#[test]
fn invalid_proxy_ca_pem_is_rejected() {
    let invalid: [&[u8]; 3] = [
        b"",
        b"not a certificate",
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ];
    for pem in invalid {
        match Client::builder(Chrome::latest()).proxy_ca_certs(pem) {
            Err(Error::InvalidArgument(..)) => {}
            Err(e) => panic!("expected InvalidArgument, got {e}"),
            Ok(_) => panic!("accepted {}", String::from_utf8_lossy(pem)),
        }
    }
}
