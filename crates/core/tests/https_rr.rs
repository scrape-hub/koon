//! Offline tests for HTTP/3 discovery from a DNS HTTPS record
//! (`QuicConfig::https_rr`): a fake nameserver answers the record, checked
//! against the native (plain DNS) and DoH resolvers, which share their
//! answer-parsing and decision code (`Client::https_record`).

#![cfg(feature = "doh")]

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use btls::ssl::Ssl;
use common::h3::{h3_server, h3_server_with_socket};
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use koon_core::dns::{DohConfig, DohResolver, NativeHttpsResolver};
use koon_core::{CertAuthority, Chrome, Client, Safari};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const HOST: &str = "https-rr.koon.test";

/// `profile`, accepting the local servers' certificates.
fn insecure(mut profile: koon_core::BrowserProfile) -> koon_core::BrowserProfile {
    profile.tls.danger_accept_invalid_certs = true;
    profile
}

/// SvcParams advertising `alpn` alone.
fn alpn_params(alpn: &[&str]) -> Vec<(SvcParamKey, SvcParamValue)> {
    let alpn = alpn.iter().map(|s| (*s).to_string()).collect();
    vec![(SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(alpn)))]
}

/// Like [`alpn_params`], with the record's `port` SvcParam (RFC 9460 §7.2)
/// set to `port`: captured on macOS Safari against a record that set it to
/// 8443.
fn alpn_port_params(alpn: &[&str], port: u16) -> Vec<(SvcParamKey, SvcParamValue)> {
    let mut params = alpn_params(alpn);
    params.push((SvcParamKey::Port, SvcParamValue::Port(port)));
    params
}

/// HTTPS server on 127.0.0.1 for `host` that answers every request with a
/// plain 200, no Alt-Svc header: so any HTTP/3 attempt in these tests can
/// only come from the DNS HTTPS record, never from a learned alternative.
/// `port` 0 picks one; TCP and UDP port numbers are independent, so this
/// can share a number with a UDP-only `h3_server` on purpose (see
/// `first_connection_actually_uses_http3_when_a_real_server_answers`, which
/// needs a record with no `port` SvcParam, the common case, to still
/// reach the same address as the URL's own port). Returns the bound port.
async fn plain_server(host: &str, port: u16) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    serve_plain_tls(host, listener)
}

/// [`plain_server`] on a listener the caller already bound.
fn serve_plain_tls(host: &str, listener: TcpListener) -> u16 {
    let (cert, key) = common::leaf(host);
    let acceptor = Arc::new(common::tls_acceptor_builder(&cert, &key).build());
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let ssl = Ssl::new(acceptor.context()).unwrap();
                let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
                if std::pin::Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let response =
                    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// A TCP listener and a UDP socket bound to the *same* port number, for a
/// test that needs an [`h3_server_with_socket`] and a plain TLS server to
/// share one: binds TCP on `:0` first (the OS never hands out a port from
/// Windows' excluded ranges for that), then tries UDP on the number it
/// picked, retrying on a fresh TCP port if that fails: Hyper-V/WSL reserve
/// some TCP ranges (`netsh int ipv4 show excludedportrange protocol=tcp`),
/// and binding UDP first risked landing on one of them.
async fn bind_matching_tcp_and_udp() -> (TcpListener, std::net::UdpSocket) {
    loop {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        match std::net::UdpSocket::bind(("127.0.0.1", port)) {
            Ok(udp) => return (listener, udp),
            Err(_) => continue,
        }
    }
}

/// A profile whose DNS HTTPS record advertises `h3` still ends up on TCP
/// when nothing answers on the QUIC port: Chrome races it
/// (`connect_racing_quic`) so the 300 ms head start is the only delay.
#[tokio::test]
async fn first_connection_falls_back_to_tcp_when_the_advertised_h3_never_answers() {
    let (dns_addr, queries) = common::fake_https_dns_server(HOST, alpn_params(&["h3", "h2"])).await;
    let tcp_port = plain_server(HOST, 0).await;

    let profile = insecure(Chrome::latest());
    assert!(
        profile.quic.as_ref().unwrap().https_rr,
        "Chrome should follow DNS HTTPS records by default"
    );

    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    let url = format!("https://{HOST}:{tcp_port}/");
    let resp = client.get(&url).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_ne!(
        resp.version, "h3",
        "no real HTTP/3 server is listening: the request must fall back to TCP"
    );
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "the HTTPS record must have been queried to attempt QUIC at all"
    );
}

/// Safari opens straight on QUIC when its DNS HTTPS record says `h3`
/// (`connect_direct_quic`, no parallel TCP race); when that QUIC attempt
/// fails outright it still falls back to TCP.
#[tokio::test]
async fn safari_direct_quic_attempt_falls_back_to_tcp_too() {
    let (dns_addr, queries) = common::fake_https_dns_server(HOST, alpn_params(&["h3", "h2"])).await;
    let tcp_port = plain_server(HOST, 0).await;

    let profile = insecure(Safari::latest());
    assert!(
        profile.quic.as_ref().unwrap().https_rr,
        "macOS Safari follows DNS HTTPS records"
    );

    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    let url = format!("https://{HOST}:{tcp_port}/");
    let resp = client.get(&url).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_ne!(resp.version, "h3");
    assert_eq!(queries.load(Ordering::SeqCst), 1);
}

/// A profile whose QUIC config turns `https_rr` off (a custom profile, or
/// koon before this feature) never queries the record at all: it relies on
/// Alt-Svc alone.
#[tokio::test]
async fn a_profile_with_https_rr_off_never_queries_the_record() {
    let (dns_addr, queries) = common::fake_https_dns_server(HOST, alpn_params(&["h3", "h2"])).await;
    let tcp_port = plain_server(HOST, 0).await;

    let mut profile = insecure(Chrome::latest());
    profile.quic.as_mut().unwrap().https_rr = false;

    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    let url = format!("https://{HOST}:{tcp_port}/");
    let resp = client.get(&url).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        queries.load(Ordering::SeqCst),
        0,
        "https_rr = false must never ask the nameserver for the record"
    );
}

/// A record without `h3` in its `alpn` does not trigger a QUIC attempt
/// either: only the presence of `h3` does.
#[tokio::test]
async fn a_record_without_h3_alpn_is_not_treated_as_an_http3_alternative() {
    let (dns_addr, queries) = common::fake_https_dns_server(HOST, alpn_params(&["h2"])).await;
    let tcp_port = plain_server(HOST, 0).await;

    let profile = insecure(Chrome::latest());

    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    let url = format!("https://{HOST}:{tcp_port}/");
    let resp = client.get(&url).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_ne!(resp.version, "h3");
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "the record is still queried"
    );
}

/// The positive case the fallback tests above exist to be measured
/// against: when a real HTTP/3 server does answer on the address the DNS
/// HTTPS record promised, the very first connection to a fresh client: a
/// host it never saw an Alt-Svc header for: actually completes over
/// HTTP/3. Matches Chrome's `dnsAlpnH3Job*` and Firefox's `HTTPSSVC`
/// routing (both captured live against cloudflare.com on Windows 11) and
/// Safari's straight-to-QUIC (Codemagic capture on macOS).
#[tokio::test]
async fn first_connection_actually_uses_http3_when_a_real_server_answers() {
    for chrome in [true, false] {
        // A record with no `port` SvcParam (the common case) means the
        // HTTP/3 attempt targets the URL's own port, so the HTTP/3 server
        // has to sit on the very port the plain one does: fine, since TCP
        // and UDP port numbers are independent namespaces.
        let (tcp_listener, udp_socket) = bind_matching_tcp_and_udp().await;
        let (cert, key) = common::leaf(HOST);
        let h3 = h3_server_with_socket(cert, key, udp_socket);
        let port = serve_plain_tls(HOST, tcp_listener);
        assert_eq!(port, h3.addr.port());
        let (dns_addr, queries) =
            common::fake_https_dns_server(HOST, alpn_params(&["h3", "h2"])).await;

        let profile = insecure(if chrome {
            Chrome::latest()
        } else {
            Safari::latest()
        });

        let client = Client::builder(profile)
            .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], port)))
            .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
            .build()
            .unwrap();

        let url = format!("https://{HOST}:{port}/");
        let resp = client.get(&url).await.unwrap();
        assert_eq!(
            (resp.status, resp.version.as_str()),
            (200, "h3"),
            "{chrome}"
        );
        assert_eq!(queries.load(Ordering::SeqCst), 1, "{chrome}");
    }
}

/// The record's own `port` SvcParam redirects the HTTP/3 attempt of Safari
/// and Firefox to a different port than the URL's (captured from both on
/// macOS): only the redirected port has an HTTP/3 server, so a 200 over h3
/// proves it was honoured, not ignored. Chromium ignores such a record
/// (`chromium_ignores_an_https_record_on_another_port`).
#[tokio::test]
async fn https_rr_port_param_redirects_the_http3_attempt() {
    let profiles = [
        Safari::latest(),
        koon_core::Firefox::version(157, koon_core::Os::MacOS).unwrap(),
    ];
    for mut profile in profiles {
        let (cert, key) = common::leaf(HOST);
        let h3 = h3_server(cert, key);
        let (dns_addr, queries) =
            common::fake_https_dns_server(HOST, alpn_port_params(&["h3"], h3.addr.port())).await;
        let tcp_port = plain_server(HOST, 0).await;
        let family = format!("{:?}", profile.header_family);
        profile.tls.danger_accept_invalid_certs = true;

        let client = Client::builder(profile)
            .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
            .resolve(HOST, h3.addr)
            .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
            .build()
            .unwrap();

        // The URL names the plain server's port; only the record's `port`
        // leads to a server that speaks at all for HTTP/3.
        let url = format!("https://{HOST}:{tcp_port}/");
        let resp = client.get(&url).await.unwrap();
        assert_eq!(
            (resp.status, resp.version.as_str()),
            (200, "h3"),
            "{family}"
        );
        assert_eq!(queries.load(Ordering::SeqCst), 1, "{family}");
    }
}

/// Chromium ignores a record whose `port` differs from the request's
/// ("Chrome does not yet support endpoints diverging by port",
/// `dns_response_result_extractor.cc`; captured: no datagram to the
/// record's port from Chrome, Edge, Opera or Brave): the same record that
/// takes Safari and Firefox to HTTP/3 leaves Chrome on TCP.
#[tokio::test]
async fn chromium_ignores_an_https_record_on_another_port() {
    let (cert, key) = common::leaf(HOST);
    let h3 = h3_server(cert, key);
    let (dns_addr, queries) =
        common::fake_https_dns_server(HOST, alpn_port_params(&["h3"], h3.addr.port())).await;
    let tcp_port = plain_server(HOST, 0).await;

    let profile = insecure(Chrome::latest());

    let client = Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
        .resolve(HOST, h3.addr)
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    let url = format!("https://{HOST}:{tcp_port}/");
    let resp = client.get(&url).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_ne!(resp.version, "h3");
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "the record is still queried"
    );
}

/// Firefox asks the system resolver for the record on Windows, Linux and
/// Android, and on macOS from 151 on; up to 150 macOS asks only through
/// TRR (`network.dns.native_https_query` was false there): without DoH
/// configured, the macOS profile of 150 never asks.
#[tokio::test]
async fn firefox_on_macos_asks_the_system_resolver_from_151() {
    let cases = [
        (koon_core::Os::Windows, 157, 1),
        (koon_core::Os::MacOS, 150, 0),
        (koon_core::Os::MacOS, 151, 1),
        (koon_core::Os::MacOS, 157, 1),
    ];
    for (os, version, expected) in cases {
        let (dns_addr, queries) = common::fake_https_dns_server(HOST, alpn_params(&["h2"])).await;
        let tcp_port = plain_server(HOST, 0).await;

        let mut profile = koon_core::Firefox::version(version, os).unwrap();
        profile.tls.danger_accept_invalid_certs = true;

        let client = Client::builder(profile)
            .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], tcp_port)))
            .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
            .build()
            .unwrap();

        let url = format!("https://{HOST}:{tcp_port}/");
        let resp = client.get(&url).await.unwrap();
        assert_eq!(resp.status, 200, "{os:?} {version}");
        assert_eq!(queries.load(Ordering::SeqCst), expected, "{os:?} {version}");
    }
}

/// A truncated UDP answer is not used as is (it would report no record at
/// all, matching a browser that gave up); the resolver retries over TCP and
/// returns the record from there.
#[tokio::test]
async fn truncated_udp_answer_retries_over_tcp() {
    let dns_addr = common::truncating_https_dns_server(HOST, alpn_params(&["h3"])).await;
    let resolver = NativeHttpsResolver::with_nameserver(dns_addr);
    let record = resolver
        .query_https_record(HOST)
        .await
        .unwrap()
        .expect("the record from the TCP retry, not a truncated non-answer");
    assert_eq!(record.alpn, ["h3"]);
}

// ============================================================
// DNS-over-HTTPS (the resolver's own connection, not just the shared
// answer-parsing the native resolver's tests already cover)
// ============================================================

/// A DNS-over-HTTPS server on 127.0.0.1 answering every `/dns-query` POST
/// with an HTTPS record for `host` advertising `alpn`. Returns its port and
/// its throwaway CA in PEM, for [`DohResolver::with_extra_roots`], a real
/// DoH provider's certificate chains to a publicly trusted root, which a
/// local test server cannot present, so this is the one part of the DoH
/// path the native resolver's tests above cannot stand in for.
async fn doh_server(host: &str, alpn: &[&str]) -> (u16, Vec<u8>) {
    let dir = common::temp_dir("doh-test");
    let ca = CertAuthority::load_or_generate(dir.path().to_path_buf()).unwrap();
    let (cert, key) = ca.get_or_create_leaf(host).unwrap();
    let ca_pem = ca.ca_cert_pem().unwrap();

    let acceptor = common::h2_acceptor(&cert, &key);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = host.to_string();
    let params = alpn_params(alpn);

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let Ok(mut tls) = tokio_btls::SslStream::new(ssl, tcp) else {
                continue;
            };
            let (host, params) = (host.clone(), params.clone());
            tokio::spawn(async move {
                if std::pin::Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                let Ok(mut h2) = http2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = h2.accept().await {
                    let (host, params) = (host.clone(), params.clone());
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut data = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let Ok(chunk) = chunk else { return };
                            let _ = body.flow_control().release_capacity(chunk.len());
                            data.extend_from_slice(&chunk);
                        }
                        let Ok(query) = Message::from_bytes(&data) else {
                            return;
                        };
                        let Ok(wire) = common::https_answer(&query, &host, params).to_bytes()
                        else {
                            return;
                        };
                        let http_response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(http_response, false) else {
                            return;
                        };
                        let _ = send.send_data(bytes::Bytes::from(wire), true);
                    });
                }
            });
        }
    });
    (port, ca_pem)
}

/// The DoH resolver's own connection (TLS to a server outside koon's
/// built-in root store, trusted only via [`DohResolver::with_extra_roots`])
/// yields the same record a real provider would, over its own HTTP/2 POST:
/// not just the wire-format parsing `parse_https_answers` shares with the
/// native resolver.
#[tokio::test]
async fn doh_resolver_fetches_the_record_over_its_own_connection() {
    let (port, ca_pem) = doh_server(HOST, &["h3", "h2"]).await;
    let config = DohConfig {
        server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_hostname: HOST.to_string(),
        server_port: port,
    };
    let resolver = DohResolver::with_extra_roots(config, &ca_pem).unwrap();
    let record = resolver
        .query_https_record(HOST)
        .await
        .unwrap()
        .expect("a record from the local DoH server");
    assert_eq!(record.alpn, ["h3", "h2"]);
}

/// [`DohResolver::with_extra_roots`] rejects a PEM bundle with no
/// certificate in it, the same way
/// [`koon_core::ClientBuilder::proxy_ca_certs`] does for HTTPS proxies.
#[test]
fn doh_resolver_with_extra_roots_rejects_an_empty_pem() {
    let config = DohConfig {
        server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_hostname: HOST.to_string(),
        server_port: 443,
    };
    assert!(DohResolver::with_extra_roots(config, b"not a certificate").is_err());
}

/// A DoH server that answers every `/dns-query` POST with `body_len` bytes of
/// junk instead of a DNS message. Returns its port and its throwaway CA in
/// PEM.
async fn oversized_doh_server(host: &str, body_len: usize) -> (u16, Vec<u8>) {
    let dir = common::temp_dir("doh-oversized-test");
    let ca = CertAuthority::load_or_generate(dir.path().to_path_buf()).unwrap();
    let (cert, key) = ca.get_or_create_leaf(host).unwrap();
    let ca_pem = ca.ca_cert_pem().unwrap();

    let acceptor = common::h2_acceptor(&cert, &key);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let ssl = Ssl::new(acceptor.context()).unwrap();
                let Ok(mut tls) = tokio_btls::SslStream::new(ssl, tcp) else {
                    return;
                };
                if std::pin::Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                let Ok(mut h2) = http2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((_request, mut respond))) = h2.accept().await {
                    tokio::spawn(async move {
                        let http_response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(http_response, false) else {
                            return;
                        };
                        // Far larger than any real DNS message (RFC 1035 §4.2.2's 64 KiB TCP
                        // bound), to check the resolver's own cap rather than relying on a slow
                        // trickle.
                        let junk = bytes::Bytes::from(vec![0u8; body_len]);
                        let _ = send.send_data(junk, true);
                    });
                }
            });
        }
    });
    (port, ca_pem)
}

/// A DoH server that accepts a `/dns-query` POST and its request body, then
/// never answers it (no headers, no data, no reset), to check that the
/// resolver gives up instead of hanging forever on a peer that goes silent
/// after accepting the request.
async fn hanging_doh_server(host: &str) -> (u16, Vec<u8>) {
    let dir = common::temp_dir("doh-hanging-test");
    let ca = CertAuthority::load_or_generate(dir.path().to_path_buf()).unwrap();
    let (cert, key) = ca.get_or_create_leaf(host).unwrap();
    let ca_pem = ca.ca_cert_pem().unwrap();

    let acceptor = common::h2_acceptor(&cert, &key);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let ssl = Ssl::new(acceptor.context()).unwrap();
                let Ok(mut tls) = tokio_btls::SslStream::new(ssl, tcp) else {
                    return;
                };
                if std::pin::Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                let Ok(mut h2) = http2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((_request, respond))) = h2.accept().await {
                    // Keep the response handle alive (and thus the stream open, un-reset)
                    // forever instead of dropping it, which would otherwise send an implicit
                    // RST_STREAM and fail the client quickly instead of hanging it.
                    tokio::spawn(async move {
                        let _keep_open = respond;
                        std::future::pending::<()>().await;
                    });
                }
            });
        }
    });
    (port, ca_pem)
}

/// TRANSPORT-2: a DoH response is capped at a DNS-over-TCP message's size
/// (RFC 1035 §4.2.2), so a compromised or misconfigured DoH endpoint cannot
/// turn one lookup into unbounded memory growth.
#[tokio::test]
async fn doh_resolver_rejects_a_response_larger_than_a_dns_message() {
    let (port, ca_pem) = oversized_doh_server(HOST, 200_000).await;
    let config = DohConfig {
        server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_hostname: HOST.to_string(),
        server_port: port,
    };
    let resolver = DohResolver::with_extra_roots(config, &ca_pem).unwrap();
    let err = resolver.query_https_record(HOST).await.unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
}

/// TRANSPORT-2: a DoH peer that accepts the request and then goes silent
/// does not hang the lookup forever: the resolver's own response timeout
/// (a few seconds) gives up instead.
#[tokio::test]
async fn doh_resolver_times_out_on_a_silent_peer() {
    let (port, ca_pem) = hanging_doh_server(HOST).await;
    let config = DohConfig {
        server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        server_hostname: HOST.to_string(),
        server_port: port,
    };
    let resolver = DohResolver::with_extra_roots(config, &ca_pem).unwrap();
    let err = resolver.query_https_record(HOST).await.unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err}");
}
