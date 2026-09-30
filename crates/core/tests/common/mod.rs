//! Helpers shared by the offline integration tests: a scratch CA directory,
//! a certificate for a test hostname, TLS acceptors built from it, a fake
//! nameserver answering HTTPS/SVCB queries, and an HTTP/3 server with a
//! relay in front of it (`h3`).

// Each test binary uses a part of the helpers.
#![allow(dead_code)]

pub mod h3;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use btls::pkey::{PKey, Private};
use btls::ssl::{AlpnError, Ssl, SslAcceptor, SslAcceptorBuilder, SslMethod};
use btls::x509::X509;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::https::HTTPS;
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use koon_core::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A fresh scratch directory under the OS temp dir, named `koon-<prefix>-`.
/// Removed when the guard is dropped, also on a panic.
pub fn temp_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("koon-{prefix}-"))
        .tempdir()
        .expect("temp dir")
}

/// A certificate for `host` from a throwaway CA.
pub fn leaf(host: &str) -> (X509, PKey<Private>) {
    let dir = temp_dir("test-leaf");
    let ca = CertAuthority::load_or_generate(dir.path().to_path_buf()).expect("CA");
    ca.get_or_create_leaf(host).expect("leaf cert")
}

/// A `mozilla_intermediate_v5` acceptor builder for `cert`/`key`, with no
/// ALPN callback set: callers add their own protocol negotiation.
pub fn tls_acceptor_builder(cert: &X509, key: &PKey<Private>) -> SslAcceptorBuilder {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate(cert).unwrap();
    builder.set_private_key(key).unwrap();
    builder
}

/// A TLS acceptor for `cert`/`key` that selects `h2` in ALPN and nothing
/// else.
pub fn h2_acceptor(cert: &X509, key: &PKey<Private>) -> SslAcceptor {
    let mut builder = tls_acceptor_builder(cert, key);
    builder.set_alpn_select_callback(|_, offered| {
        btls::ssl::select_next_proto(b"\x02h2", offered).ok_or(AlpnError::NOACK)
    });
    builder.build()
}

/// HTTPS server on 127.0.0.1 for `host` that answers every request with an
/// Alt-Svc advertisement for `h3_port`. Returns its port.
pub async fn alt_svc_server(host: &str, h3_port: u16) -> u16 {
    plain_server_with_headers(host, &format!("alt-svc: h3=\":{h3_port}\"; ma=86400\r\n")).await
}

/// Plain HTTPS server on 127.0.0.1 for `host`, answering every request with
/// `200 ok` and no Alt-Svc header: for a test that must rule out Alt-Svc as
/// the reason a client reached HTTP/3 (see `https_rr.rs`). Returns its port.
pub async fn plain_server(host: &str) -> u16 {
    plain_server_with_headers(host, "").await
}

async fn plain_server_with_headers(host: &str, extra_headers: &str) -> u16 {
    let (cert, key) = leaf(host);
    let acceptor = Arc::new(tls_acceptor_builder(&cert, &key).build());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let extra_headers = extra_headers.to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let extra_headers = extra_headers.clone();
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
                let response = format!(
                    "HTTP/1.1 200 OK\r\n{extra_headers}\
                     content-length: 2\r\nconnection: close\r\n\r\nok"
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// A ServiceMode HTTPS record answer for `host` at SvcPriority 1 carrying
/// `params` (RFC 9460), matching `query`'s id and question; NODATA if
/// `query` did not ask for an HTTPS record.
pub fn https_answer(
    query: &Message,
    host: &str,
    params: Vec<(SvcParamKey, SvcParamValue)>,
) -> Message {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NoError);
    for q in query.queries() {
        response.add_query(q.clone());
    }
    if query
        .queries()
        .first()
        .is_some_and(|q| q.query_type() == RecordType::HTTPS)
    {
        let target = Name::from_str(&format!("{host}.")).unwrap();
        let svcb = SVCB::new(1, Name::root(), params);
        response.add_answer(Record::from_rdata(target, 300, RData::HTTPS(HTTPS(svcb))));
    }
    response
}

/// A UDP nameserver answering every HTTPS-type query for `host` with a
/// ServiceMode record carrying `params`, NODATA otherwise. Returns its
/// address and the number of queries it received.
pub async fn fake_https_dns_server(
    host: &str,
    params: Vec<(SvcParamKey, SvcParamValue)>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
    let addr = socket.local_addr().expect("local addr");
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    let host = host.to_string();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let response = https_answer(&query, &host, params.clone());
            if let Ok(bytes) = response.to_bytes() {
                let _ = socket.send_to(&bytes, from).await;
            }
        }
    });
    (addr, queries)
}

/// A nameserver that truncates every UDP answer (the `TC` bit, no usable
/// record: as if the real one had not fit the EDNS buffer) and answers the
/// real query, a ServiceMode record for `host` carrying `params`, only over
/// TCP on the same port number (independent namespaces): the system's
/// resolvers and the browsers retry over TCP instead of trusting a
/// possibly-incomplete UDP answer.
pub async fn truncating_https_dns_server(
    host: &str,
    params: Vec<(SvcParamKey, SvcParamValue)>,
) -> SocketAddr {
    // Windows never excludes a port TCP already bound; UDP first risks
    // landing in a range Hyper-V/WSL reserve.
    let (udp, tcp_listener) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(tcp) => break (udp, tcp),
            Err(_) => continue,
        }
    };
    let addr = udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                break;
            };
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let mut response = Message::new();
            response.set_id(query.id());
            response.set_message_type(MessageType::Response);
            response.set_op_code(OpCode::Query);
            response.set_truncated(true);
            for q in query.queries() {
                response.add_query(q.clone());
            }
            if let Ok(bytes) = response.to_bytes() {
                let _ = udp.send_to(&bytes, from).await;
            }
        }
    });
    let host = host.to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp_listener.accept().await {
            let (host, params) = (host.clone(), params.clone());
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let Ok(query) = Message::from_bytes(&body) else {
                    return;
                };
                let response = https_answer(&query, &host, params);
                let Ok(bytes) = response.to_bytes() else {
                    return;
                };
                let len = (bytes.len() as u16).to_be_bytes();
                let _ = stream.write_all(&len).await;
                let _ = stream.write_all(&bytes).await;
            });
        }
    });
    addr
}

/// Poll `ready` every 10 ms until it returns `true` or `timeout` elapses.
/// Returns whether it became ready in time, so a caller can assert on a
/// timeout instead of panicking inside the helper.
pub async fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while !ready() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}
