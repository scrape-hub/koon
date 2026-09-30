//! Tests for the local MITM proxy against local origin servers: how requests and responses pass
//! through it. Certificate-authority behaviour (leaf signing, caching, CA persistence) is
//! unit-tested next to `CertAuthority` in `src/proxy/ca.rs`.
//!
//! No network access needed: origins run on 127.0.0.1, and the TLS tests
//! only terminate TLS at the proxy.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use btls::ssl::{SslConnector, SslMethod, SslSession, SslSessionCacheMode};
use btls::x509::X509;
use koon_core::{Chrome, Client, HeaderMode, ProxyServer, ProxyServerAuth, ProxyServerConfig};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod common;

/// A fresh scratch directory under the OS temp dir with a unique name, so
/// parallel test runs (and repeat runs) never collide. It is removed when
/// the guard is dropped, also when the test fails.
fn temp_ca_dir(name: &str) -> TempDir {
    common::temp_dir(&format!("proxy-test-{name}"))
}

// ------------------------------------------------------------------
// Proxy server against local origins
// ------------------------------------------------------------------

/// A proxy with its CA in a fresh temp directory, which lives as long as
/// the returned guard.
async fn start_proxy(
    name: &str,
    header_mode: HeaderMode,
    timeout_secs: u64,
) -> (ProxyServer, TempDir) {
    let ca_dir = temp_ca_dir(name);
    let proxy = ProxyServer::start(ProxyServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        header_mode,
        ca_dir: Some(ca_dir.path().to_string_lossy().into_owned()),
        client: Client::builder(Chrome::latest()).timeout(Duration::from_secs(timeout_secs)),
        ..ProxyServerConfig::default()
    })
    .await
    .expect("proxy should start");
    (proxy, ca_dir)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read one HTTP/1.1 message head plus a Content-Length body from `stream`,
/// keeping bytes past it in `buf`. `None` at EOF.
async fn read_message<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let head_len = loop {
        if let Some(pos) = find(buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if stream.read_buf(buf).await.ok()? == 0 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_len]).to_string();
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_len + length {
        if stream.read_buf(buf).await.ok()? == 0 {
            return None;
        }
    }
    let rest = buf.split_off(head_len + length);
    Some(std::mem::replace(buf, rest))
}

/// An origin that answers every request with the raw request it received
/// (head and body) as its body.
async fn echo_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while let Some(request) = read_message(&mut stream, &mut buf).await {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                        request.len()
                    );
                    if stream.write_all(head.as_bytes()).await.is_err()
                        || stream.write_all(&request).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// An origin that answers one connection with `parts`, written with
/// `gap` in between.
async fn scripted_origin(parts: Vec<Vec<u8>>, gap: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        read_message(&mut stream, &mut buf).await;
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(gap).await;
            }
            stream.write_all(part).await.unwrap();
        }
        // Keep the connection open until the client is done with it.
        let _ = stream.read(&mut [0u8; 1]).await;
    });
    addr
}

/// A parsed response from the proxy: its head (lowercased) and its body,
/// de-chunked if it was chunked.
struct Response {
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn status(&self) -> &str {
        self.head.split(' ').nth(1).unwrap_or("")
    }

    fn has_header(&self, line: &str) -> bool {
        self.head
            .contains(&format!("\r\n{}\r\n", line.to_ascii_lowercase()))
    }
}

/// Split everything a proxy connection returned into responses.
fn parse_responses(mut raw: &[u8]) -> Vec<Response> {
    let mut responses = Vec::new();
    while let Some(pos) = find(raw, b"\r\n\r\n") {
        let head = String::from_utf8_lossy(&raw[..pos + 4]).to_ascii_lowercase();
        raw = &raw[pos + 4..];
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|v| v.trim().parse::<usize>().ok());
        let mut body = Vec::new();
        if head.contains("\r\ntransfer-encoding: chunked\r\n") {
            loop {
                let line_end = find(raw, b"\r\n").expect("chunk size line");
                let size =
                    usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).unwrap(), 16)
                        .unwrap();
                raw = &raw[line_end + 2..];
                if size == 0 {
                    raw = &raw[2..];
                    break;
                }
                body.extend_from_slice(&raw[..size]);
                raw = &raw[size + 2..];
            }
        } else if let Some(length) = length {
            body.extend_from_slice(&raw[..length]);
            raw = &raw[length..];
        } else {
            body.extend_from_slice(raw);
            raw = &[];
        }
        responses.push(Response { head, body });
    }
    responses
}

/// Send raw bytes to the proxy and collect everything until it closes the
/// connection.
async fn exchange(proxy: &ProxyServer, request: &[u8]) -> Vec<Response> {
    let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw))
        .await
        .expect("proxy should answer and close")
        .unwrap();
    parse_responses(&raw)
}

#[tokio::test]
async fn impersonate_forwards_request_headers_but_not_the_client_identity() {
    let origin = echo_origin().await;
    let (proxy, _ca_dir) = start_proxy("impersonate", HeaderMode::Impersonate, 10).await;

    let request = format!(
        "POST http://{origin}/login HTTP/1.1\r\n\
         Host: {origin}\r\n\
         User-Agent: curl/8.0\r\n\
         Accept: text/plain\r\n\
         Cookie: sid=abc\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Authorization: Bearer token\r\n\
         Referer: http://{origin}/form\r\n\
         Origin: http://{origin}\r\n\
         X-Custom: yes\r\n\
         Content-Length: 7\r\n\
         Connection: close\r\n\r\n\
         a=1&b=2"
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].status(), "200");
    let seen = String::from_utf8_lossy(&responses[0].body).to_string();

    assert!(seen.starts_with("POST /login HTTP/1.1\r\n"), "{seen}");
    for expected in [
        "Cookie: sid=abc",
        "Content-Type: application/x-www-form-urlencoded",
        "Authorization: Bearer token",
        &format!("Referer: http://{origin}/form"),
        &format!("Origin: http://{origin}"),
        "X-Custom: yes",
        "Content-Length: 7",
    ] {
        assert!(
            seen.contains(&format!("\r\n{expected}\r\n")),
            "{expected} missing:\n{seen}"
        );
    }
    assert!(seen.ends_with("\r\n\r\na=1&b=2"), "{seen}");
    assert!(seen.contains("Chrome/"), "{seen}");
    assert!(!seen.contains("curl"), "{seen}");
    assert!(!seen.contains("Accept: text/plain"), "{seen}");

    proxy.shutdown();
}

#[tokio::test]
async fn passthrough_keeps_header_case_and_order() {
    let origin = echo_origin().await;
    let (proxy, _ca_dir) = start_proxy("passthrough", HeaderMode::Passthrough, 10).await;

    let request = format!(
        "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nUser-Agent: MyAgent\r\nx-lower: 1\r\nX-Mixed-CASE: 2\r\nConnection: close\r\n\r\n"
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    let seen = String::from_utf8_lossy(&responses[0].body).to_string();
    assert!(
        seen.contains("\r\nUser-Agent: MyAgent\r\nx-lower: 1\r\nX-Mixed-CASE: 2\r\n"),
        "{seen}"
    );

    proxy.shutdown();
}

#[tokio::test]
async fn pipelined_requests_without_a_body_are_all_answered() {
    let origin = echo_origin().await;
    let (proxy, _ca_dir) = start_proxy("pipelining", HeaderMode::Impersonate, 10).await;

    let request = format!(
        "GET http://{origin}/a HTTP/1.1\r\nHost: {origin}\r\n\r\n\
         POST http://{origin}/b HTTP/1.1\r\nHost: {origin}\r\nContent-Length: 3\r\n\r\nxyz\
         GET http://{origin}/c HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    let lines: Vec<String> = responses
        .iter()
        .map(|r| {
            let body = String::from_utf8_lossy(&r.body).to_string();
            body.lines().next().unwrap_or("").to_string()
        })
        .collect();
    assert_eq!(
        lines,
        ["GET /a HTTP/1.1", "POST /b HTTP/1.1", "GET /c HTTP/1.1"]
    );
    assert!(String::from_utf8_lossy(&responses[1].body).ends_with("\r\n\r\nxyz"));

    proxy.shutdown();
}

#[tokio::test]
async fn invalid_requests_get_400() {
    let origin = echo_origin().await;
    let (proxy, _ca_dir) = start_proxy("bad-request", HeaderMode::Impersonate, 10).await;

    for request in [
        format!("POST http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nContent-Length: abc\r\n\r\n"),
        format!("GET /relative HTTP/1.1\r\nHost: {origin}\r\n\r\n"),
        format!(
            "POST http://{origin}/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
    ] {
        let responses = exchange(&proxy, request.as_bytes()).await;
        assert_eq!(responses[0].status(), "400", "{request}");
    }

    proxy.shutdown();
}

#[tokio::test]
async fn response_body_is_streamed_as_it_arrives() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        read_message(&mut stream, &mut buf).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nfirst\n\r\n")
            .await
            .unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"5\r\nlast\n\r\n0\r\n\r\n").await.unwrap();
        let _ = stream.read(&mut [0u8; 1]).await;
    });
    let (proxy, _ca_dir) = start_proxy("streaming", HeaderMode::Impersonate, 10).await;

    let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    stream
        .write_all(
            format!(
                "GET http://{origin}/events HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    // The first event arrives while the origin still holds back the rest.
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while find(&raw, b"first\n").is_none() {
            assert_ne!(stream.read_buf(&mut raw).await.unwrap(), 0);
        }
    })
    .await
    .expect("the first chunk should be forwarded before the body is complete");

    release_tx.send(()).unwrap();
    stream.read_to_end(&mut raw).await.unwrap();
    let responses = parse_responses(&raw);
    assert!(responses[0].has_header("transfer-encoding: chunked"));
    assert_eq!(responses[0].body, b"first\nlast\n");

    proxy.shutdown();
}

#[tokio::test]
async fn body_slower_than_the_timeout_still_arrives() {
    // Four pieces 400 ms apart: 1.2 s in total, over the 1 s timeout, but
    // never idle for that long.
    let parts = vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\naaa".to_vec(),
        b"bbb".to_vec(),
        b"ccc".to_vec(),
        b"ddd".to_vec(),
    ];
    let origin = scripted_origin(parts, Duration::from_millis(400)).await;
    let (proxy, _ca_dir) = start_proxy("slow-body", HeaderMode::Impersonate, 1).await;

    let request =
        format!("GET http://{origin}/big HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses[0].status(), "200");
    assert!(responses[0].has_header("content-length: 12"));
    assert_eq!(responses[0].body, b"aaabbbcccddd");

    proxy.shutdown();
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn impersonate_decodes_the_body_and_passthrough_keeps_it() {
    let text = b"compressed body ".repeat(20);
    let encoded = gzip(&text);
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        encoded.len()
    )
    .into_bytes();
    response.extend_from_slice(&encoded);

    for mode in [HeaderMode::Impersonate, HeaderMode::Passthrough] {
        let origin = scripted_origin(vec![response.clone()], Duration::ZERO).await;
        let (proxy, _ca_dir) = start_proxy("encoding", mode, 10).await;
        let request =
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
        let responses = exchange(&proxy, request.as_bytes()).await;
        let r = &responses[0];
        match mode {
            HeaderMode::Impersonate => {
                assert_eq!(r.body, text);
                assert!(!r.head.contains("content-encoding"), "{}", r.head);
                assert!(!r.head.contains("content-length"), "{}", r.head);
                assert!(r.has_header("transfer-encoding: chunked"));
            }
            HeaderMode::Passthrough => {
                assert_eq!(r.body, encoded);
                assert!(r.has_header("content-encoding: gzip"), "{}", r.head);
                assert!(r.has_header(&format!("content-length: {}", encoded.len())));
            }
        }
        proxy.shutdown();
    }
}

#[tokio::test]
async fn shutdown_closes_open_connections() {
    let origin = echo_origin().await;
    let (proxy, _ca_dir) = start_proxy("shutdown", HeaderMode::Impersonate, 10).await;

    let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let request = format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let response = read_message(&mut stream, &mut buf).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

    // The keep-alive connection is still open; shutting down closes it.
    proxy.shutdown();
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
        .await
        .expect("shutdown should close the connection");
    assert!(read.is_err() || rest.is_empty());
}

/// A TLS client that trusts `ca_pem` and records the sessions it is given.
fn tls_client(ca_pem: &[u8], sessions: Arc<Mutex<Vec<SslSession>>>) -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder
        .cert_store_mut()
        .add_cert(X509::from_pem(ca_pem).unwrap())
        .unwrap();
    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    builder.set_new_session_callback(move |_, session| sessions.lock().unwrap().push(session));
    builder.build()
}

/// Open a CONNECT tunnel through the proxy and complete a verified TLS
/// handshake for `host` inside it.
async fn open_tunnel(
    proxy: &ProxyServer,
    connector: &SslConnector,
    target: &str,
    host: &str,
    session: Option<&SslSession>,
) -> tokio_btls::SslStream<TcpStream> {
    let mut tcp = TcpStream::connect(proxy.local_addr()).await.unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut established = Vec::new();
    while find(&established, b"\r\n\r\n").is_none() {
        assert_ne!(tcp.read_buf(&mut established).await.unwrap(), 0);
    }
    assert!(established.starts_with(b"HTTP/1.1 200"));

    let mut ssl = connector.configure().unwrap().into_ssl(host).unwrap();
    if let Some(session) = session {
        // SAFETY: the session comes from a context configured like this one.
        unsafe { ssl.set_session(session).unwrap() };
    }
    let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
    Pin::new(&mut tls)
        .connect()
        .await
        .expect("the leaf certificate should verify for the tunnel's host");
    tls
}

#[tokio::test]
async fn connect_tunnels_verify_for_ip_and_long_hosts_and_resume_tls() {
    let (proxy, _ca_dir) = start_proxy("connect", HeaderMode::Impersonate, 5).await;
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let connector = tls_client(&proxy.ca_cert_pem().unwrap(), sessions.clone());

    // A long host name (over the 64-character Common Name limit).
    let long = format!("{}.example.com", "a".repeat(70));
    drop(open_tunnel(&proxy, &connector, &format!("{long}:443"), &long, None).await);

    // An IP literal: verified against the iPAddress SAN. Nothing listens on
    // port 1, so the forwarded request gets a 502.
    let mut tls = open_tunnel(&proxy, &connector, "127.0.0.1:1", "127.0.0.1", None).await;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw)
        .await
        .expect("the proxy should end the tunnel with close_notify");
    assert!(
        raw.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
        "{}",
        String::from_utf8_lossy(&raw)
    );

    // The acceptor for the host is reused, so its sessions resume.
    let session = sessions
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the proxy should issue a session ticket");
    let tls = open_tunnel(
        &proxy,
        &connector,
        "127.0.0.1:1",
        "127.0.0.1",
        Some(&session),
    )
    .await;
    assert!(tls.ssl().session_reused());

    proxy.shutdown();
}

#[tokio::test]
async fn tunnels_present_the_leaf_for_the_sni_host() {
    let (proxy, _ca_dir) = start_proxy("sni", HeaderMode::Impersonate, 5).await;
    let connector = tls_client(&proxy.ca_cert_pem().unwrap(), Arc::default());

    // The CONNECT target is an IP, but the client names a host in its SNI:
    // the leaf follows the SNI, and verifies for that host.
    let tls = open_tunnel(&proxy, &connector, "127.0.0.1:1", "example.com", None).await;
    let leaf = tls.ssl().peer_certificate().unwrap();
    let sans = leaf.subject_alt_names().unwrap();
    assert_eq!(sans.iter().next().unwrap().dnsname(), Some("example.com"));

    proxy.shutdown();
}

#[tokio::test]
async fn upstream_client_settings_apply() {
    // The echo origin answers requests in absolute form too, as a forward
    // proxy for plain http:// URLs would.
    let upstream = echo_origin().await;
    let ca_dir = temp_ca_dir("upstream");
    let proxy = ProxyServer::start(ProxyServerConfig {
        ca_dir: Some(ca_dir.path().to_string_lossy().into_owned()),
        client: Client::builder(Chrome::latest())
            .proxy(&format!("http://{upstream}"))
            .unwrap()
            .locale("de-DE"),
        ..ProxyServerConfig::default()
    })
    .await
    .expect("proxy should start");

    let request = "GET http://example.test/page HTTP/1.1\r\nHost: example.test\r\n\
                   Accept-Language: en-GB\r\nConnection: close\r\n\r\n";
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses[0].status(), "200");
    let seen = String::from_utf8_lossy(&responses[0].body).to_ascii_lowercase();
    assert!(
        seen.starts_with("get http://example.test/page http/1.1\r\n"),
        "{seen}"
    );
    assert!(
        seen.contains("\r\naccept-language: de-de,de;q=0.9,"),
        "{seen}"
    );
    assert!(!seen.contains("en-gb"), "{seen}");

    proxy.shutdown();
}

#[tokio::test]
async fn redirects_and_cookies_are_left_to_the_proxied_client() {
    // The default client follows redirects and keeps cookies; the proxy
    // turns both off.
    let redirect = b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\n\
                     Set-Cookie: sid=1; Path=/\r\nContent-Length: 0\r\n\r\n"
        .to_vec();
    let origin = scripted_origin(vec![redirect], Duration::ZERO).await;
    let echo = echo_origin().await;
    let ca_dir = temp_ca_dir("no-redirects");
    let proxy = ProxyServer::start(ProxyServerConfig {
        ca_dir: Some(ca_dir.path().to_string_lossy().into_owned()),
        ..ProxyServerConfig::default()
    })
    .await
    .expect("proxy should start");

    let request = format!(
        "GET http://{origin}/start HTTP/1.1\r\nHost: {origin}\r\n\r\n\
         GET http://{echo}/next HTTP/1.1\r\nHost: {echo}\r\nConnection: close\r\n\r\n"
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses[0].status(), "302");
    assert!(responses[0].has_header("location: /elsewhere"));
    assert!(responses[0].has_header("set-cookie: sid=1; path=/"));
    let seen = String::from_utf8_lossy(&responses[1].body).to_ascii_lowercase();
    assert!(seen.starts_with("get /next "), "{seen}");
    assert!(!seen.contains("sid=1"), "{seen}");

    proxy.shutdown();
}

async fn get_streaming(client: &Client, origin: SocketAddr) -> koon_core::StreamingResponse {
    client
        .send_streaming(
            http::Method::GET,
            &format!("http://{origin}/"),
            koon_core::Body::empty(),
            Default::default(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn streaming_responses_decode_their_content_on_request() {
    let text = b"streamed and compressed ".repeat(40);
    let encoded = gzip(&text);
    // The body arrives in two pieces, the first too short to decode to
    // anything yet.
    let parts = || {
        let mut first = format!(
            "HTTP/1.1 200 OK
Content-Encoding: gzip
Content-Length: {}

",
            encoded.len()
        )
        .into_bytes();
        first.extend_from_slice(&encoded[..10]);
        vec![first, encoded[10..].to_vec()]
    };
    let client = Client::new(Chrome::latest()).unwrap();

    let origin = scripted_origin(parts(), Duration::from_millis(50)).await;
    let mut response = get_streaming(&client, origin).await;
    assert!(response.decode_content());
    // The headers still describe the bytes on the wire.
    assert!(
        response
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") && v == "gzip")
    );
    let mut decoded = Vec::new();
    while let Some(chunk) = response.next_chunk().await {
        let chunk = chunk.unwrap();
        assert!(!chunk.is_empty(), "no empty chunks");
        decoded.extend(chunk);
    }
    assert_eq!(decoded, text);

    // Without decode_content() the body arrives as sent.
    let origin = scripted_origin(parts(), Duration::from_millis(50)).await;
    let mut response = get_streaming(&client, origin).await;
    let mut raw = Vec::new();
    while let Some(chunk) = response.next_chunk().await {
        raw.extend(chunk.unwrap());
    }
    assert_eq!(raw, encoded);
}

/// An origin for uploads: it stores each request body (Content-Length or
/// chunked), reports how many bytes past the head have arrived so far, and
/// answers with the body length.
async fn upload_origin() -> (
    SocketAddr,
    tokio::sync::watch::Receiver<usize>,
    Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (progress_tx, progress) = tokio::sync::watch::channel(0usize);
    let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let stored = bodies.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let head_len = loop {
                if let Some(pos) = find(&buf, b"\r\n\r\n") {
                    break pos + 4;
                }
                if stream.read_buf(&mut buf).await.unwrap() == 0 {
                    return;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_len]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|v| v.trim().parse::<usize>().ok());
            let mut raw = buf.split_off(head_len);
            loop {
                progress_tx.send_replace(raw.len());
                let done = match length {
                    Some(length) => raw.len() >= length,
                    None => raw.ends_with(b"0\r\n\r\n"),
                };
                if done || stream.read_buf(&mut raw).await.unwrap() == 0 {
                    break;
                }
            }
            let body = if length.is_some() {
                raw
            } else {
                let mut body = Vec::new();
                let mut rest = &raw[..];
                loop {
                    let line_end = find(rest, b"\r\n").unwrap();
                    let size =
                        usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16)
                            .unwrap();
                    rest = &rest[line_end + 2..];
                    if size == 0 {
                        break;
                    }
                    body.extend_from_slice(&rest[..size]);
                    rest = &rest[size + 2..];
                }
                body
            };
            let answer = body.len().to_string();
            stored.lock().unwrap().push(body);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    (addr, progress, bodies)
}

/// Upload `pieces` through the proxy to a fresh upload origin, after the
/// head `head_for(origin)`. Before the second half goes out, the origin
/// must have received part of the body: a proxy that read the whole body
/// first would never get there. Returns the responses and the bodies the
/// origin stored.
async fn upload_through(
    proxy: &ProxyServer,
    head_for: impl Fn(SocketAddr) -> String,
    pieces: &[Vec<u8>],
) -> (Vec<Response>, Vec<Vec<u8>>) {
    let (origin, mut progress, bodies) = upload_origin().await;
    let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let (mut reader, mut writer) = stream.split();
    writer.write_all(head_for(origin).as_bytes()).await.unwrap();
    let half = pieces.len() / 2;
    for piece in &pieces[..half] {
        writer.write_all(piece).await.unwrap();
    }
    tokio::time::timeout(
        Duration::from_secs(10),
        progress.wait_for(|received| *received >= 2 * 1024 * 1024),
    )
    .await
    .expect("the origin receives the body while the client still sends it")
    .unwrap();
    for piece in &pieces[half..] {
        writer.write_all(piece).await.unwrap();
    }
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), reader.read_to_end(&mut raw))
        .await
        .expect("the proxy answers")
        .unwrap();
    let bodies = bodies.lock().unwrap().clone();
    (parse_responses(&raw), bodies)
}

#[tokio::test]
async fn large_uploads_are_streamed_through_and_arrive_intact() {
    let (proxy, _ca_dir) = start_proxy("upload", HeaderMode::Impersonate, 30).await;
    let data: Vec<u8> = (0..20 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let pieces: Vec<Vec<u8>> = data.chunks(64 * 1024).map(<[u8]>::to_vec).collect();

    // Content-Length: forwarded with the same length.
    let (responses, bodies) = upload_through(
        &proxy,
        |origin| {
            format!(
                "POST http://{origin}/upload HTTP/1.1\r\nHost: {origin}\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                data.len()
            )
        },
        &pieces,
    )
    .await;
    assert_eq!(responses[0].status(), "200");
    assert_eq!(responses[0].body, data.len().to_string().as_bytes());
    assert!(bodies[0] == data, "the body arrives byte for byte");

    // Chunked: forwarded chunked, as the length is unknown.
    let chunked: Vec<Vec<u8>> = pieces
        .iter()
        .map(|piece| {
            let mut chunk = format!("{:x}\r\n", piece.len()).into_bytes();
            chunk.extend_from_slice(piece);
            chunk.extend_from_slice(b"\r\n");
            chunk
        })
        .chain(std::iter::once(b"0\r\n\r\n".to_vec()))
        .collect();
    let (responses, bodies) = upload_through(
        &proxy,
        |origin| {
            format!(
                "PUT http://{origin}/upload HTTP/1.1\r\nHost: {origin}\r\n\
                 Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
        },
        &chunked,
    )
    .await;
    assert_eq!(responses[0].status(), "200");
    assert!(bodies[0] == data, "the body arrives byte for byte");

    proxy.shutdown();
}

#[tokio::test]
async fn small_bodies_are_buffered_and_keep_their_length() {
    let origin = echo_origin().await;
    let (proxy, _ca_dir) = start_proxy("small-body", HeaderMode::Impersonate, 10).await;
    // A chunked body under the buffering limit goes out with a length.
    let request = format!(
        "POST http://{origin}/form HTTP/1.1\r\nHost: {origin}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    let echoed = String::from_utf8_lossy(&responses[0].body).to_ascii_lowercase();
    assert!(echoed.contains("\r\ncontent-length: 9\r\n"), "{echoed}");
    assert!(!echoed.contains("transfer-encoding"), "{echoed}");
    assert!(echoed.ends_with("\r\n\r\nwikipedia"), "{echoed}");
    proxy.shutdown();
}

#[tokio::test]
async fn connections_beyond_the_cap_wait_for_a_free_slot() {
    let origin = echo_origin().await;
    let ca_dir = temp_ca_dir("connection-cap");
    let proxy = ProxyServer::start(ProxyServerConfig {
        ca_dir: Some(ca_dir.path().to_string_lossy().into_owned()),
        max_connections: 1,
        ..ProxyServerConfig::default()
    })
    .await
    .expect("proxy should start");

    // Connection A occupies the only slot: an incomplete request line never lets its handler
    // task finish, so it never releases its permit on its own.
    let mut a = TcpStream::connect(proxy.local_addr()).await.unwrap();
    a.write_all(b"GET").await.unwrap();
    // Give the accept loop time to actually accept A and spawn its handler before B connects:
    // local loopback accept is normally sub-millisecond, this only bounds against scheduler
    // noise, not a race the test itself needs to win.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Connection B: accepted at the TCP/kernel level (the backlog doesn't need our accept_loop
    // to be polling), but its bytes sit unread since the loop is waiting for a permit and never
    // reaches listener.accept() again.
    let mut b = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let request =
        format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    b.write_all(request.as_bytes()).await.unwrap();

    let mut byte = [0u8; 1];
    let premature = tokio::time::timeout(Duration::from_millis(300), b.read(&mut byte)).await;
    assert!(
        premature.is_err(),
        "B must not be served while the only slot is held by A"
    );

    // A's connection closes without ever completing a request head: the proxy answers 400 and
    // ends the task, freeing its permit for the accept loop to pick up B.
    drop(a);
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), b.read_to_end(&mut raw))
        .await
        .expect("B should be served once a slot frees up")
        .unwrap();
    assert!(
        raw.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&raw)
    );

    proxy.shutdown();
}

#[tokio::test]
async fn non_loopback_listen_addr_is_refused_by_default_but_can_be_allowed() {
    // 192.0.2.1 (TEST-NET-1) is no address of this machine: without the opt-in the refusal comes
    // before any bind, with it the bind itself fails. Nothing listens on a reachable interface.
    let ca_dir = temp_ca_dir("non-loopback");
    let start = |allow_non_loopback| {
        ProxyServer::start(ProxyServerConfig {
            listen_addr: "192.0.2.1:0".to_string(),
            ca_dir: Some(ca_dir.path().to_string_lossy().into_owned()),
            allow_non_loopback,
            ..ProxyServerConfig::default()
        })
    };
    let Err(refused) = start(false).await else {
        panic!("a non-loopback address must be refused without allow_non_loopback");
    };
    assert_eq!(refused.code(), "PROXY_ERROR", "{refused}");
    assert!(refused.to_string().contains("loopback"), "{refused}");
    let Err(allowed) = start(true).await else {
        panic!("192.0.2.1 is not a local address");
    };
    assert_eq!(allowed.code(), "IO_ERROR", "{allowed}");
}

fn basic_auth(user: &str, pass: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
}

#[tokio::test]
async fn proxy_authorization_is_required_when_configured() {
    let origin = echo_origin().await;
    let ca_dir = temp_ca_dir("auth");
    let proxy = ProxyServer::start(ProxyServerConfig {
        ca_dir: Some(ca_dir.path().to_string_lossy().into_owned()),
        auth: Some(ProxyServerAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
        ..ProxyServerConfig::default()
    })
    .await
    .expect("proxy should start");

    // No credentials: 407, with the challenge header, and the connection closes.
    let request =
        format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses[0].status(), "407");
    assert!(responses[0].has_header("proxy-authenticate: basic realm=\"koon\""));

    // Wrong credentials: also 407.
    let request = format!(
        "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {}\r\n\
         Connection: close\r\n\r\n",
        basic_auth("user", "wrong")
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses[0].status(), "407");

    // Correct credentials: forwarded as normal.
    let request = format!(
        "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {}\r\n\
         Connection: close\r\n\r\n",
        basic_auth("user", "pass")
    );
    let responses = exchange(&proxy, request.as_bytes()).await;
    assert_eq!(responses[0].status(), "200");

    proxy.shutdown();
}
