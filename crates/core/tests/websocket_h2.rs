//! Offline tests of WebSockets over HTTP/2 (RFC 8441) against a local TLS
//! server for `ws.koon.test` that speaks h2 (with or without
//! `SETTINGS_ENABLE_CONNECT_PROTOCOL`) and HTTP/1.1: which connection a
//! socket takes, the ALPN of a new one, the extended CONNECT's frames and
//! headers as captured from Chrome 153 and Firefox 156, messages both ways,
//! and how the stream ends.

mod common;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use btls::ssl::{AlpnError, Ssl, SslAcceptor};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use koon_core::profile::Os;
use koon_core::{BrowserProfile, Chrome, Client, Firefox, Safari, WsMessage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tungstenite::protocol::Role;

const HOST: &str = "ws.koon.test";
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const WINDOW_UPDATE: u8 = 0x8;

/// What the server offers.
#[derive(Clone, Copy)]
struct Config {
    /// Offer h2 in ALPN (else only http/1.1).
    h2: bool,
    /// Send `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
    extended_connect: bool,
    /// End the stream with the Close frame the server sends (in the same
    /// DATA frame); otherwise it never ends it.
    end_stream: bool,
}

/// A frame the client sent.
#[derive(Debug, Clone, PartialEq)]
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
    at: Instant,
}

/// A request the server got: `:method`, `:protocol`, the URI, and the
/// regular headers in wire order (HTTP/1.1: name casing as sent, the
/// request line as the method).
#[derive(Debug, Clone, PartialEq)]
struct Request {
    method: String,
    protocol: Option<String>,
    uri: String,
    headers: Vec<(String, String)>,
}

/// One TCP connection.
#[derive(Debug, Default, Clone, PartialEq)]
struct Conn {
    /// ALPN protocols of the ClientHello.
    alpn: Vec<String>,
    /// Whether the ClientHello carries ALPS.
    alps: bool,
    negotiated: String,
    frames: Vec<Frame>,
    requests: Vec<Request>,
    /// WebSocket messages the server got, per stream (0 over HTTP/1.1).
    messages: Vec<(u32, String)>,
}

type Log = Arc<Mutex<Vec<Conn>>>;

fn with_conn(log: &Log, i: usize, f: impl FnOnce(&mut Conn)) {
    f(&mut log.lock().unwrap()[i]);
}

/// Records what is read through it: the ClientHello under TLS, the HTTP/2
/// frames above it.
struct Tap<S> {
    inner: S,
    seen: Arc<Mutex<Vec<(Instant, Vec<u8>)>>>,
    /// Called synchronously right after new bytes are appended to `seen`, so
    /// a caller can keep a derived view (parsed HTTP/2 frames) exactly
    /// current instead of re-deriving it on a timer and racing how long
    /// that takes.
    on_read: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.seen
                .lock()
                .unwrap()
                .push((Instant::now(), buf.filled()[before..].to_vec()));
            if let Some(on_read) = &this.on_read {
                on_read();
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The extensions of the ClientHello at the start of `bytes`.
fn hello_extensions(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let body = &bytes[5 + 4..];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    p += 2 + u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 1 + body[p] as usize;
    let end = p + 2 + u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let mut out = Vec::new();
    while p + 4 <= end {
        let ty = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        out.push((ty, body[p + 4..p + 4 + len].to_vec()));
        p += 4 + len;
    }
    out
}

/// The protocol names of an ALPN extension.
fn alpn_names(ext: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 2;
    while p < ext.len() {
        let n = ext[p] as usize;
        out.push(String::from_utf8_lossy(&ext[p + 1..p + 1 + n]).into_owned());
        p += 1 + n;
    }
    out
}

/// Split the client's HTTP/2 bytes (after the preface) into frames.
fn frames(chunks: &[(Instant, Vec<u8>)]) -> Vec<Frame> {
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut preface = false;
    for (at, chunk) in chunks {
        buf.extend_from_slice(chunk);
        if !preface {
            if buf.len() < PREFACE.len() {
                continue;
            }
            buf.drain(..PREFACE.len());
            preface = true;
        }
        while buf.len() >= 9 {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < 9 + len {
                break;
            }
            out.push(Frame {
                kind: buf[3],
                flags: buf[4],
                stream: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff,
                payload: buf[9..9 + len].to_vec(),
                at: *at,
            });
            buf.drain(..9 + len);
        }
    }
    out
}

/// A server frame of a WebSocket (RFC 6455 §5.2), unmasked.
fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mut out = vec![0x80 | opcode, payload.len() as u8];
    out.extend_from_slice(payload);
    out
}

/// Complete client frames at the start of `buf` (masked): (opcode,
/// payload). Consumes them.
fn client_frames(buf: &mut Vec<u8>) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    loop {
        if buf.len() < 2 {
            return out;
        }
        let mut len = (buf[1] & 0x7f) as usize;
        let mut p = 2;
        if len == 126 {
            if buf.len() < 4 {
                return out;
            }
            len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            p = 4;
        }
        assert!(buf[1] & 0x80 != 0, "client frames are masked");
        if buf.len() < p + 4 + len {
            return out;
        }
        let mask = [buf[p], buf[p + 1], buf[p + 2], buf[p + 3]];
        let payload: Vec<u8> = buf[p + 4..p + 4 + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        out.push((buf[0] & 0x0f, payload));
        buf.drain(..p + 4 + len);
    }
}

async fn serve(config: Config, acceptor: Arc<SslAcceptor>, tcp: TcpStream, log: Log) {
    let index = {
        let mut conns = log.lock().unwrap();
        conns.push(Conn::default());
        conns.len() - 1
    };
    let hello = Arc::new(Mutex::new(Vec::new()));
    let tcp = Tap {
        inner: tcp,
        seen: hello.clone(),
        on_read: None,
    };
    let ssl = Ssl::new(acceptor.context()).unwrap();
    let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
    let accepted = Pin::new(&mut tls).accept().await;
    let bytes: Vec<u8> = hello
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, b)| b.clone())
        .collect();
    let exts = hello_extensions(&bytes);
    with_conn(&log, index, |c| {
        c.alpn = exts
            .iter()
            .find(|(t, _)| *t == 0x0010)
            .map(|(_, e)| alpn_names(e))
            .unwrap_or_default();
        c.alps = exts.iter().any(|(t, _)| matches!(*t, 0x4469 | 0x44cd));
    });
    if accepted.is_err() {
        return;
    }
    let negotiated = tls
        .ssl()
        .selected_alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default();
    with_conn(&log, index, |c| c.negotiated = negotiated.clone());
    if negotiated == "h2" {
        serve_h2(config, tls, index, log).await;
    } else {
        serve_h1(tls, index, log).await;
    }
}

async fn serve_h2<S>(config: Config, tls: S, index: usize, log: Log)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen: Arc<Mutex<Vec<(Instant, Vec<u8>)>>> = Arc::default();
    // Re-parse the frame log in the same poll_read that reads new bytes, so
    // it is exactly current for whoever next observes an effect of those
    // bytes, instead of catching up on its own schedule.
    let on_read = {
        let (log, seen) = (log.clone(), seen.clone());
        Arc::new(move || {
            let parsed = frames(&seen.lock().unwrap());
            with_conn(&log, index, |c| c.frames = parsed);
        })
    };
    let io = Tap {
        inner: tls,
        seen: seen.clone(),
        on_read: Some(on_read),
    };
    let mut builder = http2::server::Builder::new();
    if config.extended_connect {
        builder.enable_connect_protocol();
    }
    let Ok(mut conn) = builder.handshake::<_, Bytes>(io).await else {
        return;
    };
    while let Some(Ok((request, respond))) = conn.accept().await {
        let log = log.clone();
        tokio::spawn(async move {
            let (parts, body) = request.into_parts();
            let protocol = parts
                .extensions
                .get::<http2::ext::Protocol>()
                .map(|p| p.as_str().to_string());
            let headers = parts
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let websocket = parts.method == http::Method::CONNECT;
            with_conn(&log, index, |c| {
                c.requests.push(Request {
                    method: parts.method.to_string(),
                    protocol,
                    uri: parts.uri.to_string(),
                    headers,
                })
            });
            if websocket {
                h2_echo(config, respond, body, index, log).await;
            } else {
                let mut respond = respond;
                let response = http::Response::builder()
                    .status(200)
                    .header("set-cookie", "session=1; Path=/; Secure")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(response, false) {
                    let _ = send.send_data(Bytes::from_static(b"ok"), true);
                }
            }
        });
    }
}

/// Echo text messages on an HTTP/2 WebSocket stream: `echo:<text>`. The
/// text `server-close` makes the server close the socket; a Close frame of
/// the client is answered.
async fn h2_echo(
    config: Config,
    mut respond: http2::server::SendResponse<Bytes>,
    mut body: http2::RecvStream,
    index: usize,
    log: Log,
) {
    let response = http::Response::builder().status(200).body(()).unwrap();
    let Ok(mut send) = respond.send_response(response, false) else {
        return;
    };
    let stream = send.stream_id().as_u32();
    let mut buf = Vec::new();
    while let Some(Ok(data)) = body.data().await {
        let _ = body.flow_control().release_capacity(data.len());
        buf.extend_from_slice(&data);
        for (opcode, payload) in client_frames(&mut buf) {
            match opcode {
                0x1 => {
                    let text = String::from_utf8(payload).unwrap();
                    with_conn(&log, index, |c| c.messages.push((stream, text.clone())));
                    if text == "server-close" {
                        let close = ws_frame(0x8, &[0x03, 0xe9]);
                        let _ = send.send_data(close.into(), config.end_stream);
                    } else {
                        let echo = ws_frame(0x1, format!("echo:{text}").as_bytes());
                        let _ = send.send_data(echo.into(), false);
                    }
                }
                0x2 => {
                    let _ = send.send_data(ws_frame(0x2, &payload).into(), false);
                }
                0x8 => {
                    with_conn(&log, index, |c| c.messages.push((stream, "<close>".into())));
                    let reply = ws_frame(0x8, &payload[..2.min(payload.len())]);
                    let _ = send.send_data(reply.into(), config.end_stream);
                }
                _ => {}
            }
        }
    }
    // Keep the stream until the connection ends, so that the client decides
    // how its half ends.
    std::future::pending::<()>().await;
}

/// An HTTP/1.1 WebSocket upgrade, then an echo.
async fn serve_h1<S>(mut tls: S, index: usize, log: Log)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let key = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    with_conn(&log, index, |c| {
        c.requests.push(Request {
            method: request_line.clone(),
            protocol: None,
            uri: String::new(),
            headers,
        })
    });
    let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if tls.write_all(response.as_bytes()).await.is_err() {
        return;
    }
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(tls, Role::Server, None).await;
    while let Some(Ok(message)) = ws.next().await {
        if let tungstenite::Message::Text(text) = message {
            with_conn(&log, index, |c| c.messages.push((0, text.clone())));
            if ws
                .send(tungstenite::Message::Text(format!("echo:{text}")))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// Start a server; returns its port and log.
async fn server(config: Config) -> (u16, Log) {
    let (cert, key) = common::leaf(HOST);
    let mut builder = common::tls_acceptor_builder(&cert, &key);
    let protocols: &'static [u8] = if config.h2 {
        b"\x02h2\x08http/1.1"
    } else {
        b"\x08http/1.1"
    };
    builder.set_alpn_select_callback(move |_, offered| {
        btls::ssl::select_next_proto(protocols, offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = Arc::new(builder.build());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let server_log = log.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve(config, acceptor.clone(), tcp, server_log.clone()));
        }
    });
    (port, log)
}

fn client(mut profile: BrowserProfile, port: u16) -> Client {
    profile.tls.danger_accept_invalid_certs = true;
    Client::builder(profile)
        .resolve(HOST, SocketAddr::from(([127, 0, 0, 1], port)))
        .build()
        .unwrap()
}

fn conns(log: &Log) -> Vec<Conn> {
    log.lock().unwrap().clone()
}

/// Wait until `check` holds for the log, at most 5 s.
async fn wait_for(log: &Log, check: impl Fn(&[Conn]) -> bool) {
    for _ in 0..500 {
        if check(&log.lock().unwrap()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out: {:#?}", conns(log));
}

/// Wait until the log stops changing for two consecutive 20 ms polls (at
/// most 2 s), then return it — for asserting that nothing more arrives on a
/// connection, where there is no positive event left to poll for (the
/// frame log is a snapshot a background task refreshes every 10 ms, so a
/// quiet log is the closest thing to "done").
async fn settle(log: &Log) -> Vec<Conn> {
    let mut last = conns(log);
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let now = conns(log);
        if now == last {
            return now;
        }
        last = now;
    }
    last
}

fn names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(k, _)| k.as_str()).collect()
}

/// The HPACK representation of each field of a HEADERS frame: `idxN`,
/// `incN`, `noidxN`, `neverN` (N the name index, 0 for a literal name) with
/// `/H` or `/raw` for the value's string encoding.
fn representations(f: &Frame) -> Vec<String> {
    let block = &f.payload[if f.flags & 0x20 != 0 { 5 } else { 0 }..];
    let mut out = Vec::new();
    let mut i = 0;
    let int = |i: &mut usize, prefix: u32| -> usize {
        let mask = (1usize << prefix) - 1;
        let mut v = block[*i] as usize & mask;
        *i += 1;
        if v == mask {
            let mut m = 0;
            loop {
                let b = block[*i] as usize;
                *i += 1;
                v += (b & 0x7f) << m;
                m += 7;
                if b & 0x80 == 0 {
                    break;
                }
            }
        }
        v
    };
    let string = |i: &mut usize| -> &'static str {
        let huffman = block[*i] & 0x80 != 0;
        let len = int(i, 7);
        *i += len;
        if huffman { "H" } else { "raw" }
    };
    while i < block.len() {
        let b = block[i];
        let (kind, prefix) = if b & 0x80 != 0 {
            out.push(format!("idx{}", int(&mut i, 7)));
            continue;
        } else if b & 0x40 != 0 {
            ("inc", 6)
        } else if b & 0x20 != 0 {
            out.push(format!("size{}", int(&mut i, 5)));
            continue;
        } else if b & 0x10 != 0 {
            ("never", 4)
        } else {
            ("noidx", 4)
        };
        let index = int(&mut i, prefix);
        if index == 0 {
            string(&mut i);
        }
        out.push(format!("{kind}{index}/{}", string(&mut i)));
    }
    out
}

/// The priority block of a HEADERS frame: (exclusive, dependency, weight).
fn priority(f: &Frame) -> Option<(bool, u32, u16)> {
    (f.flags & 0x20 != 0).then(|| {
        let p = &f.payload[if f.flags & 0x8 != 0 { 1 } else { 0 }..];
        let dep = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        (dep >> 31 == 1, dep & 0x7fff_ffff, u16::from(p[4]) + 1)
    })
}

/// The frames the client sent on `stream`.
fn on_stream(conn: &Conn, stream: u32) -> Vec<Frame> {
    conn.frames
        .iter()
        .filter(|f| f.stream == stream)
        .cloned()
        .collect()
}

const H2_ECP: Config = Config {
    h2: true,
    extended_connect: true,
    end_stream: true,
};

async fn echo(ws: &koon_core::WebSocket, text: &str) {
    ws.send_text(text).await.unwrap();
    match ws.receive().await.unwrap() {
        Some(WsMessage::Text(t)) => assert_eq!(t, format!("echo:{text}")),
        other => panic!("unexpected {other:?}"),
    }
}

/// Chrome 153 opens the socket as an extended CONNECT on the HTTP/2
/// connection of its requests, with the captured layout, and forgets the
/// stream once the server ended it after the closing handshake.
#[tokio::test]
async fn chrome_uses_its_h2_connection() {
    let (port, log) = server(H2_ECP).await;
    let client = client(Chrome::version(153, Os::Windows).unwrap(), port);
    let origin = format!("https://{HOST}:{port}");
    assert_eq!(
        client.get(&format!("{origin}/")).await.unwrap().version,
        "h2"
    );

    let ws = client
        .websocket(&format!("wss://{HOST}:{port}/chat?room=1"))
        .await
        .unwrap();
    echo(&ws, "hello").await;
    ws.send_binary(&[1, 2, 3]).await.unwrap();
    match ws.receive().await.unwrap() {
        Some(WsMessage::Binary(b)) => assert_eq!(b, [1, 2, 3]),
        other => panic!("unexpected {other:?}"),
    }
    ws.close(Some(1000), None).await.unwrap();
    assert!(ws.receive().await.unwrap().is_none());
    // A request after it shares the connection too: on the same ordered
    // TCP/TLS byte stream, its response only comes back once the server has
    // read (and the frame log therefore already carries) everything the
    // earlier WebSocket exchange sent.
    client.get(&format!("{origin}/after")).await.unwrap();

    let conns = conns(&log);
    assert_eq!(conns.len(), 1, "one connection: {conns:#?}");
    let conn = &conns[0];
    let request = &conn.requests[1];
    assert_eq!(request.method, "CONNECT");
    assert_eq!(request.protocol.as_deref(), Some("websocket"));
    assert_eq!(request.uri, format!("https://{HOST}:{port}/chat?room=1"));
    assert_eq!(
        names(&request.headers),
        [
            "pragma",
            "cache-control",
            "user-agent",
            "origin",
            "sec-websocket-version",
            "accept-encoding",
            "accept-language",
            "cookie"
        ]
    );
    let value = |name: &str| {
        request
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(value("origin"), Some(origin.as_str()));
    assert_eq!(value("cookie"), Some("session=1"));
    assert_eq!(value("sec-websocket-version"), Some("13"));

    // HEADERS on stream 3 without END_STREAM, LOWEST priority (weight 147,
    // exclusive), pseudo-header fields as Chrome 153 encodes them: :method
    // CONNECT, :authority (indexed since the request), :scheme, :path, then
    // :protocol as a literal with a new name, none of them but :authority
    // indexed.
    let frames = on_stream(conn, 3);
    let headers = &frames[0];
    assert_eq!(headers.kind, HEADERS);
    assert_eq!(headers.flags & 0x1, 0);
    assert_eq!(priority(headers), Some((true, 0, 147)));
    let reps = representations(headers);
    assert_eq!(reps[0], "noidx2/raw", "{reps:?}");
    assert!(reps[1].starts_with("idx"), "{reps:?}");
    assert_eq!(reps[2..5], ["idx7", "noidx4/H", "noidx0/H"], "{reps:?}");

    // One DATA frame per WebSocket frame: text, binary, Close; none ends the
    // stream, and after the server's END_STREAM nothing follows.
    let data: Vec<&Frame> = frames.iter().filter(|f| f.kind == DATA).collect();
    assert_eq!(data.len(), 3, "{frames:#?}");
    assert!(data.iter().all(|f| f.flags & 0x1 == 0));
    assert!(!frames.iter().any(|f| f.kind == RST_STREAM));
    assert_eq!(conn.messages, [(3, "hello".into()), (3, "<close>".into())]);
}

/// Chrome 154 answers the server's END_STREAM with an empty DATA frame that
/// ends its half.
#[tokio::test]
async fn chrome_154_answers_end_stream() {
    let (port, log) = server(H2_ECP).await;
    let client = client(Chrome::version(154, Os::Windows).unwrap(), port);
    client
        .get(&format!("https://{HOST}:{port}/"))
        .await
        .unwrap();
    let ws = client
        .websocket(&format!("wss://{HOST}:{port}/"))
        .await
        .unwrap();
    ws.close(Some(1000), None).await.unwrap();
    assert!(ws.receive().await.unwrap().is_none());
    wait_for(&log, |c| {
        on_stream(&c[0], 3)
            .iter()
            .any(|f| f.kind == DATA && f.flags & 0x1 != 0)
    })
    .await;
    let frames = on_stream(&conns(&log)[0], 3);
    let end = frames.last().unwrap();
    assert_eq!((end.kind, end.flags, end.payload.len()), (DATA, 0x1, 0));
    assert!(!frames.iter().any(|f| f.kind == RST_STREAM));
}

/// The data frames the client sent on `stream` once one of them ended the
/// stream, and whether it reset the stream.
async fn client_data_until_end(log: &Log, stream: u32) -> (Vec<Frame>, bool) {
    wait_for(log, |c| {
        on_stream(&c[0], stream)
            .iter()
            .any(|f| f.kind == DATA && f.flags & 0x1 != 0)
    })
    .await;
    let conns = settle(log).await;
    let frames = on_stream(&conns[0], stream);
    let reset = frames.iter().any(|f| f.kind == RST_STREAM);
    (
        frames.into_iter().filter(|f| f.kind == DATA).collect(),
        reset,
    )
}

/// Chrome 155 ends its half with the Close frame (captured): the DATA frame
/// of its Close carries END_STREAM and nothing follows the server's
/// END_STREAM; a server that closes first gets a Close reply carrying
/// END_STREAM.
#[tokio::test]
async fn chrome_155_ends_its_half_with_the_close_frame() {
    let chrome155 = || Chrome::version(155, Os::Windows).unwrap();

    // The client closes.
    let (port, log) = server(H2_ECP).await;
    let http = client(chrome155(), port);
    http.get(&format!("https://{HOST}:{port}/")).await.unwrap();
    let ws = http
        .websocket(&format!("wss://{HOST}:{port}/"))
        .await
        .unwrap();
    echo(&ws, "hello").await;
    ws.close(Some(1000), None).await.unwrap();
    assert!(ws.receive().await.unwrap().is_none());
    let (data, reset) = client_data_until_end(&log, 3).await;
    assert_eq!(data.len(), 2, "{data:#?}");
    assert_eq!(data[0].flags & 0x1, 0);
    assert_eq!((data[1].flags & 0x1, data[1].payload[0]), (0x1, 0x88));
    assert!(!reset);

    // The server closes and ends the stream.
    let (port, log) = server(H2_ECP).await;
    let http = client(chrome155(), port);
    http.get(&format!("https://{HOST}:{port}/")).await.unwrap();
    let ws = http
        .websocket(&format!("wss://{HOST}:{port}/"))
        .await
        .unwrap();
    ws.send_text("server-close").await.unwrap();
    assert!(ws.receive().await.unwrap().is_none());
    let (data, reset) = client_data_until_end(&log, 3).await;
    assert_eq!(data.len(), 2, "{data:#?}");
    assert_eq!((data[1].flags & 0x1, data[1].payload[0]), (0x1, 0x88));
    assert!(!reset);
}

/// When the server does not end the stream after the closing handshake,
/// Chrome resets it with CANCEL after 2 s (155 too, whose Close frame ended
/// its half), Firefox after 1 s.
#[tokio::test]
async fn unended_stream_is_reset_after_the_linger_time() {
    for (profile, linger) in [
        (Chrome::version(153, Os::Windows).unwrap(), 2000),
        (Chrome::version(155, Os::Windows).unwrap(), 2000),
        (Firefox::latest(), 1000),
    ] {
        let (port, log) = server(Config {
            end_stream: false,
            ..H2_ECP
        })
        .await;
        let client = client(profile, port);
        client
            .get(&format!("https://{HOST}:{port}/"))
            .await
            .unwrap();
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/"))
            .await
            .unwrap();
        ws.close(Some(1000), None).await.unwrap();
        assert!(ws.receive().await.unwrap().is_none());
        let closed = Instant::now();
        let reset = |c: &[Conn]| {
            c.iter()
                .flat_map(|c| c.frames.iter())
                .find(|f| f.kind == RST_STREAM)
                .cloned()
        };
        wait_for(&log, |c| reset(c).is_some()).await;
        let rst = reset(&conns(&log)).unwrap();
        assert_eq!(rst.payload, 8u32.to_be_bytes(), "CANCEL");
        let after = rst.at.duration_since(closed).as_millis();
        assert!(
            (linger - 300..linger + 700).contains(&after),
            "reset after {after} ms, expected about {linger}"
        );
    }
}

/// Without SETTINGS_ENABLE_CONNECT_PROTOCOL, Chrome opens a new connection
/// that offers only http/1.1 (no ALPS) and upgrades on it; so it does for a
/// socket before any request, even to a server that enables extended
/// CONNECT.
#[tokio::test]
async fn chrome_falls_back_to_a_new_http1_connection() {
    for (config, request_first) in [
        (
            Config {
                extended_connect: false,
                ..H2_ECP
            },
            true,
        ),
        (H2_ECP, false),
    ] {
        let (port, log) = server(config).await;
        let client = client(Chrome::version(153, Os::Windows).unwrap(), port);
        if request_first {
            client
                .get(&format!("https://{HOST}:{port}/"))
                .await
                .unwrap();
        }
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/ws"))
            .await
            .unwrap();
        echo(&ws, "hi").await;

        let conns = conns(&log);
        let last = conns.last().unwrap();
        assert_eq!(conns.len(), if request_first { 2 } else { 1 });
        assert_eq!(last.alpn, ["http/1.1"]);
        assert!(!last.alps);
        assert_eq!(last.negotiated, "http/1.1");
        let upgrade = &last.requests[0];
        assert_eq!(upgrade.method, "GET /ws HTTP/1.1");
        assert_eq!(names(&upgrade.headers)[..2], ["Host", "Connection"]);
        if request_first {
            // The request's connection offered h2 with ALPS.
            assert_eq!(conns[0].alpn, ["h2", "http/1.1"]);
            assert!(conns[0].alps);
        }
    }
}

/// Firefox opens a connection of its own for WebSockets, offering h2 and
/// http/1.1, and runs this and later sockets over it as extended CONNECTs
/// with the captured layout.
#[tokio::test]
async fn firefox_uses_its_own_h2_connection() {
    let (port, log) = server(H2_ECP).await;
    let client = client(Firefox::latest(), port);
    client
        .get(&format!("https://{HOST}:{port}/"))
        .await
        .unwrap();
    for _ in 0..2 {
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/chat"))
            .await
            .unwrap();
        echo(&ws, "hello").await;
        ws.close(Some(1000), None).await.unwrap();
        assert!(ws.receive().await.unwrap().is_none());
    }

    let conns = conns(&log);
    assert_eq!(conns.len(), 2, "{conns:#?}");
    let conn = &conns[1];
    assert_eq!(conn.alpn, ["h2", "http/1.1"]);
    assert_eq!(conn.negotiated, "h2");
    assert_eq!(conn.requests.len(), 2);
    let request = &conn.requests[0];
    assert_eq!(request.method, "CONNECT");
    assert_eq!(request.protocol.as_deref(), Some("websocket"));
    assert_eq!(
        names(&request.headers),
        [
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-websocket-version",
            "origin",
            "cookie",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "pragma",
            "cache-control"
        ]
    );

    let headers: Vec<&Frame> = conn.frames.iter().filter(|f| f.kind == HEADERS).collect();
    for h in &headers {
        assert_eq!(h.flags & 0x1, 0);
        assert_eq!(priority(h), Some((false, 0, 22)));
        // The stream's WINDOW_UPDATE follows its HEADERS.
        assert!(
            conn.frames
                .iter()
                .any(|f| f.kind == WINDOW_UPDATE && f.stream == h.stream)
        );
    }
    // :method CONNECT, :path, :authority, :scheme, :protocol as Firefox 156
    // encodes them on a new connection: literals naming the last static
    // entry of their name, :path never indexed, :protocol a new name.
    let reps: Vec<String> = representations(headers[0])
        .into_iter()
        .filter(|r| !r.starts_with("size"))
        .collect();
    assert_eq!(
        reps[..5],
        ["inc3/H", "noidx5/H", "inc1/H", "idx7", "inc0/H"],
        "{reps:?}"
    );
    // No END_STREAM or RST_STREAM from the client.
    assert!(
        !conn
            .frames
            .iter()
            .any(|f| f.kind == RST_STREAM || (f.kind == DATA && f.flags & 0x1 != 0))
    );
}

/// A server whose h2 lacks extended CONNECT: Firefox keeps that connection
/// and upgrades on a new one offering only http/1.1, as it does right away
/// for the next socket.
#[tokio::test]
async fn firefox_falls_back_without_extended_connect() {
    let (port, log) = server(Config {
        extended_connect: false,
        ..H2_ECP
    })
    .await;
    let client = client(Firefox::latest(), port);
    for _ in 0..2 {
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/"))
            .await
            .unwrap();
        echo(&ws, "hi").await;
    }
    let conns = conns(&log);
    let alpn: Vec<(Vec<String>, String)> = conns
        .iter()
        .map(|c| (c.alpn.clone(), c.negotiated.clone()))
        .collect();
    let h2 = vec!["h2".to_string(), "http/1.1".to_string()];
    let h1 = vec!["http/1.1".to_string()];
    assert_eq!(
        alpn,
        [
            (h2, "h2".to_string()),
            (h1.clone(), "http/1.1".to_string()),
            (h1, "http/1.1".to_string())
        ]
    );
    assert!(conns[0].requests.is_empty());
}

/// A server that picks http/1.1 on Firefox's new connection gets the
/// upgrade on it.
#[tokio::test]
async fn firefox_upgrades_on_a_new_http1_connection() {
    let (port, log) = server(Config {
        h2: false,
        ..H2_ECP
    })
    .await;
    let client = client(Firefox::latest(), port);
    let ws = client
        .websocket(&format!("wss://{HOST}:{port}/"))
        .await
        .unwrap();
    echo(&ws, "hi").await;
    let conns = conns(&log);
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].alpn, ["h2", "http/1.1"]);
    assert_eq!(conns[0].negotiated, "http/1.1");
}

/// When the server's Close frame ends the stream, Chrome up to 153 and
/// Firefox send no reply: END_STREAM ends the connection for them.
#[tokio::test]
async fn no_close_reply_after_end_stream() {
    for profile in [
        Chrome::version(153, Os::Windows).unwrap(),
        Firefox::latest(),
    ] {
        let (port, log) = server(H2_ECP).await;
        let client = client(profile, port);
        client
            .get(&format!("https://{HOST}:{port}/"))
            .await
            .unwrap();
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/"))
            .await
            .unwrap();
        ws.send_text("server-close").await.unwrap();
        // The client observing its stream end (END_STREAM) is downstream of
        // the server having read and answered "server-close", so the frame
        // log (updated synchronously as the server reads) is already
        // current here — no further wait needed, deterministically.
        assert!(ws.receive().await.unwrap().is_none());
        let conns = conns(&log);
        let conn = conns.last().unwrap();
        let stream = conn
            .frames
            .iter()
            .rev()
            .find(|f| f.kind == HEADERS)
            .unwrap()
            .stream;
        let data: Vec<Frame> = on_stream(conn, stream)
            .into_iter()
            .filter(|f| f.kind != HEADERS && f.kind != WINDOW_UPDATE)
            .collect();
        // Only the text frame; no Close reply, no END_STREAM, no reset.
        assert_eq!(data.len(), 1, "{data:#?}");
        assert_eq!(conn.messages.last().unwrap().1, "server-close");
    }
}

/// Safari up to macOS 15 and iOS 18 never uses HTTP/2 for WebSockets: a new
/// connection offering only http/1.1, with the captured header order.
#[tokio::test]
async fn safari_18_upgrades_over_http1() {
    for (profile, first) in [
        (
            Safari::version("18.3", Os::MacOS).unwrap(),
            ["Host", "Upgrade"],
        ),
        (
            Safari::version("17.0", Os::Ios).unwrap(),
            ["Host", "Pragma"],
        ),
    ] {
        let (port, log) = server(H2_ECP).await;
        let client = client(profile, port);
        client
            .get(&format!("https://{HOST}:{port}/"))
            .await
            .unwrap();
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/"))
            .await
            .unwrap();
        echo(&ws, "hi").await;
        let conns = conns(&log);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[1].negotiated, "http/1.1");
        assert_eq!(conns[1].alpn, ["http/1.1"]);
        assert_eq!(names(&conns[1].requests[0].headers)[..2], first);
    }
}

/// Safari from macOS 26 and iOS 26 on opens the socket as an extended
/// CONNECT on the HTTP/2 connection of its requests, with the captured
/// layout, and resets the stream with NO_ERROR right after the closing
/// handshake (captured from Safari 26.6.2 and 27.0 on macOS, 26.5 on iOS).
#[tokio::test]
async fn safari_26_uses_its_h2_connection() {
    for (profile, end_stream) in [
        (Safari::latest(), true),
        (Safari::version("26.5", Os::Ios).unwrap(), false),
    ] {
        let (port, log) = server(Config {
            end_stream,
            ..H2_ECP
        })
        .await;
        let client = client(profile, port);
        client
            .get(&format!("https://{HOST}:{port}/"))
            .await
            .unwrap();
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/chat"))
            .await
            .unwrap();
        echo(&ws, "hello").await;
        ws.close(Some(1000), None).await.unwrap();
        assert!(ws.receive().await.unwrap().is_none());
        wait_for(&log, |c| {
            on_stream(&c[0], 3).iter().any(|f| f.kind == RST_STREAM)
        })
        .await;

        let conns = conns(&log);
        assert_eq!(conns.len(), 1, "one connection: {conns:#?}");
        let conn = &conns[0];
        let request = &conn.requests[1];
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.protocol.as_deref(), Some("websocket"));
        assert_eq!(
            names(&request.headers),
            [
                "origin",
                "pragma",
                "sec-fetch-site",
                "sec-websocket-version",
                "sec-fetch-mode",
                "user-agent",
                "cache-control",
                "sec-fetch-dest",
                "accept",
                "accept-language",
                "priority",
                "accept-encoding",
                "cookie"
            ]
        );
        // No priority block; :method CONNECT and :protocol indexed.
        let frames = on_stream(conn, 3);
        let headers = &frames[0];
        assert_eq!(headers.kind, HEADERS);
        assert_eq!(headers.flags, 0x4);
        let reps = representations(headers);
        assert_eq!(reps[0], "inc2/raw", "{reps:?}");
        assert!(reps[2].starts_with("idx"), "{reps:?}");
        assert_eq!(reps[3], "noidx4/H", "{reps:?}");
        assert_eq!(reps[4], "inc0/H", "{reps:?}");
        assert_eq!(reps.last().map(String::as_str), Some("never32/H"));
        // Text and Close in a DATA frame each, then RST_STREAM(NO_ERROR),
        // whether the server ended the stream or not.
        let data: Vec<&Frame> = frames.iter().filter(|f| f.kind == DATA).collect();
        assert_eq!(data.len(), 2, "{frames:#?}");
        assert!(data.iter().all(|f| f.flags & 0x1 == 0));
        let last = frames.last().unwrap();
        assert_eq!((last.kind, last.payload.clone()), (RST_STREAM, vec![0; 4]));
    }
}

/// Safari answers the server's Close frame in three DATA frames (header,
/// masking key, payload), also after the server's END_STREAM, then resets
/// the stream with NO_ERROR.
#[tokio::test]
async fn safari_26_answers_a_server_close_in_three_frames() {
    for end_stream in [true, false] {
        let (port, log) = server(Config {
            end_stream,
            ..H2_ECP
        })
        .await;
        let client = client(Safari::latest(), port);
        client
            .get(&format!("https://{HOST}:{port}/"))
            .await
            .unwrap();
        let ws = client
            .websocket(&format!("wss://{HOST}:{port}/"))
            .await
            .unwrap();
        ws.send_text("server-close").await.unwrap();
        assert!(ws.receive().await.unwrap().is_none());
        wait_for(&log, |c| {
            on_stream(&c[0], 3).iter().any(|f| f.kind == RST_STREAM)
        })
        .await;
        let frames = on_stream(&conns(&log)[0], 3);
        let tail: Vec<(u8, usize)> = frames
            .iter()
            .filter(|f| f.kind == DATA || f.kind == RST_STREAM)
            .map(|f| (f.kind, f.payload.len()))
            .collect();
        // The text frame, the reply to Close 1001 (2 + 4 + 2 bytes), the reset.
        assert_eq!(
            tail,
            [(DATA, 18), (DATA, 2), (DATA, 4), (DATA, 2), (RST_STREAM, 4)],
            "end_stream {end_stream}: {frames:#?}"
        );
        assert_eq!(frames.last().unwrap().payload, [0; 4]);
    }
}

/// Without extended CONNECT, Safari 26 opens a new connection offering only
/// http/1.1, with the captured order: Host first, the key, Connection and
/// Upgrade last.
#[tokio::test]
async fn safari_26_falls_back_to_a_new_http1_connection() {
    let (port, log) = server(Config {
        extended_connect: false,
        ..H2_ECP
    })
    .await;
    let client = client(Safari::latest(), port);
    client
        .get(&format!("https://{HOST}:{port}/"))
        .await
        .unwrap();
    let ws = client
        .websocket(&format!("wss://{HOST}:{port}/ws"))
        .await
        .unwrap();
    echo(&ws, "hi").await;
    let conns = conns(&log);
    let last = conns.last().unwrap();
    assert_eq!(conns.len(), 2);
    assert_eq!(last.alpn, ["http/1.1"]);
    let upgrade = names(&last.requests[0].headers);
    assert_eq!(upgrade[..2], ["Host", "Origin"]);
    assert_eq!(
        upgrade[upgrade.len() - 3..],
        ["Sec-WebSocket-Key", "Connection", "Upgrade"]
    );
}

/// libwebsockets.org enables extended CONNECT (and starts streams with a
/// window of 0): after a request, Chrome's and Firefox's profiles open its
/// `dumb-increment-protocol` demo over HTTP/2 and get its counter.
#[tokio::test]
#[ignore = "network: libwebsockets.org"]
async fn libwebsockets_org_over_h2() {
    for profile in [Chrome::latest(), Firefox::latest()] {
        let client = Client::new(profile).unwrap();
        let response = client.get("https://libwebsockets.org/").await.unwrap();
        assert_eq!(response.version, "h2");
        let ws = client
            .websocket_with_headers(
                "wss://libwebsockets.org/",
                vec![(
                    "Sec-WebSocket-Protocol".into(),
                    "dumb-increment-protocol".into(),
                )],
            )
            .await
            .unwrap();
        for _ in 0..3 {
            match ws.receive().await.unwrap() {
                Some(WsMessage::Text(t)) => {
                    t.trim().parse::<u64>().unwrap();
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        ws.close(Some(1000), None).await.unwrap();
    }
}
