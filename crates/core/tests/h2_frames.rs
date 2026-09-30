//! Offline tests of the HTTP/2 frames koon writes as Firefox and Chrome:
//! first stream ID, HEADERS priority, stream WINDOW_UPDATE, HPACK
//! representations, TLS record layout, PINGs and the close. A local TLS
//! server reads the raw frames; each TLS read returns the plaintext of one
//! record, so the reads show which frames shared a record.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::Method;
use koon_core::http2::ConnectionPing;
use koon_core::{Body, BrowserProfile, Chrome, Client, Firefox, OkHttp, RequestOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

mod common;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;

/// A frame the client sent, with the TLS record (numbered from 0) it came
/// in.
#[derive(Debug, Clone)]
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
    record: usize,
}

/// How the client's side of the connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// Still open.
    Open,
    /// close_notify, then EOF.
    CloseNotify,
    /// EOF without close_notify.
    Fin,
}

/// The server's TCP stream, counting the encrypted TLS records (content
/// type 23) that arrive. Of those, the client's Finished and every record a
/// read returns data from are accounted for; TLS consumes a close_notify
/// alert without returning data, so one more record reveals it.
struct CountRecords {
    tcp: TcpStream,
    records: Arc<AtomicUsize>,
    /// Bytes of the current record still to come, or of its header.
    header: Vec<u8>,
    remaining: usize,
}

impl AsyncRead for CountRecords {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.tcp).poll_read(cx, buf);
        for &byte in &buf.filled()[before..] {
            if this.remaining > 0 {
                this.remaining -= 1;
                continue;
            }
            this.header.push(byte);
            if this.header.len() == 5 {
                this.remaining = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
                if this.header[0] == 23 {
                    this.records.fetch_add(1, Ordering::Relaxed);
                }
                this.header.clear();
            }
        }
        polled
    }
}

impl AsyncWrite for CountRecords {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().tcp).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct Seen {
    frames: Vec<Frame>,
    /// Whether the preface came in the first record.
    preface_record: Option<usize>,
    end: Option<End>,
}

type Log = Arc<Mutex<Seen>>;

/// A minimal HTTP/2 server: it acknowledges SETTINGS and PINGs and answers
/// requests with 200, once `batch` of them arrived (to keep streams open).
async fn server(batch: usize) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let (cert, key) = common::leaf("127.0.0.1");
    let acceptor = common::h2_acceptor(&cert, &key);
    let seen = log.clone();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let records = Arc::new(AtomicUsize::new(0));
        let tcp = CountRecords {
            tcp,
            records: records.clone(),
            header: Vec::new(),
            remaining: 0,
        };
        let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
        let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut tls).accept().await.unwrap();
        // The client's Finished, then one per read with data (a read
        // returns the data of one record).
        let mut consumed = 1;
        tls.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();

        let mut buf = Vec::new();
        let mut preface = false;
        let mut waiting = Vec::new();
        let mut record = 0;
        let mut chunk = vec![0u8; 1 << 16];
        loop {
            let n = match tls.read(&mut chunk).await {
                Ok(n) if n > 0 => n,
                // EOF, with or without close_notify.
                _ => {
                    let end = if records.load(Ordering::Relaxed) > consumed {
                        End::CloseNotify
                    } else {
                        End::Fin
                    };
                    seen.lock().unwrap().end = Some(end);
                    return;
                }
            };
            consumed += 1;
            buf.extend_from_slice(&chunk[..n]);
            if !preface && buf.len() >= PREFACE.len() {
                assert_eq!(&buf[..PREFACE.len()], PREFACE);
                buf.drain(..PREFACE.len());
                preface = true;
                seen.lock().unwrap().preface_record = Some(record);
            }
            while preface && buf.len() >= 9 {
                let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
                if buf.len() < 9 + len {
                    break;
                }
                let head: Vec<u8> = buf.drain(..9 + len).collect();
                let f = Frame {
                    kind: head[3],
                    flags: head[4],
                    stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
                    payload: head[9..].to_vec(),
                    record,
                };
                match f.kind {
                    SETTINGS if f.flags & 1 == 0 => {
                        tls.write_all(&frame(SETTINGS, 1, 0, &[])).await.unwrap();
                    }
                    PING if f.flags & 1 == 0 => {
                        tls.write_all(&frame(PING, 1, 0, &f.payload)).await.unwrap();
                    }
                    HEADERS => {
                        waiting.push(f.stream);
                        if waiting.len() >= batch {
                            for id in waiting.drain(..) {
                                // :status 200, END_HEADERS | END_STREAM.
                                tls.write_all(&frame(HEADERS, 0x5, id, &[0x88]))
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                    _ => {}
                }
                seen.lock().unwrap().frames.push(f);
            }
            record += 1;
        }
    });
    (port, log)
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() as u32).to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn client(mut profile: BrowserProfile) -> Client {
    profile.tls.danger_accept_invalid_certs = true;
    Client::new(profile).unwrap()
}

fn options(headers: &[(&str, &str)]) -> RequestOptions {
    RequestOptions {
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        ..Default::default()
    }
}

/// The priority block of a HEADERS frame: (exclusive, dependency, wire
/// weight).
fn priority(f: &Frame) -> Option<(bool, u32, u16)> {
    (f.flags & 0x20 != 0).then(|| {
        let p = &f.payload[if f.flags & 0x8 != 0 { 1 } else { 0 }..];
        let dep = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        (dep >> 31 == 1, dep & 0x7fff_ffff, u16::from(p[4]) + 1)
    })
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

async fn wait_for_end(log: &Log) -> End {
    common::wait_until(Duration::from_secs(5), || log.lock().unwrap().end.is_some()).await;
    log.lock().unwrap().end.unwrap_or(End::Open)
}

#[tokio::test]
async fn firefox_frames() {
    let (port, log) = server(1).await;
    let client = client(Firefox::latest());
    let url = format!("https://127.0.0.1:{port}/");
    client.get(&url).await.unwrap();
    let image = options(&[
        ("accept", "image/avif,image/webp,*/*"),
        ("sec-fetch-dest", "image"),
        ("sec-fetch-mode", "no-cors"),
        ("sec-fetch-site", "same-origin"),
    ]);
    client
        .send(
            Method::GET,
            &format!("{url}favicon.ico"),
            Body::empty(),
            image,
        )
        .await
        .unwrap();
    client.get(&format!("{url}next")).await.unwrap();
    client.close();
    let end = wait_for_end(&log).await;

    let seen = log.lock().unwrap();
    let frames = &seen.frames;
    // [preface, SETTINGS, WINDOW_UPDATE] in the first record.
    assert_eq!(seen.preface_record, Some(0));
    let first: Vec<u8> = frames
        .iter()
        .filter(|f| f.record == 0)
        .map(|f| f.kind)
        .collect();
    assert_eq!(first, [SETTINGS, WINDOW_UPDATE]);

    let headers: Vec<&Frame> = frames.iter().filter(|f| f.kind == HEADERS).collect();
    assert_eq!(
        headers.iter().map(|f| f.stream).collect::<Vec<_>>(),
        [3, 5, 7]
    );
    let weights: Vec<_> = headers.iter().map(|f| priority(f)).collect();
    assert_eq!(
        weights,
        [
            Some((false, 0, 42)),
            Some((false, 0, 12)),
            Some((false, 0, 42))
        ]
    );
    for h in &headers {
        assert_eq!(h.flags, 0x25);
        // The stream's WINDOW_UPDATE follows in the same record: 128 KB to
        // 12 MB.
        let wu = frames
            .iter()
            .find(|f| f.kind == WINDOW_UPDATE && f.stream == h.stream)
            .expect("stream WINDOW_UPDATE");
        assert_eq!(wu.record, h.record);
        assert_eq!(wu.payload, 12_451_840u32.to_be_bytes());
        assert_eq!(frames.iter().filter(|f| f.record == h.record).count(), 2);
    }
    // :path / as a literal without indexing, every string Huffman-coded.
    let reps = representations(headers[0]);
    assert_eq!(&reps[..4], ["idx2", "noidx4/H", "inc1/H", "idx7"]);
    assert!(reps.iter().all(|r| !r.ends_with("/raw")), "{reps:?}");
    // Another path names the last :path entry of the static table.
    assert_eq!(representations(headers[2])[1], "noidx5/H");

    // GOAWAY, close_notify, FIN.
    assert!(frames.iter().any(|f| f.kind == GOAWAY));
    assert_eq!(end, End::CloseNotify);
}

#[tokio::test]
async fn chrome_frames() {
    // Two requests at once: the second depends on the first.
    let (port, log) = server(2).await;
    let client = Arc::new(client(Chrome::latest()));
    let url = format!("https://127.0.0.1:{port}/");
    let fetch = options(&[
        ("accept", "*/*"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
    ]);
    let navigation = {
        let (client, url) = (client.clone(), url.clone());
        tokio::spawn(async move { client.get(&url).await })
    };
    // The fetch's dependency (on stream 1) only matches capture if the
    // navigation's stream is already open when its HEADERS goes out.
    common::wait_until(Duration::from_secs(5), || {
        log.lock().unwrap().frames.iter().any(|f| f.kind == HEADERS)
    })
    .await;
    client
        .send(Method::GET, &format!("{url}api"), Body::empty(), fetch)
        .await
        .unwrap();
    navigation.await.unwrap().unwrap();
    client.close();
    let end = wait_for_end(&log).await;

    let seen = log.lock().unwrap();
    let frames = &seen.frames;
    assert_eq!(seen.preface_record, Some(0));
    let first: Vec<u8> = frames
        .iter()
        .filter(|f| f.record == 0)
        .map(|f| f.kind)
        .collect();
    assert_eq!(first, [SETTINGS, WINDOW_UPDATE]);

    let headers: Vec<&Frame> = frames.iter().filter(|f| f.kind == HEADERS).collect();
    assert_eq!(headers.iter().map(|f| f.stream).collect::<Vec<_>>(), [1, 3]);
    // u=0 -> 256; u=1 -> 220, on the open stream 1.
    assert_eq!(priority(headers[0]), Some((true, 0, 256)));
    assert_eq!(priority(headers[1]), Some((true, 1, 220)));
    for h in &headers {
        // One record per HEADERS frame, no stream WINDOW_UPDATE.
        assert_eq!(frames.iter().filter(|f| f.record == h.record).count(), 1);
    }
    assert!(
        !frames
            .iter()
            .any(|f| f.kind == WINDOW_UPDATE && f.stream != 0)
    );
    // Huffman only where shorter: "?0" and "1" stay raw.
    let reps = representations(headers[0]);
    assert_eq!(&reps[..4], ["idx2", "inc1/H", "idx7", "idx4"]);
    assert_eq!(reps[5], "inc0/raw", "sec-ch-ua-mobile: {reps:?}");
    assert_eq!(reps[7], "inc0/raw", "upgrade-insecure-requests: {reps:?}");

    // No GOAWAY and no close_notify: a plain FIN.
    assert!(!frames.iter().any(|f| f.kind == GOAWAY));
    assert_eq!(end, End::Fin);
}

/// OkHttp as captured from 4.12.0 and 5.5.0 on Android 17: the preface, the
/// SETTINGS and the connection WINDOW_UPDATE each in a record of its own,
/// streams from 3 without priority, a POST's HEADERS in one record with its
/// DATA, and a close with close_notify but without GOAWAY.
#[tokio::test]
async fn okhttp_frames() {
    let (port, log) = server(1).await;
    let client = client(OkHttp::latest());
    let url = format!("https://127.0.0.1:{port}/");
    client.get(&format!("{url}start")).await.unwrap();
    let json = options(&[("content-type", "application/json; charset=utf-8")]);
    client
        .send(
            Method::POST,
            &format!("{url}api"),
            Body::from("{\"a\":1}"),
            json,
        )
        .await
        .unwrap();
    client.close();
    let end = wait_for_end(&log).await;

    let seen = log.lock().unwrap();
    let frames = &seen.frames;
    // The preface alone in the first record.
    assert_eq!(seen.preface_record, Some(0));
    let layout: Vec<(usize, u8)> = frames
        .iter()
        .filter(|f| !(f.kind == SETTINGS && f.flags & 1 != 0))
        .take(3)
        .map(|f| (f.record, f.kind))
        .collect();
    assert_eq!(layout, [(1, SETTINGS), (2, WINDOW_UPDATE), (3, HEADERS)]);

    let headers: Vec<&Frame> = frames.iter().filter(|f| f.kind == HEADERS).collect();
    assert_eq!(headers.iter().map(|f| f.stream).collect::<Vec<_>>(), [3, 5]);
    assert_eq!(headers[0].flags, 0x5);
    assert_eq!(priority(headers[0]), None);
    assert_eq!(
        representations(headers[0]),
        ["idx2", "noidx4/H", "inc1/H", "idx7", "inc16/H", "inc58/H"]
    );
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.record == headers[0].record)
            .count(),
        1
    );
    let data = frames.iter().find(|f| f.kind == DATA).expect("DATA");
    assert_eq!((data.stream, data.record), (5, headers[1].record));
    assert_eq!(frames.iter().filter(|f| f.record == data.record).count(), 2);

    // close_notify and FIN, no GOAWAY.
    assert!(!frames.iter().any(|f| f.kind == GOAWAY));
    assert_eq!(end, End::CloseNotify);
}

#[tokio::test]
async fn chrome_ping_follows_headers_after_idle_time() {
    let (port, log) = server(1).await;
    let mut profile = Chrome::latest();
    profile.http2.ping = Some(ConnectionPing::BeforeRequest {
        idle_ms: 200,
        timeout_ms: 5_000,
    });
    let client = client(profile);
    let url = format!("https://127.0.0.1:{port}/");
    client.get(&url).await.unwrap();
    client.get(&url).await.unwrap();
    // The next request must be idle_ms (200 ms) past the last read for the
    // client to attach a PING; there is no event to wait for here, just
    // elapsed wall-clock time, so sleeping past that threshold is correct.
    tokio::time::sleep(Duration::from_millis(400)).await;
    client.get(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    client.get(&url).await.unwrap();

    let seen = log.lock().unwrap();
    let frames: Vec<(u8, u32, Vec<u8>, usize)> = seen
        .frames
        .iter()
        .filter(|f| matches!(f.kind, HEADERS | PING))
        .map(|f| (f.kind, f.stream, f.payload.clone(), f.record))
        .collect();
    let kinds: Vec<u8> = frames.iter().map(|f| f.0).collect();
    assert_eq!(kinds, [HEADERS, HEADERS, HEADERS, PING, HEADERS, PING]);
    // Counted from 1, each in a record after its HEADERS.
    assert_eq!(frames[3].2, 1u64.to_be_bytes());
    assert_eq!(frames[5].2, 2u64.to_be_bytes());
    assert!(frames[3].3 > frames[2].3);
}

#[tokio::test]
async fn firefox_pings_an_idle_connection() {
    let (port, log) = server(1).await;
    let mut profile = Firefox::latest();
    let idle_ms: u64 = 300;
    profile.http2.ping = Some(ConnectionPing::Idle {
        idle_ms,
        timeout_ms: 5_000,
    });
    let client = client(profile);
    let start = std::time::Instant::now();
    client
        .get(&format!("https://127.0.0.1:{port}/"))
        .await
        .unwrap();

    // Wait for the first idle ping instead of guessing how long that
    // takes; how many more could have arrived by the time it shows up is
    // then bounded by the real time that actually passed, not by a sleep
    // duration a slow CI runner might overrun.
    common::wait_until(Duration::from_secs(5), || {
        log.lock().unwrap().frames.iter().any(|f| f.kind == PING)
    })
    .await;
    let seen = log.lock().unwrap();
    let elapsed = start.elapsed();
    let pings: Vec<&Frame> = seen.frames.iter().filter(|f| f.kind == PING).collect();
    let max_pings = elapsed.as_millis() / u128::from(idle_ms) + 1;
    // Answered pings keep the connection: one after each 300 ms idle.
    assert!(
        !pings.is_empty() && (pings.len() as u128) <= max_pings,
        "{pings:?} elapsed={elapsed:?} max={max_pings}"
    );
    assert!(pings.iter().all(|p| p.payload == [0; 8] && p.flags == 0));
    assert_eq!(seen.end, None);
}

/// The parameters of a SETTINGS frame, in wire order.
fn settings(f: &Frame) -> Vec<(u16, u32)> {
    f.payload
        .chunks(6)
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
            )
        })
        .collect()
}

/// Safari's HTTP/2 layer as captured from Safari on macOS 14.7 to 27.0 and
/// iOS 17.0.1 to 27.0: SETTINGS and their order (macOS 15.0 still those of
/// macOS 14; ENABLE_CONNECT_PROTOCOL up to macOS 15.2 and iOS 18.3), the
/// connection
/// WINDOW_UPDATE, the pseudo-header order (in the HPACK representations;
/// `:path /` is in the static table),
/// HEADERS priorities by destination (none from macOS 26 on, none for
/// fetches), and cookies as never-indexed crumbs.
#[tokio::test]
async fn safari_frames() {
    type Weights = [Option<(bool, u32, u16)>; 4];
    let weighted = |document, style, image| -> Weights {
        [
            Some((false, 0, document)),
            None,
            Some((false, 0, style)),
            Some((false, 0, image)),
        ]
    };
    let cases: [(
        &str,
        koon_core::Os,
        Vec<(u16, u32)>,
        u32,
        [&str; 4],
        Weights,
    ); 7] = [
        (
            "17.0",
            koon_core::Os::MacOS,
            vec![(2, 0), (4, 4_194_304), (3, 100)],
            10_485_760,
            ["idx2", "idx7", "idx4", "inc1/H"],
            weighted(255, 24, 8),
        ),
        (
            "18.0",
            koon_core::Os::MacOS,
            vec![(2, 0), (4, 4_194_304), (3, 100)],
            10_485_760,
            ["idx2", "idx7", "idx4", "inc1/H"],
            weighted(255, 24, 8),
        ),
        (
            "18.3",
            koon_core::Os::MacOS,
            vec![(2, 0), (3, 100), (4, 2_097_152), (8, 1), (9, 1)],
            10_420_225,
            ["idx2", "idx7", "inc1/H", "idx4"],
            weighted(256, 64, 4),
        ),
        (
            "18.0",
            koon_core::Os::Ios,
            vec![(2, 0), (3, 100), (4, 2_097_152), (8, 1), (9, 1)],
            10_420_225,
            ["idx2", "idx7", "inc1/H", "idx4"],
            weighted(256, 64, 4),
        ),
        (
            "18.1",
            koon_core::Os::MacOS,
            vec![(2, 0), (3, 100), (4, 2_097_152), (8, 1), (9, 1)],
            10_420_225,
            ["idx2", "idx7", "inc1/H", "idx4"],
            weighted(256, 64, 4),
        ),
        (
            "18.4",
            koon_core::Os::MacOS,
            vec![(2, 0), (3, 100), (4, 2_097_152), (9, 1)],
            10_420_225,
            ["idx2", "idx7", "inc1/H", "idx4"],
            weighted(256, 64, 4),
        ),
        (
            "27.0",
            koon_core::Os::MacOS,
            vec![(2, 0), (3, 100), (4, 2_097_152), (9, 1)],
            10_420_225,
            ["idx2", "idx7", "inc1/H", "idx4"],
            [None; 4],
        ),
    ];
    for (version, os, expected_settings, increment, pseudo, weights) in cases {
        let (port, log) = server(1).await;
        let client = client(koon_core::Safari::version(version, os).unwrap());
        let url = format!("https://127.0.0.1:{port}/");
        client.get(&url).await.unwrap();
        let subresource = |accept: &str, mode: &str, dest: &str| {
            let mut o = options(&[
                ("accept", accept),
                ("sec-fetch-mode", mode),
                ("sec-fetch-dest", dest),
                ("referer", &url),
            ]);
            o.headers.push(("cookie".into(), "a=1; b=2".into()));
            o
        };
        for (path, request) in [
            ("api", subresource("*/*", "cors", "empty")),
            (
                "s.css",
                subresource("text/css,*/*;q=0.1", "no-cors", "style"),
            ),
            (
                "i.png",
                subresource("image/webp,*/*;q=0.5", "no-cors", "image"),
            ),
        ] {
            client
                .send(Method::GET, &format!("{url}{path}"), Body::empty(), request)
                .await
                .unwrap();
        }

        let seen = log.lock().unwrap();
        let frames = &seen.frames;
        let first_settings = frames
            .iter()
            .find(|f| f.kind == SETTINGS && f.flags & 1 == 0)
            .unwrap();
        assert_eq!(
            settings(first_settings),
            expected_settings,
            "{version} {os}"
        );
        let wu = frames
            .iter()
            .find(|f| f.kind == WINDOW_UPDATE && f.stream == 0)
            .unwrap();
        assert_eq!(wu.payload, increment.to_be_bytes(), "{version} {os}");

        let headers: Vec<&Frame> = frames.iter().filter(|f| f.kind == HEADERS).collect();
        assert_eq!(headers.len(), 4);
        let got: Vec<_> = headers.iter().map(|f| priority(f)).collect();
        assert_eq!(got, weights, "{version} {os}");
        assert_eq!(representations(headers[0])[..4], pseudo, "{version} {os}");
        // No WINDOW_UPDATE for streams.
        assert!(
            !frames
                .iter()
                .any(|f| f.kind == WINDOW_UPDATE && f.stream != 0)
        );
        // Other paths as literals without indexing, cookies as never-indexed
        // crumbs.
        let reps = representations(headers[1]);
        assert!(reps.contains(&"noidx4/H".to_string()), "{reps:?}");
        let crumbs = reps.iter().filter(|r| r.starts_with("never32/")).count();
        assert_eq!(crumbs, 2, "{reps:?}");
    }
}
