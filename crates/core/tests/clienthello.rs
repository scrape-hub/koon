//! Offline ClientHello layout tests.
//!
//! A local TLS server records the raw ClientHello of every connection, so the
//! extension layout koon puts on the wire is checked without network access.
//! It also issues session tickets, which covers resumed handshakes — public
//! fingerprinting services never resume, so the online tests cannot see them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use btls::ssl::Ssl;
use koon_core::{BrowserProfile, Chrome, Client, Firefox, Opera, Os};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod common;

const SERVER_NAME: u16 = 0x0000;
const SESSION_TICKET: u16 = 0x0023;
const PRE_SHARED_KEY: u16 = 0x0029;
const KEY_SHARE: u16 = 0x0033;
const SIGNATURE_ALGORITHMS: u16 = 0x000d;
const DELEGATED_CREDENTIALS: u16 = 0x0022;
const ECH: u16 = 0xfe0d;
const TRUST_ANCHORS: u16 = 0xca34;
const X25519_MLKEM768: u16 = 0x11ec;
const X25519: u16 = 0x001d;
const P256: u16 = 0x0017;

/// Real Firefox 156 connecting to a hostname, captured through a CONNECT
/// relay. Identical in Firefox 147–156 apart from server_name, which is
/// missing when a capture targets an IP literal.
const FIREFOX_FULL_HANDSHAKE: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b,
    0x000d, 0x002d, 0x001c, 0x001b, 0xfe0d,
];

fn types(exts: &[(u16, Vec<u8>)]) -> Vec<u16> {
    exts.iter().map(|(t, _)| *t).collect()
}

fn is_grease(ty: u16) -> bool {
    ty & 0x0f0f == 0x0a0a && ty >> 8 == ty & 0xff
}

/// Extensions of a ClientHello record (type and payload), in wire order.
fn extensions(record: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let u16_at = |p: usize| u16::from_be_bytes([record[p], record[p + 1]]);
    // record header, handshake header, legacy_version, random
    let mut p = 5 + 4 + 2 + 32;
    p += 1 + record[p] as usize; // session_id
    p += 2 + u16_at(p) as usize; // cipher_suites
    p += 1 + record[p] as usize; // compression_methods
    let end = p + 2 + u16_at(p) as usize;
    p += 2;
    let mut exts = Vec::new();
    while p < end {
        let len = u16_at(p + 2) as usize;
        exts.push((u16_at(p), record[p + 4..p + 4 + len].to_vec()));
        p += 4 + len;
    }
    exts
}

/// A list of u16 behind a 2-byte length (signature_algorithms,
/// delegated_credentials).
fn u16s(exts: &[(u16, Vec<u8>)], ty: u16) -> Vec<u16> {
    let data = &exts.iter().find(|(t, _)| *t == ty).expect("extension").1;
    data[2..]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Groups of the key_share extension.
fn key_share_groups(exts: &[(u16, Vec<u8>)]) -> Vec<u16> {
    let Some((_, data)) = exts.iter().find(|(t, _)| *t == KEY_SHARE) else {
        return Vec::new();
    };
    let mut groups = Vec::new();
    let mut p = 2;
    while p + 4 <= data.len() {
        groups.push(u16::from_be_bytes([data[p], data[p + 1]]));
        p += 4 + u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
    }
    groups
}

/// Local HTTPS server that records every ClientHello it receives.
struct HelloServer {
    port: u16,
    hellos: Arc<Mutex<Vec<Vec<(u16, Vec<u8>)>>>>,
}

impl HelloServer {
    async fn start() -> Self {
        let (cert, key) = common::leaf("localhost");
        let acceptor = Arc::new(common::tls_acceptor_builder(&cert, &key).build());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hellos = Arc::new(Mutex::new(Vec::new()));
        let recorded = hellos.clone();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                // Peek the complete first record, leaving it in the socket for
                // the TLS handshake.
                let mut buf = vec![0u8; 5 + 16 * 1024];
                let record = loop {
                    let n = tcp.peek(&mut buf).await.unwrap();
                    if n >= 5 {
                        let len = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
                        if n >= len {
                            break buf[..len].to_vec();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                };
                recorded.lock().unwrap().push(extensions(&record));

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
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        HelloServer { port, hellos }
    }

    /// Make two requests on separate connections: a full handshake, then a
    /// resumed one. Returns both ClientHellos' extension lists.
    async fn full_and_resumed(
        &self,
        mut profile: BrowserProfile,
    ) -> (Vec<(u16, Vec<u8>)>, Vec<(u16, Vec<u8>)>) {
        profile.tls.danger_accept_invalid_certs = true;
        let client = Client::builder(profile).build().unwrap();
        let url = format!("https://localhost:{}/", self.port);

        let first = client.get(&url).await.expect("first request");
        assert!(!first.tls_resumed);
        let second = client.get(&url).await.expect("second request");
        assert!(second.tls_resumed, "second connection did not resume");
        assert!(!second.connection_reused);

        let hellos = self.hellos.lock().unwrap();
        assert!(hellos.len() >= 2, "expected two ClientHellos");
        let n = hellos.len();
        (hellos[n - 2].clone(), hellos[n - 1].clone())
    }
}

#[tokio::test]
async fn firefox_extension_order_matches_real_browser() {
    let server = HelloServer::start().await;
    let (full_exts, resumed_exts) = server.full_and_resumed(Firefox::latest()).await;
    let full = types(&full_exts);
    let resumed = types(&resumed_exts);

    assert_eq!(full, FIREFOX_FULL_HANDSHAKE, "full handshake");
    // Firefox sends three key shares, P-256 included.
    assert_eq!(
        key_share_groups(&full_exts),
        [X25519_MLKEM768, X25519, P256]
    );
    assert_eq!(
        u16s(&full_exts, DELEGATED_CREDENTIALS),
        [0x0403, 0x0503, 0x0603, 0x0203]
    );
    // NSS's ECH GREASE: AES-128-GCM or ChaCha20-Poly1305, and a payload as
    // long as the padded inner ClientHello, 240 bytes for this one.
    let ech = &full_exts.iter().find(|(t, _)| *t == ECH).unwrap().1;
    assert_eq!(ech[..3], [0x00, 0x00, 0x01]);
    assert!([[0x00, 0x01], [0x00, 0x03]].contains(&[ech[3], ech[4]]));
    assert_eq!(u16::from_be_bytes([ech[40], ech[41]]), 240);

    // NSS drops session_ticket when offering a TLS 1.3 PSK; pre_shared_key
    // comes last. Everything else keeps its position.
    let mut expected: Vec<u16> = FIREFOX_FULL_HANDSHAKE
        .iter()
        .copied()
        .filter(|&t| t != SESSION_TICKET)
        .collect();
    expected.push(PRE_SHARED_KEY);
    assert_eq!(resumed, expected, "resumed handshake");
}

#[tokio::test]
async fn chrome_resumption_keeps_session_ticket() {
    let server = HelloServer::start().await;
    let (full_exts, resumed_exts) = server.full_and_resumed(Chrome::latest()).await;
    let full = types(&full_exts);
    let resumed = types(&resumed_exts);

    assert!(full.contains(&SERVER_NAME));
    assert!(full.contains(&TRUST_ANCHORS));
    let shares = key_share_groups(&full_exts);
    assert_eq!(shares.len(), 3);
    assert!(is_grease(shares[0]));
    assert_eq!(shares[1..], [X25519_MLKEM768, X25519]);
    assert!(full.contains(&SESSION_TICKET));
    assert!(!full.contains(&PRE_SHARED_KEY));

    // Chrome keeps the same extension set (in a new permutation) and appends
    // pre_shared_key after everything else, including the trailing GREASE.
    assert_eq!(resumed.last(), Some(&PRE_SHARED_KEY));
    let set = |exts: &[u16]| {
        let mut v: Vec<u16> = exts
            .iter()
            .copied()
            .filter(|&t| !is_grease(t) && t != PRE_SHARED_KEY)
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(set(&full), set(&resumed));
}

/// The trust_anchors extension of Chrome for Testing 154, the same on every
/// connection: the 28 IDs of Chrome Root Store version 39, sorted.
const CHROME_154_TRUST_ANCHORS: &str = "00b80582df1302010582df1302060582df13020d0582df13020e\
    0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d0108\
    08839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b\
    2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604\
    d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f";

/// The IDs of Chrome for Testing 152 and Opera 136 (Chrome Root Store
/// version 36), sorted; the browsers list them in a random order.
const CHROMIUM_152_TRUST_ANCHOR_IDS: &[&str] = &[
    "82df130201",
    "82df130206",
    "82df13020d",
    "82df13020e",
    "82df13020f",
    "82df130212",
    "82df130213",
    "82df130214",
    "839a648c9b2d0107",
    "839a648c9b2d0108",
    "839a648c9b2d0109",
    "839a648c9b2d010a",
    "839a648c9b2d010b",
    "839a648c9b2d010c",
    "839a648c9b2d010d",
    "839a648c9b2d0112",
    "839a648c9b2d0113",
    "d6790901",
    "d6790902",
    "d6790903",
    "d6790904",
    "d6790905",
    "d6790906",
    "d6790907",
    "d6790908",
    "d6790909",
    "d679090a",
    "d679090b",
    "d679090c",
    "d679090d",
    "d679090e",
    "d679090f",
];

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn trust_anchors(exts: &[(u16, Vec<u8>)]) -> Option<Vec<u8>> {
    exts.iter()
        .find(|(t, _)| *t == TRUST_ANCHORS)
        .map(|(_, d)| d.clone())
}

/// The IDs of a trust_anchors payload, hex, in wire order.
fn trust_anchor_ids(payload: &[u8]) -> Vec<String> {
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]) as usize,
        payload.len() - 2
    );
    let mut ids = Vec::new();
    let mut p = 2;
    while p < payload.len() {
        let len = payload[p] as usize;
        ids.push(
            payload[p + 1..p + 1 + len]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        );
        p += 1 + len;
    }
    ids
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

#[tokio::test]
async fn chrome_trust_anchor_ids_by_version() {
    let server = HelloServer::start().await;
    let chrome = |major| Chrome::version(major, Os::Windows).unwrap();
    let chrome_153_ids = trust_anchor_ids(&unhex(CHROME_154_TRUST_ANCHORS));

    // No extension up to Chrome 151.
    let (full, _) = server.full_and_resumed(chrome(140)).await;
    assert_eq!(trust_anchors(&full), None);
    let (full, _) = server.full_and_resumed(chrome(151)).await;
    assert_eq!(trust_anchors(&full), None);
    // No GREASE signature algorithm before Chrome 152.
    let sigalgs = u16s(&full, SIGNATURE_ALGORITHMS);
    assert_eq!(sigalgs[0], 0x0904, "{sigalgs:x?}");

    // Chrome 152: the 32 IDs of its store, in an order of the client that
    // its resumed connection keeps.
    let (full, resumed) = server.full_and_resumed(chrome(152)).await;
    let payload = trust_anchors(&full).unwrap();
    assert_eq!(payload.len(), 206);
    assert_eq!(
        sorted(trust_anchor_ids(&payload)),
        CHROMIUM_152_TRUST_ANCHOR_IDS
    );
    assert_eq!(trust_anchors(&resumed).unwrap(), payload);

    // Chrome 153: 28 IDs, again in an order of each client.
    let (full, resumed) = server.full_and_resumed(chrome(153)).await;
    let payload = trust_anchors(&full).unwrap();
    assert_eq!(payload.len(), 186);
    assert_eq!(sorted(trust_anchor_ids(&payload)), chrome_153_ids);
    assert_eq!(trust_anchors(&resumed).unwrap(), payload);
    let (other_client, _) = server.full_and_resumed(chrome(153)).await;
    assert_ne!(
        trust_anchors(&other_client).unwrap(),
        payload,
        "another client, another order"
    );

    // Chrome 154 sorts them: the captured bytes.
    let (full, resumed) = server.full_and_resumed(chrome(154)).await;
    assert_eq!(
        trust_anchors(&full).unwrap(),
        unhex(CHROME_154_TRUST_ANCHORS)
    );
    assert_eq!(
        trust_anchors(&resumed).unwrap(),
        unhex(CHROME_154_TRUST_ANCHORS)
    );
    // Chrome 152+ puts a GREASE value first, then the ML-DSA schemes.
    let sigalgs = u16s(&full, SIGNATURE_ALGORITHMS);
    assert!(is_grease(sigalgs[0]), "{sigalgs:x?}");
    assert_eq!(sigalgs[1..4], [0x0904, 0x0905, 0x0906]);
    assert_eq!(sigalgs.len(), 12);

    // Edge does not send the extension; Opera sends it from 136 on, with
    // Chromium 152's IDs and GREASE signature algorithm.
    let (full, _) = server.full_and_resumed(koon_core::Edge::latest()).await;
    assert_eq!(trust_anchors(&full), None);
    let (full, _) = server
        .full_and_resumed(Opera::version(135, Os::Windows).unwrap())
        .await;
    assert_eq!(trust_anchors(&full), None);
    assert_eq!(u16s(&full, SIGNATURE_ALGORITHMS)[0], 0x0904);
    let (full, _) = server
        .full_and_resumed(Opera::version(136, Os::Windows).unwrap())
        .await;
    assert_eq!(
        sorted(trust_anchor_ids(&trust_anchors(&full).unwrap())),
        CHROMIUM_152_TRUST_ANCHOR_IDS
    );
    let sigalgs = u16s(&full, SIGNATURE_ALGORITHMS);
    assert!(is_grease(sigalgs[0]), "{sigalgs:x?}");
    assert_eq!(sigalgs[1..4], [0x0904, 0x0905, 0x0906]);
}

/// Extensions of the ClientHellos of real Edge 152.0.4191.66 and
/// 153.0.4234.48 to www.cloudflare.com (full handshakes), sorted, without
/// the two GREASE extensions. Edge sends no trust_anchors extension.
const EDGE_152_EXTENSIONS: &[u16] = &[
    0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
    0x0033, 0x44cd, 0xfe0d, 0xff01,
];

/// signature_algorithms of the same captures after their leading GREASE
/// value: ML-DSA first, then Chrome's list.
const EDGE_152_SIGALGS: &[u16] = &[
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

#[tokio::test]
async fn edge_152_and_153_clienthello_matches_capture() {
    let server = HelloServer::start().await;
    for major in [152, 153] {
        let profile = koon_core::Edge::version(major, Os::Windows).unwrap();
        let (full_exts, resumed_exts) = server.full_and_resumed(profile).await;
        let full = types(&full_exts);
        let resumed = types(&resumed_exts);

        assert_eq!(full.iter().filter(|&&t| is_grease(t)).count(), 2);
        let mut set: Vec<u16> = full.iter().copied().filter(|&t| !is_grease(t)).collect();
        set.sort_unstable();
        assert_eq!(set, EDGE_152_EXTENSIONS, "Edge {major} full handshake");

        let sigalgs = u16s(&full_exts, SIGNATURE_ALGORITHMS);
        assert!(is_grease(sigalgs[0]), "Edge {major}: {sigalgs:x?}");
        assert_eq!(sigalgs[1..], *EDGE_152_SIGALGS, "Edge {major}");
        let shares = key_share_groups(&full_exts);
        assert!(is_grease(shares[0]));
        assert_eq!(shares[1..], [X25519_MLKEM768, X25519]);

        // Resumed: the same set with pre_shared_key appended last.
        assert_eq!(resumed.last(), Some(&PRE_SHARED_KEY), "Edge {major}");
        let mut set: Vec<u16> = resumed
            .iter()
            .copied()
            .filter(|&t| !is_grease(t) && t != PRE_SHARED_KEY)
            .collect();
        set.sort_unstable();
        assert_eq!(set, EDGE_152_EXTENSIONS, "Edge {major} resumed handshake");
    }
}

/// The extensions of real Chrome 153 on Android 17 (full handshake, GREASE
/// left out), sorted: desktop Chrome's plus server_padding (0x12E0).
const CHROME_153_ANDROID_EXTENSIONS: &[u16] = &[
    0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
    0x0033, 0x12e0, 0x44cd, 0xca34, 0xfe0d, 0xff01,
];

/// Chrome `major` on `os` whose client is in the group of
/// `PqcBandwidthExperiment` that asks for `bytes`, or with `None` outside
/// the trial (which 94 % of the clients are).
fn chrome_in_padding_trial(major: u32, os: Os, bytes: Option<u16>) -> BrowserProfile {
    let mut profile = Chrome::version(major, os).unwrap();
    let trial = profile.tls.server_padding_trial.as_mut().unwrap();
    match bytes {
        Some(bytes) => {
            trial.enrolled_slots = trial.slots;
            trial.groups.retain(|g| g.bytes == bytes);
            assert_eq!(trial.groups.len(), 1, "no group asks for {bytes}");
        }
        None => trial.enrolled_slots = 0,
    }
    profile
}

/// A Chrome client in `PqcBandwidthExperiment` asks for its group's server
/// padding in every ClientHello, resumed ones included (captured from
/// Chrome 153 on Android, which asked for 4000 bytes); a client outside the
/// trial does not.
#[tokio::test]
async fn chrome_in_the_padding_trial_requests_server_padding() {
    const SERVER_PADDING: u16 = 0x12e0;
    let server = HelloServer::start().await;
    let profile = chrome_in_padding_trial(153, Os::Android, Some(12_000));
    let (full_exts, resumed_exts) = server.full_and_resumed(profile).await;
    let set = |exts: &[(u16, Vec<u8>)]| {
        let mut v: Vec<u16> = types(exts)
            .into_iter()
            .filter(|&t| !is_grease(t) && t != PRE_SHARED_KEY)
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(set(&full_exts), CHROME_153_ANDROID_EXTENSIONS);
    assert_eq!(set(&resumed_exts), CHROME_153_ANDROID_EXTENSIONS);
    for exts in [&full_exts, &resumed_exts] {
        let padding = &exts.iter().find(|(t, _)| *t == SERVER_PADDING).unwrap().1;
        assert_eq!(padding, &12_000u16.to_be_bytes());
    }

    // The group of 0 bytes still sends the extension.
    let (zero, _) = server
        .full_and_resumed(chrome_in_padding_trial(155, Os::Windows, Some(0)))
        .await;
    let padding = &zero.iter().find(|(t, _)| *t == SERVER_PADDING).unwrap().1;
    assert_eq!(padding, &[0, 0]);

    let (outside, _) = server
        .full_and_resumed(chrome_in_padding_trial(153, Os::Windows, None))
        .await;
    assert!(!types(&outside).contains(&SERVER_PADDING));
}

/// OkHttp 4.12.0 and 5.5.0 on Android 17: Conscrypt's ClientHello, in
/// BoringSSL's extension order with psk_key_exchange_modes, one X25519 key
/// share and padding; the second connection resumes the TLS 1.3 session.
#[tokio::test]
async fn okhttp_clienthellos_match_the_captures() {
    const ORDER: &[u16] = &[
        0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0033, 0x002d,
        0x002b,
    ];
    const PADDING: u16 = 0x0015;
    let server = HelloServer::start().await;
    for major in [4, 5] {
        let profile = koon_core::OkHttp::version(major).unwrap();
        let (full_exts, resumed_exts) = server.full_and_resumed(profile).await;
        assert_eq!(
            types(&full_exts),
            [ORDER, &[PADDING]].concat(),
            "OkHttp {major} full handshake"
        );
        assert_eq!(key_share_groups(&full_exts), [X25519]);
        // session_ticket stays; pre_shared_key comes last, after the padding
        // a shorter hello still gets.
        let resumed: Vec<u16> = types(&resumed_exts)
            .into_iter()
            .filter(|&t| t != PADDING)
            .collect();
        assert_eq!(
            resumed,
            [ORDER, &[PRE_SHARED_KEY]].concat(),
            "OkHttp {major} resumed handshake"
        );
    }
}

#[tokio::test]
async fn https_proxy_is_reached_over_tls() {
    let server = HelloServer::start().await;
    let client = Client::builder(Chrome::latest())
        .proxy(&format!("https://localhost:{}", server.port))
        .unwrap()
        .danger_accept_invalid_proxy_certs(true)
        .build()
        .unwrap();

    // Plain http:// through an HTTPS proxy: TLS to the proxy, then the
    // request in absolute form inside that TLS connection.
    let resp = client.get("http://example.test/").await.expect("request");
    assert_eq!(resp.status, 200);

    // The proxy connection offers http/1.1 only: CONNECT over HTTP/2 is not
    // supported, so h2 must not be negotiated with the proxy.
    let hello = server.hellos.lock().unwrap().last().cloned().unwrap();
    let alpn = &hello.iter().find(|(t, _)| *t == 0x0010).expect("ALPN").1;
    assert!(!alpn.windows(2).any(|w| w == b"h2"));
}

/// supported_versions (1-byte list length), GREASE left out.
fn supported_versions(exts: &[(u16, Vec<u8>)]) -> Vec<u16> {
    let data = &exts
        .iter()
        .find(|(t, _)| *t == 0x002b)
        .expect("extension")
        .1;
    data[1..]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .collect()
}

/// Safari's ClientHello as captured from Safari on macOS 14.7 to 15.7.9 and
/// 26.1 to 27.0 and iOS 17.0.1 to 27.0: BoringSSL's extension order,
/// padding while the hello is shorter than 512 bytes, TLS 1.1 and 1.0
/// offered up to macOS 15 and iOS 18, ecdsa_sha1 up to macOS 15.1 and iOS
/// 18.1, X25519MLKEM768 from 26 on. A second connection offers no session:
/// Safari never resumes over TCP.
#[tokio::test]
async fn safari_clienthellos_match_the_captures() {
    const ORDER: &[u16] = &[
        0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
        0x002b, 0x001b,
    ];
    const P384: u16 = 0x0018;
    const P521: u16 = 0x0019;
    let server = HelloServer::start().await;
    for (version, os, legacy, groups, shares, sha1) in [
        (
            "17.0",
            Os::MacOS,
            true,
            vec![X25519, P256, P384, P521],
            vec![X25519],
            true,
        ),
        (
            "18.0",
            Os::Ios,
            true,
            vec![X25519, P256, P384, P521],
            vec![X25519],
            true,
        ),
        (
            "18.1",
            Os::MacOS,
            true,
            vec![X25519, P256, P384, P521],
            vec![X25519],
            true,
        ),
        (
            "18.2",
            Os::MacOS,
            true,
            vec![X25519, P256, P384, P521],
            vec![X25519],
            false,
        ),
        (
            "18.3",
            Os::MacOS,
            true,
            vec![X25519, P256, P384, P521],
            vec![X25519],
            false,
        ),
        (
            "26.0",
            Os::Ios,
            false,
            vec![X25519_MLKEM768, X25519, P256, P384, P521],
            vec![X25519_MLKEM768, X25519],
            false,
        ),
        (
            "27.0",
            Os::MacOS,
            false,
            vec![X25519_MLKEM768, X25519, P256, P384, P521],
            vec![X25519_MLKEM768, X25519],
            false,
        ),
    ] {
        let mut profile = koon_core::Safari::version(version, os).unwrap();
        profile.tls.danger_accept_invalid_certs = true;
        let client = Client::builder(profile).build().unwrap();
        let url = format!("https://localhost:{}/", server.port);
        let first = client.get(&url).await.expect("first request");
        let second = client.get(&url).await.expect("second request");
        assert!(!first.tls_resumed && !second.tls_resumed, "{version}");
        assert!(!second.connection_reused);

        let hellos = server.hellos.lock().unwrap().clone();
        for exts in &hellos[hellos.len() - 2..] {
            let all = types(exts);
            let mut expected = ORDER.to_vec();
            // Padding to 512 bytes; the ML-KEM key share makes the hello
            // longer.
            if legacy {
                expected.push(0x0015);
            }
            let order: Vec<u16> = all.iter().copied().filter(|t| !is_grease(*t)).collect();
            assert_eq!(order, expected, "{version} {os}");
            assert!(is_grease(all[0]) && is_grease(all[14]), "{all:04x?}");
            assert!(!all.contains(&PRE_SHARED_KEY) && !all.contains(&SESSION_TICKET));
            let versions: &[u16] = if legacy {
                &[0x0304, 0x0303, 0x0302, 0x0301]
            } else {
                &[0x0304, 0x0303]
            };
            assert_eq!(supported_versions(exts), versions, "{version} {os}");
            let offered: Vec<u16> = u16s(exts, 0x000a)
                .into_iter()
                .filter(|g| !is_grease(*g))
                .collect();
            assert_eq!(offered, groups, "{version} {os}");
            let with_shares: Vec<u16> = key_share_groups(exts)
                .into_iter()
                .filter(|g| !is_grease(*g))
                .collect();
            assert_eq!(with_shares, shares, "{version} {os}");
            let sigalgs = u16s(exts, SIGNATURE_ALGORITHMS);
            assert_eq!(sigalgs.contains(&0x0203), sha1, "{version} {os}");
            assert_eq!(sigalgs.len(), if sha1 { 11 } else { 10 });
            // Padded to 512 bytes like the captures: 188 bytes there with
            // ecdsa_sha1, 190 without, for a server name 9 bytes longer
            // (`www.cloudflare.com`) than `localhost`.
            if legacy {
                let padding = exts.iter().find(|(t, _)| *t == 0x0015).unwrap();
                assert_eq!(
                    padding.1.len(),
                    if sha1 { 188 + 9 } else { 190 + 9 },
                    "{version} {os}"
                );
            }
        }
    }
}
