//! Offline tests of the QUIC ClientHello.
//!
//! koon's HTTP/3 client connects to a local UDP socket that records its
//! datagrams and never answers. The test derives the Initial keys from the
//! destination connection ID (RFC 9001 §5.2), removes header protection,
//! decrypts the Initial packets, reassembles the CRYPTO stream and checks
//! the ClientHello and its transport parameters against captures of Chrome
//! 153, Firefox 155 to 157 and Safari on macOS 14.7 to 27.0 and iOS 17.0.1
//! to 27.0, as `clienthello.rs` does for TCP. A
//! local HTTPS server advertises the UDP port in Alt-Svc, and
//! `ClientBuilder::resolve` points a test hostname at both.
//!
//! Only full handshakes are covered: resuming needs a server that issues
//! tickets. What differs between connections by design (extension and
//! parameter order, GREASE values, random lengths) is checked for its
//! range.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use btls::hash::MessageDigest;
use btls::hmac::Hmac;
use btls::symm::{Cipher, decrypt_aead, encrypt};
use koon_core::{BrowserProfile, Chrome, Client, Firefox};
use tokio::net::UdpSocket;

/// Test hostname: sent as SNI, pointed at 127.0.0.1 by `resolve`.
const HOST: &str = "quic.koon.test";

// ============================================================
// Initial packet protection (RFC 9001 §5)
// ============================================================

/// initial_salt of QUIC version 1 (RFC 9001 §5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::init(key, &MessageDigest::sha256()).unwrap();
    hmac.update(data).unwrap();
    hmac.finalize().unwrap()
}

/// HKDF-Expand-Label with an empty context (RFC 8446 §7.1), for outputs of
/// at most one SHA-256 block.
fn hkdf_expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    let label = format!("tls13 {label}");
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info.push(1); // HKDF-Expand block counter
    let mut out = hmac_sha256(secret, &info);
    out.truncate(len);
    out
}

/// The client's Initial packet protection keys.
struct InitialKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
}

fn client_initial_keys(dcid: &[u8]) -> InitialKeys {
    let initial_secret = hmac_sha256(&INITIAL_SALT_V1, dcid);
    let secret = hkdf_expand_label(&initial_secret, "client in", 32);
    InitialKeys {
        key: hkdf_expand_label(&secret, "quic key", 16),
        iv: hkdf_expand_label(&secret, "quic iv", 12),
        hp: hkdf_expand_label(&secret, "quic hp", 16),
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn initial_keys_match_rfc9001_appendix_a() {
    let keys = client_initial_keys(&hex("8394c8f03e515708"));
    assert_eq!(keys.key, hex("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(keys.iv, hex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(keys.hp, hex("9f50449e04a0e810283a1e9933adedd2"));
}

fn varint(buf: &[u8], p: &mut usize) -> u64 {
    let len = 1 << (buf[*p] >> 6);
    let mut value = u64::from(buf[*p] & 0x3f);
    for i in 1..len {
        value = (value << 8) | u64::from(buf[*p + i]);
    }
    *p += len;
    value
}

/// A decrypted client Initial packet.
struct Initial {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    pn: u64,
    /// Frame types in order (`PADDING` runs count once).
    frames: Vec<&'static str>,
    /// CRYPTO frames: offset and data.
    crypto: Vec<(u64, Vec<u8>)>,
    /// Bytes of the datagram the packet took.
    packet_len: usize,
}

/// Remove header protection from the long-header packet at the start of
/// `buf` and decrypt it. `None` for anything but an Initial.
fn open_initial(buf: &[u8], keys_for: &dyn Fn(&[u8]) -> InitialKeys) -> Option<Initial> {
    let first = buf[0];
    if first & 0x80 == 0 || (first >> 4) & 0x03 != 0 {
        return None;
    }
    assert_eq!(&buf[1..5], &[0, 0, 0, 1], "QUIC version 1");
    let mut p = 5;
    let dcid = buf[p + 1..p + 1 + buf[p] as usize].to_vec();
    p += 1 + dcid.len();
    let scid = buf[p + 1..p + 1 + buf[p] as usize].to_vec();
    p += 1 + scid.len();
    let token_len = varint(buf, &mut p) as usize;
    p += token_len;
    let length = varint(buf, &mut p) as usize;
    let pn_offset = p;

    let keys = keys_for(&dcid);
    let sample = &buf[pn_offset + 4..pn_offset + 20];
    let mask = encrypt(Cipher::aes_128_ecb(), &keys.hp, None, sample).unwrap();
    let mut header = buf[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    header.truncate(pn_offset + pn_len);
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(header[pn_offset + i]);
    }
    let end = pn_offset + length;
    let mut nonce = keys.iv.clone();
    for (i, byte) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= byte;
    }
    let payload = decrypt_aead(
        Cipher::aes_128_gcm(),
        &keys.key,
        Some(&nonce),
        &header,
        &buf[pn_offset + pn_len..end - 16],
        &buf[end - 16..end],
    )
    .expect("Initial packet decrypts");

    let mut frames = Vec::new();
    let mut crypto = Vec::new();
    let mut q = 0;
    while q < payload.len() {
        match payload[q] {
            0x00 => {
                while q < payload.len() && payload[q] == 0 {
                    q += 1;
                }
                frames.push("PADDING");
            }
            0x01 => {
                q += 1;
                frames.push("PING");
            }
            0x06 => {
                q += 1;
                let offset = varint(&payload, &mut q);
                let len = varint(&payload, &mut q) as usize;
                crypto.push((offset, payload[q..q + len].to_vec()));
                q += len;
                frames.push("CRYPTO");
            }
            other => panic!("unexpected frame type {other:#x} in a client Initial"),
        }
    }
    Some(Initial {
        dcid,
        scid,
        pn,
        frames,
        crypto,
        packet_len: end,
    })
}

// ============================================================
// ClientHello
// ============================================================

/// What a QUIC client sent before any answer.
struct Flight {
    /// Sizes of the datagrams.
    datagrams: Vec<usize>,
    /// Initial packets, one per datagram (koon and the browsers never
    /// coalesce two Initials).
    initials: Vec<Initial>,
    hello: ClientHello,
}

struct ClientHello {
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    fn parse(msg: &[u8]) -> Self {
        assert_eq!(msg[0], 0x01, "ClientHello");
        let u16_at = |p: usize| u16::from_be_bytes([msg[p], msg[p + 1]]);
        let mut p = 4 + 2 + 32;
        p += 1 + msg[p] as usize; // session_id
        let ciphers = u16_list(&msg[p + 2..p + 2 + u16_at(p) as usize]);
        p += 2 + u16_at(p) as usize;
        p += 1 + msg[p] as usize; // compression_methods
        let end = p + 2 + u16_at(p) as usize;
        p += 2;
        let mut extensions = Vec::new();
        while p < end {
            let len = u16_at(p + 2) as usize;
            extensions.push((u16_at(p), msg[p + 4..p + 4 + len].to_vec()));
            p += 4 + len;
        }
        ClientHello {
            ciphers,
            extensions,
        }
    }

    fn types(&self) -> Vec<u16> {
        self.extensions.iter().map(|(t, _)| *t).collect()
    }

    fn sorted_types(&self) -> Vec<u16> {
        let mut types = self.types();
        types.sort_unstable();
        types
    }

    fn ext(&self, ty: u16) -> &[u8] {
        self.extensions
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, d)| d.as_slice())
            .unwrap_or_else(|| panic!("extension {ty:#06x} missing"))
    }

    /// A list of u16 behind a 2-byte length (signature_algorithms,
    /// supported_groups, delegated_credentials).
    fn u16s(&self, ty: u16) -> Vec<u16> {
        u16_list(&self.ext(ty)[2..])
    }

    /// Groups of the key_share extension.
    fn key_shares(&self) -> Vec<u16> {
        let data = self.ext(KEY_SHARE);
        let mut groups = Vec::new();
        let mut p = 2;
        while p + 4 <= data.len() {
            groups.push(u16::from_be_bytes([data[p], data[p + 1]]));
            p += 4 + u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        }
        groups
    }

    /// compress_certificate algorithms (1-byte length).
    fn cert_compression(&self) -> Vec<u16> {
        u16_list(&self.ext(0x001b)[1..])
    }

    fn server_name(&self) -> String {
        String::from_utf8(self.ext(0x0000)[5..].to_vec()).unwrap()
    }

    /// quic_transport_parameters: id and raw value, in wire order.
    fn transport_parameters(&self) -> Vec<(u64, Vec<u8>)> {
        let data = self.ext(QUIC_TRANSPORT_PARAMETERS);
        let mut params = Vec::new();
        let mut p = 0;
        while p < data.len() {
            let id = varint(data, &mut p);
            let len = varint(data, &mut p) as usize;
            params.push((id, data[p..p + len].to_vec()));
            p += len;
        }
        params
    }

    /// Integer transport parameters by id, GREASE ones apart.
    fn tp_values(&self) -> BTreeMap<u64, Vec<u8>> {
        self.transport_parameters()
            .into_iter()
            .filter(|(id, _)| !is_grease_tp(*id))
            .collect()
    }

    fn has_grease(&self) -> bool {
        let grease16 = |v: u16| v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff;
        self.ciphers.iter().any(|&c| grease16(c))
            || self.types().into_iter().any(grease16)
            || self.u16s(SUPPORTED_GROUPS).into_iter().any(grease16)
            || self.key_shares().into_iter().any(grease16)
            || u16_list(&self.ext(SUPPORTED_VERSIONS)[1..])
                .into_iter()
                .any(grease16)
    }
}

fn u16_list(data: &[u8]) -> Vec<u16> {
    data.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn tp_int(value: &[u8]) -> u64 {
    let mut p = 0;
    let v = varint(value, &mut p);
    assert_eq!(p, value.len(), "varint fills the value");
    v
}

fn is_grease_tp(id: u64) -> bool {
    id % 31 == 27
}

const SUPPORTED_GROUPS: u16 = 0x000a;
const SIGNATURE_ALGORITHMS: u16 = 0x000d;
const DELEGATED_CREDENTIALS: u16 = 0x0022;
const SUPPORTED_VERSIONS: u16 = 0x002b;
const KEY_SHARE: u16 = 0x0033;
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
const ALPS: u16 = 0x44cd;
const ECH: u16 = 0xfe0d;
const EXTENDED_MASTER_SECRET: u16 = 0x0017;
const RENEGOTIATION_INFO: u16 = 0xff01;

// ============================================================
// Capture
// ============================================================

/// Let koon open an HTTP/3 connection to a UDP socket that never answers,
/// and decrypt what it sent until its ClientHello is complete.
async fn capture(mut profile: BrowserProfile) -> Flight {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let tcp_port = common::alt_svc_server(HOST, udp_port).await;
    profile.tls.danger_accept_invalid_certs = true;
    let local = |port| SocketAddr::from(([127, 0, 0, 1], port));
    let client = Client::builder(profile)
        .resolve(HOST, local(tcp_port))
        .resolve(HOST, local(udp_port))
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");

    // The first response advertises HTTP/3; the next connection tries it.
    let first = client.get(&url).await.expect("request over TCP");
    assert_eq!(first.status, 200);
    client.close();
    let second = tokio::spawn(async move { client.get(&url).await });

    let mut datagrams = Vec::new();
    let mut initials: Vec<Initial> = Vec::new();
    let mut buf = vec![0u8; 65_536];
    let hello = loop {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .expect("koon sends QUIC Initials")
            .unwrap();
        let datagram = buf[..n].to_vec();
        // Every Initial before the server's first answer uses the keys of
        // the first destination connection ID.
        let odcid = initials
            .first()
            .map(|i| i.dcid.clone())
            .unwrap_or_else(|| datagram[6..6 + datagram[5] as usize].to_vec());
        let initial =
            open_initial(&datagram, &|_| client_initial_keys(&odcid)).expect("a client Initial");
        datagrams.push(n);
        initials.push(initial);
        if let Some(message) = reassemble(&initials) {
            break ClientHello::parse(&message);
        }
    };

    // TCP takes over the request once QUIC's head start is over.
    let second = second
        .await
        .unwrap()
        .expect("request after the QUIC attempt");
    assert_eq!(second.status, 200);
    assert_ne!(second.version, "h3");

    Flight {
        datagrams,
        initials,
        hello,
    }
}

/// The ClientHello message, once the CRYPTO frames hold all of it.
fn reassemble(initials: &[Initial]) -> Option<Vec<u8>> {
    let mut stream = Vec::new();
    let mut frames: Vec<&(u64, Vec<u8>)> = initials.iter().flat_map(|i| &i.crypto).collect();
    frames.sort_by_key(|(offset, _)| *offset);
    for (offset, data) in frames {
        let offset = *offset as usize;
        if offset > stream.len() {
            return None;
        }
        let end = offset + data.len();
        if end > stream.len() {
            stream.extend_from_slice(&data[stream.len() - offset..]);
        }
    }
    if stream.len() < 4 {
        return None;
    }
    let len = 4 + ((stream[1] as usize) << 16 | (stream[2] as usize) << 8 | stream[3] as usize);
    (stream.len() >= len).then(|| stream[..len].to_vec())
}

// ============================================================
// Chrome 153
// ============================================================

/// Extensions of Chrome 153's QUIC ClientHello (full handshake), sorted;
/// the order is permuted on every connection.
const CHROME_EXTENSIONS: &[u16] = &[
    0x0000, 0x000a, 0x000d, 0x0010, 0x001b, 0x002b, 0x002d, 0x0033, 0x0039, 0x44cd, 0xca34, 0xfe0d,
];

const CHROME_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

/// Size of every datagram of Chrome's first flight.
const CHROME_DATAGRAM: usize = 1250;

const TRUST_ANCHORS: u16 = 0xca34;

/// Chrome 154's trust_anchors extension: the 28 IDs of Chrome Root Store
/// version 39, sorted. Captured over TCP from Chrome for Testing 154;
/// Chromium 154 hands QUIC the same pre-encoded list
/// (`SSLContextConfig::SelectAllTrustAnchorIDs`). Chrome 153 sends these IDs
/// in QUIC too, 186 bytes, in a new order on each connection.
const CHROME_154_TRUST_ANCHORS: &str = "00b80582df1302010582df1302060582df13020d0582df13020e\
    0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d0108\
    08839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b\
    2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604\
    d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f";

/// The IDs of a trust_anchors payload in wire order.
fn trust_anchor_ids(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut ids = Vec::new();
    let mut p = 2;
    while p < payload.len() {
        let len = payload[p] as usize;
        ids.push(payload[p + 1..p + 1 + len].to_vec());
        p += 1 + len;
    }
    ids
}

/// Chrome `major` on `os` whose client is in the group of
/// `PqcBandwidthExperiment` that asks for `bytes`, or with `None` outside
/// the trial (which 94 % of the clients are).
fn chrome_in_padding_trial(major: u32, os: koon_core::Os, bytes: Option<u16>) -> BrowserProfile {
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

/// The latest Chrome, outside `PqcBandwidthExperiment`.
fn chrome_latest() -> BrowserProfile {
    chrome_in_padding_trial(Chrome::LATEST_VERSION, koon_core::Os::Windows, None)
}

#[tokio::test]
async fn chrome_quic_hello_matches_the_browser() {
    let flight = capture(chrome_latest()).await;
    let hello = &flight.hello;

    assert_eq!(hello.server_name(), HOST);
    assert_eq!(hello.ciphers, [0x1301, 0x1302, 0x1303]);
    assert!(!hello.has_grease(), "Chrome sends no GREASE in QUIC");
    assert_eq!(hello.sorted_types(), CHROME_EXTENSIONS);
    assert_eq!(hello.u16s(SIGNATURE_ALGORITHMS), CHROME_SIGALGS);
    assert_eq!(
        hello.u16s(SUPPORTED_GROUPS),
        [0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(hello.key_shares(), [0x11ec, 0x001d]);
    assert_eq!(hello.cert_compression(), [0x0002]);
    assert_eq!(hello.ext(0x0010), b"\x00\x03\x02h3");
    assert_eq!(hello.ext(0x002d), [0x01, 0x01]);
    assert_eq!(hello.ext(ALPS), b"\x00\x03\x02h3");
    // ECH outer: type 0, HKDF-SHA256, AES-128-GCM, config ID, 32-byte enc,
    // payload of 144, 176, 208 or 240 bytes (BoringSSL).
    let ech = hello.ext(ECH);
    assert_eq!(ech[..5], [0x00, 0x00, 0x01, 0x00, 0x01]);
    assert_eq!(u16::from_be_bytes([ech[6], ech[7]]), 32);
    let payload = u16::from_be_bytes([ech[40], ech[41]]);
    assert!([144, 176, 208, 240].contains(&payload), "{payload}");
    assert_eq!(hello.ext(TRUST_ANCHORS), hex(CHROME_154_TRUST_ANCHORS));
}

#[tokio::test]
async fn chrome_153_quic_hello_carries_its_trust_anchor_ids() {
    // The same 28 IDs as Chrome 154, in a random order (per connection, see
    // the connector's unit tests).
    let flight = capture(Chrome::version(153, koon_core::Os::Windows).unwrap()).await;
    let payload = flight.hello.ext(TRUST_ANCHORS);
    assert_eq!(payload.len(), 186);
    let mut ids = trust_anchor_ids(payload);
    ids.sort();
    assert_eq!(ids, trust_anchor_ids(&hex(CHROME_154_TRUST_ANCHORS)));
}

/// A Chrome client in `PqcBandwidthExperiment`: the QUIC ClientHello plus
/// server_padding (0x12E0) asking for its group's padding, as over TCP
/// (captured from Chrome 153 on Android 17, which asked for 4000 bytes).
#[tokio::test]
async fn chrome_quic_hello_in_the_padding_trial_requests_server_padding() {
    let profile = chrome_in_padding_trial(153, koon_core::Os::Android, Some(16_000));
    let flight = capture(profile).await;
    let hello = &flight.hello;
    let mut expected = CHROME_EXTENSIONS.to_vec();
    expected.push(0x12e0);
    expected.sort_unstable();
    assert_eq!(hello.sorted_types(), expected);
    assert_eq!(hello.ext(0x12e0), 16_000u16.to_be_bytes());
    assert!(flight.datagrams.iter().all(|&n| n == CHROME_DATAGRAM));
}

#[tokio::test]
async fn chrome_transport_parameters_match_the_browser() {
    let flight = capture(chrome_latest()).await;
    let hello = &flight.hello;
    let tp = hello.tp_values();
    let ids: Vec<u64> = tp.keys().copied().collect();
    assert_eq!(
        ids,
        [
            0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0f, 0x11, 0x20, 0x3128
        ]
    );
    let int = |id: u64| tp_int(&tp[&id]);
    assert_eq!(int(0x01), 30_000);
    assert_eq!(int(0x03), 1472);
    assert_eq!(int(0x04), 15_728_640);
    assert_eq!(int(0x05), 6_291_456);
    assert_eq!(int(0x06), 6_291_456);
    assert_eq!(int(0x07), 6_291_456);
    assert_eq!(int(0x08), 100);
    assert_eq!(int(0x09), 103);
    assert_eq!(int(0x20), 65_536);
    assert!(tp[&0x0f].is_empty(), "empty source connection ID");
    assert_eq!(tp[&0x3128], b"ORIG");
    // version_information: chosen v1, then v1 and a GREASE version in
    // random order.
    let info = &tp[&0x11];
    assert_eq!(info.len(), 12);
    assert_eq!(info[..4], [0, 0, 0, 1]);
    let available = [&info[4..8], &info[8..12]];
    assert!(available.contains(&&[0, 0, 0, 1][..]));
    assert!(available.iter().any(|v| v.iter().all(|b| b & 0x0f == 0x0a)));
    // One GREASE parameter of up to 15 bytes (quiche).
    let grease: Vec<(u64, Vec<u8>)> = hello
        .transport_parameters()
        .into_iter()
        .filter(|(id, _)| is_grease_tp(*id))
        .collect();
    assert_eq!(grease.len(), 1);
    assert!(grease[0].1.len() < 16);
}

#[tokio::test]
async fn chrome_initial_packets_match_the_browser() {
    let flight = capture(chrome_latest()).await;
    // Chrome's full ClientHello, 1948-1984 bytes with its trust anchor IDs,
    // takes two Initials.
    assert_eq!(flight.initials.len(), 2);
    // Connection IDs: 8-byte Initial DCID, empty own ID.
    let first = &flight.initials[0];
    assert_eq!(first.dcid.len(), 8);
    assert!(first.scid.is_empty());
    // Every Initial datagram is 1250 bytes, padded with PADDING frames
    // inside the packet.
    assert!(
        flight.datagrams.iter().all(|&n| n == CHROME_DATAGRAM),
        "{:?}",
        flight.datagrams
    );
    assert!(
        flight
            .initials
            .iter()
            .all(|i| i.packet_len == CHROME_DATAGRAM)
    );
    // One packet number counter across all spaces, starting at 1.
    let pns: Vec<u64> = flight.initials.iter().map(|i| i.pn).collect();
    assert_eq!(pns, (1..=pns.len() as u64).collect::<Vec<_>>());
    // Chaos protection: the ClientHello in fragments, with PING and PADDING
    // frames between them, in a random order. A random order can come out
    // ascending (about one flight in 120 with five fragments), so a flight
    // in order is captured again before the test gives up.
    assert!(first.frames.contains(&"PING"), "{:?}", first.frames);
    assert!(first.frames.contains(&"PADDING"));
    assert!(first.crypto.len() > 2, "{:?}", first.crypto);
    let shuffled = |flight: &Flight| {
        flight.initials.iter().any(|initial| {
            let offsets: Vec<u64> = initial.crypto.iter().map(|(o, _)| *o).collect();
            offsets.windows(2).any(|w| w[0] > w[1])
        })
    };
    let mut attempts = 1;
    let mut flight = flight;
    while !shuffled(&flight) && attempts < 3 {
        flight = capture(chrome_latest()).await;
        attempts += 1;
    }
    assert!(
        shuffled(&flight),
        "CRYPTO frames in order in {attempts} flights"
    );
}

/// The ClientHello of the latest connection that went through `relay`.
fn relayed_hello(relay: &common::h3::Relay) -> ClientHello {
    let datagrams = relay.last_client().long_header_datagrams;
    let odcid = datagrams[0][6..6 + datagrams[0][5] as usize].to_vec();
    let mut initials = Vec::new();
    for datagram in &datagrams {
        if let Some(initial) = open_initial(datagram, &|_| client_initial_keys(&odcid)) {
            initials.push(initial);
        }
        if let Some(message) = reassemble(&initials) {
            return ClientHello::parse(&message);
        }
    }
    panic!("no complete ClientHello in {} datagrams", datagrams.len());
}

/// Chrome sends the smoothed RTT of the last connection to a server, in
/// microseconds, as google_initial_rtt (0x3127) on the next one
/// (`QuicSessionPool::ConfigureInitialRttEstimate`); the first connection
/// has none. The relay delays the server's datagrams by 40 ms.
#[tokio::test]
async fn chrome_sends_the_rtt_of_the_last_connection() {
    let (cert, key) = common::leaf(HOST);
    let server = common::h3::h3_server(cert, key);
    let relay = common::h3::Relay::start(server.addr).await;
    let tcp_port = common::alt_svc_server(HOST, relay.addr.port()).await;
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let local = |port| SocketAddr::from(([127, 0, 0, 1], port));
    let client = Client::builder(profile)
        .resolve(HOST, local(tcp_port))
        .resolve(HOST, relay.addr)
        .build()
        .unwrap();
    let url = format!("https://{HOST}:{tcp_port}/");
    assert_ne!(client.get(&url).await.unwrap().version, "h3");
    client.close();

    assert_eq!(client.get(&url).await.unwrap().version, "h3");
    assert!(!relayed_hello(&relay).tp_values().contains_key(&0x3127));
    // The RTT is remembered when the connection's last reference drops,
    // asynchronously after `close()` returns; there is no external signal
    // for that cleanup finishing, so this waits it out instead of racing it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.close();

    assert_eq!(client.get(&url).await.unwrap().version, "h3");
    let tp = relayed_hello(&relay).tp_values();
    let rtt = tp_int(&tp[&0x3127]);
    assert!((40_000..200_000).contains(&rtt), "{rtt} µs");
}

// ============================================================
// Firefox 156 and 157
// ============================================================

/// Extensions of the QUIC ClientHello of Firefox 155 to 157 (full
/// handshake), sorted.
const FIREFOX_EXTENSIONS: &[u16] = &[
    0x0000, 0x0005, 0x000a, 0x000d, 0x0010, 0x0017, 0x001b, 0x001c, 0x0022, 0x002b, 0x002d, 0x0033,
    0x0039, 0xfe0d, 0xff01,
];

/// Signature algorithms of the 157 beta (and 155): no ML-DSA.
const FIREFOX_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201,
];

const FIREFOX_DC_SIGALGS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];

/// Firefox 156 offers ML-DSA after the RSA-PSS schemes.
const FIREFOX_156_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0904, 0x0905, 0x0906, 0x0401, 0x0501,
    0x0601, 0x0201,
];

const FIREFOX_156_DC_SIGALGS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203, 0x0904, 0x0905, 0x0906];

/// Size of every datagram of Firefox's first flight.
const FIREFOX_DATAGRAM: usize = 1252;

#[tokio::test]
async fn firefox_quic_hello_matches_the_browser() {
    let flight = capture(Firefox::latest()).await;
    let hello = &flight.hello;

    assert_eq!(hello.server_name(), HOST);
    assert_eq!(hello.ciphers, [0x1301, 0x1303, 0x1302]);
    assert!(!hello.has_grease());
    assert_eq!(hello.sorted_types(), FIREFOX_EXTENSIONS);
    // Permuted, with quic_transport_parameters and ECH pinned at the end.
    let types = hello.types();
    assert_eq!(types[types.len() - 2..], [QUIC_TRANSPORT_PARAMETERS, ECH]);
    assert_eq!(hello.ext(EXTENDED_MASTER_SECRET), b"");
    assert_eq!(hello.ext(RENEGOTIATION_INFO), [0x00]);
    assert_eq!(hello.u16s(SIGNATURE_ALGORITHMS), FIREFOX_SIGALGS);
    assert_eq!(hello.u16s(DELEGATED_CREDENTIALS), FIREFOX_DC_SIGALGS);
    assert_eq!(
        hello.u16s(SUPPORTED_GROUPS),
        [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
    );
    assert_eq!(hello.key_shares(), [0x11ec, 0x001d, 0x0017]);
    // zlib, zstd, brotli.
    assert_eq!(hello.cert_compression(), [0x0001, 0x0003, 0x0002]);
    assert_eq!(hello.ext(0x001c), 16_385u16.to_be_bytes());
    assert_eq!(hello.ext(0x0005), [0x01, 0x00, 0x00, 0x00, 0x00]);
    // ECH outer: HKDF-SHA256, AES-128-GCM or ChaCha20-Poly1305, 32-byte
    // enc, a 240-byte payload for a full handshake to a 14-character name
    // (NSS pads the name to 100 bytes).
    let ech = hello.ext(ECH);
    assert_eq!(ech[..3], [0x00, 0x00, 0x01]);
    assert!([[0x00, 0x01], [0x00, 0x03]].contains(&[ech[3], ech[4]]));
    assert_eq!(u16::from_be_bytes([ech[6], ech[7]]), 32);
    assert_eq!(u16::from_be_bytes([ech[40], ech[41]]), 240);
}

/// Firefox 156's QUIC ClientHello offered ML-DSA; 155 and the 157 beta do
/// not, and none offers the finite-field groups of the TCP hello.
#[tokio::test]
async fn firefox_156_quic_hello_offers_mldsa() {
    let hello = capture(Firefox::version(156, koon_core::Os::Windows).unwrap())
        .await
        .hello;
    assert_eq!(hello.u16s(SIGNATURE_ALGORITHMS), FIREFOX_156_SIGALGS);
    assert_eq!(hello.u16s(DELEGATED_CREDENTIALS), FIREFOX_156_DC_SIGALGS);
    assert_eq!(hello.sorted_types(), FIREFOX_EXTENSIONS);
    let hello = capture(Firefox::version(155, koon_core::Os::Windows).unwrap())
        .await
        .hello;
    assert_eq!(hello.u16s(SIGNATURE_ALGORITHMS), FIREFOX_SIGALGS);
    assert_eq!(hello.u16s(DELEGATED_CREDENTIALS), FIREFOX_DC_SIGALGS);
    assert_eq!(
        hello.u16s(SUPPORTED_GROUPS),
        [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
    );
}

#[tokio::test]
async fn firefox_transport_parameters_match_the_browser() {
    let flight = capture(Firefox::latest()).await;
    let params = flight.hello.transport_parameters();
    // Fixed order, no GREASE parameter.
    let ids: Vec<u64> = params.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        [
            0x01,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0b,
            0x0e,
            0x0f,
            0x11,
            0x1d,
            0xff02_de1a,
            0x20
        ]
    );
    let tp: BTreeMap<u64, Vec<u8>> = params.into_iter().collect();
    let int = |id: u64| tp_int(&tp[&id]);
    assert_eq!(int(0x01), 30_000);
    assert_eq!(int(0x04), 25_165_824);
    assert_eq!(int(0x05), 12_582_912);
    assert_eq!(int(0x06), 1_048_576);
    assert_eq!(int(0x07), 1_048_576);
    assert_eq!(int(0x08), 100);
    assert_eq!(int(0x09), 100);
    assert_eq!(int(0x0b), 20);
    assert_eq!(int(0x0e), 8);
    assert_eq!(tp[&0x0f].len(), 3);
    assert!(tp[&0x1d].is_empty());
    assert_eq!(int(0xff02_de1a), 1000);
    assert_eq!(int(0x20), 65_535);
    // version_information: chosen v1; available GREASE, v2, v1.
    let info = &tp[&0x11];
    assert_eq!(info.len(), 16);
    assert_eq!(info[..4], [0, 0, 0, 1]);
    assert!(info[4..8].iter().all(|b| b & 0x0f == 0x0a));
    assert_eq!(info[8..], [0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1]);
}

/// Firefox up to 154 offers QUIC version 1 only: version_information holds
/// GREASE and v1. Its neqo does not know reset_stream_at (captured from the
/// 146 to 154 betas on Android).
#[tokio::test]
async fn firefox_154_offers_quic_version_1_only() {
    let flight = capture(Firefox::version(154, koon_core::Os::Windows).unwrap()).await;
    let params = flight.hello.transport_parameters();
    let ids: Vec<u64> = params.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        [
            0x01,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0b,
            0x0e,
            0x0f,
            0x11,
            0xff02_de1a,
            0x20
        ]
    );
    let tp: BTreeMap<u64, Vec<u8>> = params.into_iter().collect();
    let info = &tp[&0x11];
    assert_eq!(info.len(), 12);
    assert_eq!(info[..4], [0, 0, 0, 1]);
    assert!(info[4..8].iter().all(|b| b & 0x0f == 0x0a));
    assert_eq!(info[8..], [0, 0, 0, 1]);
}

#[tokio::test]
async fn firefox_initial_packets_match_the_browser() {
    let flight = capture(Firefox::latest()).await;
    // neqo's greased Initial DCID length, 3-byte own connection IDs.
    let first = &flight.initials[0];
    assert!((8..=20).contains(&first.dcid.len()));
    assert_eq!(first.scid.len(), 3);
    // Every datagram is 1252 bytes: the packet itself is not padded, zero
    // bytes follow it.
    assert!(
        flight.datagrams.iter().all(|&n| n == FIREFOX_DATAGRAM),
        "{:?}",
        flight.datagrams
    );
    assert!(
        flight
            .initials
            .iter()
            .all(|i| i.packet_len < FIREFOX_DATAGRAM && !i.frames.contains(&"PADDING"))
    );
    // neqo starts the Initial packet numbers at a random value of at least
    // 1 and counts on without gaps.
    let pns: Vec<u64> = flight.initials.iter().map(|i| i.pn).collect();
    assert!(pns[0] >= 1);
    assert!(pns.windows(2).all(|w| w[1] == w[0] + 1), "{pns:?}");
    // SNI slicing: the first packet carries the ClientHello's end, then its
    // start, cut inside the server name.
    let offsets: Vec<u64> = first.crypto.iter().map(|(o, _)| *o).collect();
    assert_eq!(offsets.len(), 2, "{offsets:?}");
    assert!(offsets[0] > 0 && offsets[1] == 0, "{offsets:?}");
}

// ============================================================
// Safari (Apple's QUIC stack)
// ============================================================

/// A Safari profile that follows Alt-Svc, which the capture needs: macOS
/// 15.1 and 15.2 and iOS 18.0 to 18.2 find HTTP/3 only through HTTPS
/// records (or not at all).
fn safari(version: &str, os: koon_core::Os) -> BrowserProfile {
    let mut profile = koon_core::Safari::version(version, os).unwrap();
    profile.quic.as_mut().unwrap().alt_svc = true;
    profile
}

/// Safari's QUIC ClientHello, as captured from Safari on macOS 14.7 to 27.0
/// and iOS 17.0.1 to 27.0: the TCP hello without the TLS 1.2 extensions, in
/// BoringSSL's order, GREASE included, ALPN `h3`; the ciphers, groups and
/// signature algorithms of the release's TCP hello (ecdsa_sha1 up to macOS
/// 15.1 and iOS 18.1, X25519MLKEM768 and AES-256 first from 26 on).
#[tokio::test]
async fn safari_quic_hello_matches_the_browser() {
    use koon_core::Os;
    let grease16 = |v: u16| v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff;
    for (version, os, tahoe, sha1) in [
        ("17.0", Os::MacOS, false, true),
        ("17.0", Os::Ios, false, true),
        ("18.1", Os::MacOS, false, true),
        ("18.4", Os::MacOS, false, false),
        ("18.3", Os::Ios, false, false),
        ("27.0", Os::MacOS, true, false),
    ] {
        let hello = capture(safari(version, os)).await.hello;
        assert_eq!(hello.server_name(), HOST);
        let ciphers: Vec<u16> = hello
            .ciphers
            .iter()
            .copied()
            .filter(|c| !grease16(*c))
            .collect();
        let expected_ciphers: &[u16] = if tahoe {
            &[0x1302, 0x1303, 0x1301]
        } else {
            &[0x1301, 0x1302, 0x1303]
        };
        assert_eq!(ciphers, expected_ciphers, "{version} {os}");
        let types = hello.types();
        assert!(grease16(types[0]) && grease16(types[types.len() - 1]));
        let types: Vec<u16> = types.into_iter().filter(|t| !grease16(*t)).collect();
        assert_eq!(
            types,
            [
                0x0000, 0x000a, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x0039,
                0x001b
            ],
            "{version} {os}"
        );
        assert_eq!(hello.ext(0x0010), b"\x00\x03\x02h3");
        let groups: Vec<u16> = hello
            .u16s(SUPPORTED_GROUPS)
            .into_iter()
            .filter(|g| !grease16(*g))
            .collect();
        let shares: Vec<u16> = hello
            .key_shares()
            .into_iter()
            .filter(|g| !grease16(*g))
            .collect();
        if tahoe {
            assert_eq!(groups, [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]);
            assert_eq!(shares, [0x11ec, 0x001d]);
        } else {
            assert_eq!(groups, [0x001d, 0x0017, 0x0018, 0x0019], "{version} {os}");
            assert_eq!(shares, [0x001d], "{version} {os}");
        }
        let sigalgs: &[u16] = if sha1 {
            &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601,
                0x0201,
            ]
        } else {
            &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]
        };
        assert_eq!(hello.u16s(SIGNATURE_ALGORITHMS), sigalgs, "{version} {os}");
        assert_eq!(hello.cert_compression(), [0x0001]);
    }
}

/// Safari's transport parameters (captured) in one cyclic order from a
/// random start: max_idle_timeout on 27, initial_max_streams_bidi (8) on
/// macOS 15.1 to 15.4 and iOS 18.3 and 18.4, 103 unidirectional streams on
/// macOS 14 and iOS 17 and 8 later; active_connection_id_limit although its
/// own connection ID is empty; no GREASE, version_information or
/// max_udp_payload_size. The private `0xff080808` follows the cycle: 4 on
/// macOS 15.4 to 15.7, 6 on iOS 18.4 and 18.5, 7 on 26.0 to 26.3.
#[tokio::test]
async fn safari_transport_parameters_match_the_browser() {
    use koon_core::Os;
    const CYCLE: [u64; 9] = [0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f];
    const PRIVATE: u64 = 0xff08_0808;
    for (version, os, idle, bidi, uni, private) in [
        ("27.0", Os::MacOS, Some(300_000), None, 8, None),
        ("26.6", Os::MacOS, None, None, 8, None),
        ("26.2", Os::MacOS, None, None, 8, Some(7)),
        ("26.0", Os::Ios, None, None, 8, Some(7)),
        ("18.5", Os::Ios, None, None, 8, Some(6)),
        ("18.5", Os::MacOS, None, None, 8, Some(4)),
        ("18.4", Os::MacOS, None, Some(8), 8, Some(4)),
        ("18.3", Os::Ios, None, Some(8), 8, None),
        ("18.2", Os::MacOS, None, Some(8), 8, None),
        ("17.0", Os::MacOS, None, None, 103, None),
        ("17.0", Os::Ios, None, None, 103, None),
    ] {
        let hello = capture(safari(version, os)).await.hello;
        let params = hello.transport_parameters();
        let ids: Vec<u64> = params.iter().map(|(id, _)| *id).collect();
        let (cycled, rest) = ids.split_at(ids.len() - usize::from(private.is_some()));
        let sent: Vec<u64> = CYCLE
            .iter()
            .copied()
            .filter(|id| (*id != 0x01 || idle.is_some()) && (*id != 0x08 || bidi.is_some()))
            .collect();
        let start = sent
            .iter()
            .position(|id| *id == cycled[0])
            .expect("a known start");
        let mut rotated = sent.clone();
        rotated.rotate_left(start);
        assert_eq!(cycled, rotated, "{version} {os}");
        let tp = hello.tp_values();
        match private {
            Some(value) => {
                assert_eq!(rest, [PRIVATE], "{version} {os}");
                assert_eq!(tp[&PRIVATE], [value], "{version} {os}");
            }
            None => assert!(rest.is_empty()),
        }
        let int = |id: u64| tp_int(&tp[&id]);
        if let Some(idle) = idle {
            assert_eq!(int(0x01), idle);
        }
        assert_eq!(int(0x04), 16_777_216);
        assert_eq!(int(0x05), 2_097_152);
        assert_eq!(int(0x06), 2_097_152);
        assert_eq!(int(0x07), 2_097_152);
        if let Some(bidi) = bidi {
            assert_eq!(int(0x08), bidi, "{version} {os}");
        }
        assert_eq!(int(0x09), uni, "{version} {os}");
        assert_eq!(int(0x0e), 64);
        assert!(tp[&0x0f].is_empty(), "empty source connection ID");
    }
}

/// Safari's first flight (captured): 1200-byte Initials from packet number
/// 0, an 8-byte destination and an empty source connection ID, the
/// ClientHello in CRYPTO frames of at most 999 bytes, each packet padded
/// with PADDING frames. From 26 on the X25519MLKEM768 key share needs two
/// Initials; before, the hello fits into one.
#[tokio::test]
async fn safari_initial_packets_match_the_browser() {
    use koon_core::Os;
    for (version, os, packets) in [
        ("27.0", Os::MacOS, 2),
        ("26.0", Os::Ios, 2),
        ("18.5", Os::MacOS, 1),
        ("17.0", Os::Ios, 1),
    ] {
        let flight = capture(safari(version, os)).await;
        assert_eq!(flight.initials.len(), packets, "{version} {os}");
        assert!(
            flight.datagrams.iter().all(|&n| n == 1200),
            "{:?}",
            flight.datagrams
        );
        let first = &flight.initials[0];
        assert_eq!(first.dcid.len(), 8);
        assert!(first.scid.is_empty());
        let pns: Vec<u64> = flight.initials.iter().map(|i| i.pn).collect();
        assert_eq!(pns, (0..packets as u64).collect::<Vec<_>>());
        let crypto: Vec<(u64, usize)> = flight
            .initials
            .iter()
            .flat_map(|i| i.crypto.iter().map(|(o, d)| (*o, d.len())))
            .collect();
        assert_eq!(crypto.len(), packets, "{version} {os}");
        assert_eq!(crypto[0].0, 0);
        if packets == 2 {
            assert_eq!(crypto[0], (0, 999));
            assert_eq!(crypto[1].0, 999);
        } else {
            assert!(crypto[0].1 < 999, "{crypto:?}");
        }
        for initial in &flight.initials {
            assert_eq!(
                initial.frames,
                ["CRYPTO", "PADDING"],
                "{:?}",
                initial.frames
            );
        }
    }
}

// ============================================================
// ECH over QUIC (real config from a DNS HTTPS record)
// ============================================================

/// A real ECHConfigList (HKDF-SHA256, AES-128-GCM, `config_id` 0x5a,
/// public_name "cloudflare-ech.com"), captured over DoH from a real
/// domain's HTTPS record (`crates/core/src/tls/ech_grease.rs`'s GREASE
/// tests already cover the shape without one). BoringSSL only needs it
/// well-formed to send real ECH, not a key it could complete a
/// handshake with: the peer here never answers regardless.
#[cfg(feature = "doh")]
const REAL_ECH_CONFIG_LIST: &[u8] = &[
    0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x5a, 0x00, 0x20, 0x00, 0x20, 0x03, 0x58, 0x44, 0x6e, 0x4e,
    0xfd, 0x09, 0x83, 0x1b, 0x1f, 0x79, 0xdc, 0x5a, 0x17, 0x50, 0x80, 0xa0, 0x5d, 0x4f, 0x26, 0x13,
    0xec, 0xd7, 0x6c, 0x91, 0xd9, 0x2d, 0x75, 0x8a, 0xea, 0x5b, 0x4c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63,
    0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

/// A UDP nameserver that answers a `host` HTTPS query with `alpn=h3`,
/// `port=port` (the URL's own port: Chromium ignores a record on another
/// one) and `ech=REAL_ECH_CONFIG_LIST`, so
/// a fresh client's very first connection to it tries QUIC with real ECH,
/// not GREASE (see `tests/https_rr.rs` for the same server without an ECH
/// config).
#[cfg(feature = "doh")]
async fn ech_dns_server(host: &str, port: u16) -> SocketAddr {
    use hickory_proto::rr::rdata::svcb::{Alpn, EchConfigList, SvcParamKey, SvcParamValue};

    let params = vec![
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h3".to_string()])),
        ),
        (SvcParamKey::Port, SvcParamValue::Port(port)),
        (
            SvcParamKey::EchConfigList,
            SvcParamValue::EchConfigList(EchConfigList(REAL_ECH_CONFIG_LIST.to_vec())),
        ),
    ];
    common::fake_https_dns_server(host, params).await.0
}

/// The very first QUIC connection to a host whose DNS HTTPS record
/// carries an ECH config sends that config, not GREASE: matching
/// `set_ech_config_list` for TCP and captured live for QUIC (Chrome 154
/// and Firefox 157 against quic.browserleaks.com on Windows 11: real,
/// non-random kdf/aead and a config_id from the record, not GREASE's
/// random pick).
#[cfg(feature = "doh")]
#[tokio::test]
async fn ech_over_quic_uses_the_records_config_not_grease() {
    use koon_core::dns::NativeHttpsResolver;

    const ECH_HOST: &str = "quic-ech.koon.test";
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let dns_addr = ech_dns_server(ECH_HOST, udp_port).await;

    let mut profile = chrome_latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(ECH_HOST, SocketAddr::from(([127, 0, 0, 1], udp_port)))
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    // https_rr already finds `alpn=h3` on the first connection: no
    // Alt-Svc round trip, straight to QUIC, so a single request drives
    // it (unlike `capture`, which needs the Alt-Svc two-step).
    let url = format!("https://{ECH_HOST}:{udp_port}/");
    let request = tokio::spawn(async move { client.get(&url).await });

    let mut initials: Vec<Initial> = Vec::new();
    let mut buf = vec![0u8; 65_536];
    let hello = loop {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .expect("koon sends QUIC Initials")
            .unwrap();
        let datagram = buf[..n].to_vec();
        let odcid = initials
            .first()
            .map(|i| i.dcid.clone())
            .unwrap_or_else(|| datagram[6..6 + datagram[5] as usize].to_vec());
        let initial =
            open_initial(&datagram, &|_| client_initial_keys(&odcid)).expect("a client Initial");
        initials.push(initial);
        if let Some(message) = reassemble(&initials) {
            break ClientHello::parse(&message);
        }
    };
    drop(request); // never answered; no TCP fallback registered either

    let ech = hello.ext(ECH);
    // ClientECH: outer (type 0), HKDF-SHA256, AES-128-GCM, config_id
    // 0x5a from the record: never GREASE's random AEAD or config_id.
    assert_eq!(ech[..6], [0x00, 0x00, 0x01, 0x00, 0x01, 0x5a]);
    let enc_len = u16::from_be_bytes([ech[6], ech[7]]);
    assert_eq!(enc_len, 32);
}

/// Firefox's neqo forwards only a small allowlisted subset of transport
/// parameters into the ClientHelloOuter of a split ECH ClientHello: the
/// outer is only ever a fallback the server completes if it rejects the
/// real, encrypted one, so most parameters would be both meaningless there
/// and a source of real, distinguishing values a hello otherwise meant to
/// look generic should not carry (neqo's `filter_ch_outer`; of its 8-entry
/// allowlist, a stock client only ever gives three a value). Captured live:
/// Firefox 157 on Windows 11 against quic.browserleaks.com's real ECH
/// config sent exactly `max_ack_delay`, `initial_src_cid` and
/// `version_information`, ascending by id, decrypted from the QUIC
/// Initial: the same three `write_ech_outer` (quinn-proto) filters from
/// the real (inner, unaffected: see
/// `firefox_transport_parameters_match_the_browser`) set. Chrome's own
/// outer keeps the full set (also captured), so this is neqo (Firefox)
/// only (`QuicStack::Neqo`, `quic/transport.rs`'s `crypto_config`).
#[cfg(feature = "doh")]
#[tokio::test]
async fn firefox_ech_outer_hello_reduces_transport_parameters() {
    use koon_core::dns::NativeHttpsResolver;

    const ECH_HOST: &str = "quic-ech-firefox.koon.test";
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let dns_addr = ech_dns_server(ECH_HOST, udp_port).await;

    let mut profile = Firefox::latest();
    profile.tls.danger_accept_invalid_certs = true;
    let client = Client::builder(profile)
        .resolve(ECH_HOST, SocketAddr::from(([127, 0, 0, 1], udp_port)))
        .native_https_resolver(NativeHttpsResolver::with_nameserver(dns_addr))
        .build()
        .unwrap();

    let url = format!("https://{ECH_HOST}/");
    let request = tokio::spawn(async move { client.get(&url).await });

    let mut initials: Vec<Initial> = Vec::new();
    let mut buf = vec![0u8; 65_536];
    let hello = loop {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .expect("koon sends QUIC Initials")
            .unwrap();
        let datagram = buf[..n].to_vec();
        let odcid = initials
            .first()
            .map(|i| i.dcid.clone())
            .unwrap_or_else(|| datagram[6..6 + datagram[5] as usize].to_vec());
        let initial =
            open_initial(&datagram, &|_| client_initial_keys(&odcid)).expect("a client Initial");
        initials.push(initial);
        if let Some(message) = reassemble(&initials) {
            break ClientHello::parse(&message);
        }
    };
    drop(request); // never answered; no TCP fallback registered either

    let ech = hello.ext(ECH);
    assert_eq!(
        ech[..6],
        [0x00, 0x00, 0x01, 0x00, 0x01, 0x5a],
        "real ECH, not GREASE"
    );

    let params = hello.transport_parameters();
    let ids: Vec<u64> = params.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        [0x0b, 0x0f, 0x11],
        "max_ack_delay, initial_src_cid, version_information: ascending, nothing else"
    );
    let tp: BTreeMap<u64, Vec<u8>> = params.into_iter().collect();
    assert_eq!(
        tp_int(&tp[&0x0b]),
        20,
        "the same max_ack_delay as the full (inner) set"
    );
    assert_eq!(
        tp[&0x0f].len(),
        3,
        "an initial_src_cid, the same length as the full (inner) set"
    );
    let info = &tp[&0x11];
    assert_eq!(
        info.len(),
        16,
        "the same version_information as the full (inner) set"
    );
    assert_eq!(info[..4], [0, 0, 0, 1], "chosen: v1");
}
