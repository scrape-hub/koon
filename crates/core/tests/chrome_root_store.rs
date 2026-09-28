//! Generates the embedded Chrome Root Store from the Chromium source.
//!
//! `src/tls/root_store/chrome_root_store.rs` holds the TLS trust anchors of
//! the Chrome Root Store versions listed in `SOURCES`: the `trust_anchors`
//! of `net/data/ssl/chrome_root_store/root_store.textproto` and the
//! `additional_certs` marked `tls_trust_anchor` (intermediates Chrome trusts
//! as anchors of their own), with the certificates from `root_store.certs`
//! and `additional.certs` and their trust anchor IDs — what Chromium's
//! `root_store_tool` compiles into `kChromeRootCertList`. Anchor
//! constraints are left out; koon does not evaluate them.
//!
//! The test rebuilds the file from the pinned commits and fails when the
//! checked-in one differs. With `KOON_WRITE_CHROME_ROOT_STORE=1` it writes
//! the file instead:
//!
//! ```text
//! cargo test -p koon-core --test chrome_root_store -- --ignored
//! KOON_WRITE_CHROME_ROOT_STORE=1 cargo test -p koon-core --test chrome_root_store -- --ignored
//! ```
//!
//! To embed the store of another Chrome release, add the head commit of its
//! branch (`https://chromium.googlesource.com/chromium/src/+/refs/branch-heads/<branch>?format=JSON`,
//! the branch of a milestone is listed at
//! `https://chromiumdash.appspot.com/fetch_milestones`) to `SOURCES` and
//! regenerate. The file maps every Chrome release of `SOURCES` to its store,
//! and the profile of that release sends the store's trust anchor IDs.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine;
use btls::hash::{MessageDigest, hash};
use koon_core::{Client, Firefox};

/// A Chromium commit whose Chrome Root Store is embedded.
struct Source {
    /// The Chrome release that ships it.
    chrome: u32,
    /// Release branch of that Chrome version.
    branch: &'static str,
    /// Head of the branch when the file was generated.
    commit: &'static str,
}

/// Oldest first; bit `i` of an anchor's `stores` (a `u32`) stands for
/// `SOURCES[i]`.
const SOURCES: &[Source] = &[
    Source {
        chrome: 152,
        branch: "refs/branch-heads/7977",
        commit: "b5a375accc1213427d4730a6144a86addd0cc28b",
    },
    Source {
        chrome: 153,
        branch: "refs/branch-heads/8010",
        commit: "a192098bfdd0e91a6cb96634133a45bbfe4223ba",
    },
    Source {
        chrome: 154,
        branch: "refs/branch-heads/8037",
        commit: "9a212a3eab789e5b13e390d024973319974a03f5",
    },
    Source {
        chrome: 155,
        branch: "refs/branch-heads/8059",
        commit: "e24ae319d443797cc818accf6db294264d8c472b",
    },
];

const STORE_DIR: &str = "net/data/ssl/chrome_root_store";

const OUTPUT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/tls/root_store/chrome_root_store.rs"
);

/// An entry of root_store.textproto.
struct Entry {
    kind: Kind,
    /// First line of the comment above the entry: the subject.
    name: String,
    sha256: String,
    trust_anchor_id: Vec<u8>,
    tls_trust_anchor: bool,
}

#[derive(PartialEq)]
enum Kind {
    /// `trust_anchors`: roots, all of them TLS anchors.
    Root,
    /// `additional_certs`: TLS anchors when marked `tls_trust_anchor`, else
    /// certificates for QWAC verification.
    Additional,
    /// `mtc_anchors`: Merkle Tree Certificate logs (Chrome's MTC
    /// experiment), not X.509 certificates. koon does not verify MTCs, and
    /// Chrome sends their IDs only with the experiment enabled.
    Mtc,
}

/// The TLS trust anchors of one store version.
struct Store {
    version: u32,
    anchors: Vec<Entry>,
    /// Certificates by SHA-256.
    certs: HashMap<String, Vec<u8>>,
}

/// A file of the store at `commit`. Gitiles answers `?format=TEXT` with the
/// file in base64, and at times with a transient 503 (for curl as well, often
/// several in a row), hence up to ten attempts over about a minute.
async fn fetch(client: &Client, commit: &str, file: &str) -> Vec<u8> {
    let url = format!(
        "https://chromium.googlesource.com/chromium/src/+/{commit}/{STORE_DIR}/{file}?format=TEXT"
    );
    let mut last = String::new();
    for attempt in 1..=10u64 {
        match client.get(&url).await {
            Ok(resp) if resp.status == 200 => {
                let text: String = String::from_utf8_lossy(&resp.body)
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                match base64::engine::general_purpose::STANDARD.decode(text) {
                    Ok(body) => return body,
                    Err(e) => last = format!("invalid base64: {e}"),
                }
            }
            Ok(resp) => last = format!("status {}", resp.status),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(2 * attempt.min(5))).await;
    }
    panic!("fetching {url}: {last}");
}

/// The content of the first quoted string in `value`, still escaped.
fn quoted(value: &str) -> &str {
    let start = value.find('"').expect("quoted string") + 1;
    let bytes = value.as_bytes();
    let mut i = start;
    while bytes[i] != b'"' {
        i += if bytes[i] == b'\\' { 2 } else { 1 };
    }
    &value[start..i]
}

/// Bytes of a protobuf text format string.
fn unescape(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let c = bytes[i + 1];
        i += 2;
        match c {
            b'x' | b'X' => {
                let digits = bytes[i..]
                    .iter()
                    .take(2)
                    .take_while(|b| b.is_ascii_hexdigit())
                    .count();
                out.push(u8::from_str_radix(&s[i..i + digits], 16).unwrap());
                i += digits;
            }
            b'0'..=b'7' => {
                let digits = 1 + bytes[i..]
                    .iter()
                    .take(2)
                    .take_while(|b| (b'0'..=b'7').contains(b))
                    .count();
                out.push(u8::from_str_radix(&s[i - 1..i - 1 + digits], 8).unwrap());
                i += digits - 1;
            }
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'v' => out.push(0x0b),
            other => out.push(other),
        }
    }
    out
}

/// The version and the entries of root_store.textproto.
fn parse_textproto(text: &str) -> (u32, Vec<Entry>) {
    let mut version = None;
    let mut entries = Vec::new();
    let mut comments: Vec<String> = Vec::new();
    let mut current: Option<Entry> = None;
    let mut depth = 0;
    for line in text.lines().map(str::trim) {
        let Some(entry) = current.as_mut() else {
            if let Some(comment) = line.strip_prefix('#') {
                comments.push(comment.trim().trim_matches('"').to_string());
                continue;
            }
            if line.is_empty() {
                comments.clear();
                continue;
            }
            if let Some(v) = line.strip_prefix("version_major:") {
                version = Some(v.trim().parse().expect("version_major"));
            } else {
                let kind = match line {
                    "trust_anchors {" => Kind::Root,
                    "additional_certs {" => Kind::Additional,
                    "mtc_anchors {" => Kind::Mtc,
                    _ => panic!("unexpected line in root_store.textproto: {line}"),
                };
                current = Some(Entry {
                    kind,
                    name: comments.first().cloned().unwrap_or_default(),
                    sha256: String::new(),
                    trust_anchor_id: Vec::new(),
                    tls_trust_anchor: false,
                });
                depth = 1;
            }
            comments.clear();
            continue;
        };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.ends_with('{') {
            depth += 1;
            continue;
        }
        if line == "}" {
            depth -= 1;
            if depth == 0 {
                entries.push(current.take().unwrap());
            }
            continue;
        }
        if depth > 1 {
            continue; // constraints
        }
        let (key, value) = line.split_once(':').expect("field");
        match key.trim() {
            "sha256_hex" => entry.sha256 = quoted(value).to_ascii_lowercase(),
            "trust_anchor_id" => entry.trust_anchor_id = unescape(quoted(value)),
            "tls_trust_anchor" => entry.tls_trust_anchor = value.trim().starts_with("true"),
            "der" => panic!("inline certificates are not supported"),
            _ => {}
        }
    }
    assert!(current.is_none(), "unterminated entry");
    (version.expect("version_major"), entries)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Certificates of a .certs file (PEM blocks between text dumps) by SHA-256.
fn pem_certs(text: &str) -> HashMap<String, Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certs = HashMap::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let body = &rest[start + BEGIN.len()..];
        let end = body.find(END).expect("END CERTIFICATE");
        let b64: String = body[..end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("PEM base64");
        let digest = hash(MessageDigest::sha256(), &der).unwrap();
        certs.insert(hex(&digest), der);
        rest = &body[end + END.len()..];
    }
    certs
}

async fn load(client: &Client, source: &Source) -> Store {
    let textproto = fetch(client, source.commit, "root_store.textproto").await;
    let (version, entries) = parse_textproto(std::str::from_utf8(&textproto).unwrap());
    let mut certs = HashMap::new();
    for file in ["root_store.certs", "additional.certs"] {
        let pem = fetch(client, source.commit, file).await;
        certs.extend(pem_certs(std::str::from_utf8(&pem).unwrap()));
    }
    // Chromium: every trust anchor is a TLS anchor; additional certificates
    // only when marked so (the others serve QWAC verification).
    let anchors: Vec<Entry> = entries
        .into_iter()
        .filter(|e| e.kind == Kind::Root || e.kind == Kind::Additional && e.tls_trust_anchor)
        .collect();
    for anchor in &anchors {
        assert!(
            certs.contains_key(&anchor.sha256),
            "version {version}: no certificate for {} ({})",
            anchor.sha256,
            anchor.name
        );
    }
    Store {
        version,
        anchors,
        certs,
    }
}

/// A trust anchor ID as dotted relative OID.
fn relative_oid(id: &[u8]) -> String {
    let mut arcs = Vec::new();
    let mut arc: u64 = 0;
    for &b in id {
        arc = arc << 7 | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(arc.to_string());
            arc = 0;
        }
    }
    arcs.join(".")
}

fn render(stores: &[Store]) -> String {
    // The union of all versions: the newest one's anchors in textproto
    // order, then those only older versions have.
    assert!(stores.len() <= 32, "`stores` is a u32 bitmask");
    let mut order: Vec<&Entry> = Vec::new();
    let mut membership: HashMap<&str, u32> = HashMap::new();
    for (i, store) in stores.iter().enumerate().rev() {
        for anchor in &store.anchors {
            let bits = membership.entry(anchor.sha256.as_str()).or_insert_with(|| {
                order.push(anchor);
                0
            });
            *bits |= 1 << i;
        }
    }
    // One ID per certificate across versions.
    for store in stores {
        for anchor in &store.anchors {
            let first = order.iter().find(|e| e.sha256 == anchor.sha256).unwrap();
            assert_eq!(
                first.trust_anchor_id, anchor.trust_anchor_id,
                "trust anchor ID of {} differs between versions",
                anchor.name
            );
        }
    }

    let mut out = String::new();
    out.push_str(
        "// @generated by tests/chrome_root_store.rs from the Chromium source. Do not edit.\n\
         //\n\
         // The TLS trust anchors of the Chrome Root Store: the `trust_anchors` of\n\
         // root_store.textproto and the `additional_certs` marked `tls_trust_anchor`,\n\
         // with their certificates from root_store.certs and additional.certs.\n\
         // Anchor constraints are left out. The data comes from Chromium: Copyright\n\
         // 2015 The Chromium Authors, BSD-3-Clause license (LICENSE in the Chromium\n\
         // source; the binaries ship its text in THIRD-PARTY-LICENSES.md). Sources, in\n\
         // https://chromium.googlesource.com/chromium/src/+/<commit>/net/data/ssl/chrome_root_store/\n\
         //\n",
    );
    for (store, source) in stores.iter().zip(SOURCES) {
        writeln!(
            out,
            "// version {}: Chrome {}, {} at {}",
            store.version, source.chrome, source.branch, source.commit
        )
        .unwrap();
    }
    out.push_str("\nuse super::ChromeAnchor;\n\n");
    let releases: Vec<String> = stores
        .iter()
        .zip(SOURCES)
        .map(|(store, source)| format!("({}, {})", source.chrome, store.version))
        .collect();
    out.push_str(
        "/// The Chrome releases whose store is embedded, oldest first, as (Chrome\n\
         /// major, store `version_major`). Bit `i` of an anchor's `stores` stands\n\
         /// for `RELEASES[i]`.\n",
    );
    writeln!(
        out,
        "pub(super) const RELEASES: [(u32, u32); {}] = [{}];\n",
        stores.len(),
        releases.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "pub(super) static ANCHORS: [ChromeAnchor; {}] = [",
        order.len()
    )
    .unwrap();
    for anchor in order {
        let mut notes = Vec::new();
        if anchor.kind == Kind::Additional {
            notes.push("intermediate".to_string());
        }
        if !anchor.trust_anchor_id.is_empty() {
            notes.push(format!(
                "trust anchor ID {}",
                relative_oid(&anchor.trust_anchor_id)
            ));
        }
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!(" ({})", notes.join(", "))
        };
        let der = stores
            .iter()
            .find_map(|s| s.certs.get(&anchor.sha256))
            .unwrap();
        let id: String = anchor
            .trust_anchor_id
            .iter()
            .map(|b| format!("\\x{b:02x}"))
            .collect();
        writeln!(out, "    // {}{notes}", anchor.name).unwrap();
        writeln!(out, "    ChromeAnchor {{").unwrap();
        writeln!(out, "        sha256: \"{}\",", anchor.sha256).unwrap();
        writeln!(out, "        trust_anchor_id: b\"{id}\",").unwrap();
        writeln!(
            out,
            "        stores: {:#0width$b},",
            membership[anchor.sha256.as_str()],
            width = stores.len() + 2
        )
        .unwrap();
        writeln!(
            out,
            "        der: \"{}\",",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
        .unwrap();
        writeln!(out, "    }},").unwrap();
    }
    out.push_str("];\n");
    out
}

#[tokio::test]
#[ignore]
async fn chrome_root_store_matches_the_chromium_source() {
    // Firefox verifies against Mozilla's roots, independent of the file
    // this test produces.
    let client = Client::new(Firefox::latest()).unwrap();
    let mut stores = Vec::new();
    for source in SOURCES {
        stores.push(load(&client, source).await);
    }
    for (pair, sources) in stores.windows(2).zip(SOURCES.windows(2)) {
        assert!(
            sources[0].chrome < sources[1].chrome && pair[0].version <= pair[1].version,
            "SOURCES oldest first"
        );
    }
    let generated = render(&stores);

    if std::env::var_os("KOON_WRITE_CHROME_ROOT_STORE").is_some() {
        std::fs::write(OUTPUT, &generated).unwrap();
        return;
    }
    let current = std::fs::read_to_string(OUTPUT)
        .unwrap()
        .replace("\r\n", "\n");
    assert!(
        current == generated,
        "{OUTPUT} is out of date; rerun with KOON_WRITE_CHROME_ROOT_STORE=1"
    );
}

#[test]
fn parses_protobuf_text_strings() {
    assert_eq!(unescape(r"\xd6\x79\x09\x01"), [0xd6, 0x79, 0x09, 0x01]);
    assert_eq!(unescape(r"\326y\t\001"), [0xd6, b'y', 0x09, 0x01]);
    assert_eq!(quoted(r#" "\x83\"x"  # 52580"#), r#"\x83\"x"#);
    assert_eq!(
        relative_oid(&[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a]),
        "52580.200109.1.10"
    );
    assert_eq!(relative_oid(&[0x82, 0xdf, 0x13, 0x02, 0x01]), "44947.2.1");
}
