//! Integration tests that verify TLS + HTTP/2 fingerprints against real servers.
//!
//! These tests hit `https://tls.browserleaks.com/json` and assert JA4, Akamai hash,
//! and Akamai text against reference values captured from real browsers.
//!
//! Run with: `cargo test --test fingerprint -- --ignored`

use koon_core::{Chrome, Client, Edge, Firefox, Safari};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FingerprintResponse {
    ja3_hash: String,
    ja3n_hash: String,
    ja4: String,
    akamai_hash: String,
    akamai_text: String,
}

/// Reference hashes from tools/capture/raw/ browser captures.
struct Expected {
    ja4: &'static str,
    akamai_hash: &'static str,
    akamai_text: &'static str,
}

// Chrome 131–134 (old ALPS codepoint 0x4469)
const CHROME_OLD_ALPS: Expected = Expected {
    ja4: "t13d1516h2_8daaf6152771_02713d6af862",
    akamai_hash: "52d84b11737d980aef856699f885ca86",
    akamai_text: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
};

// Chrome 135–145 (new ALPS codepoint 0x44CD)
const CHROME_NEW_ALPS: Expected = Expected {
    ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
    akamai_hash: "52d84b11737d980aef856699f885ca86",
    akamai_text: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
};

// Firefox 135–147 (identical fingerprint across all versions)
const FIREFOX: Expected = Expected {
    ja4: "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
    akamai_hash: "6ea73faa8fc5aac76bded7bd238f6433",
    akamai_text: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
};

async fn fetch_fingerprint(client: &Client) -> FingerprintResponse {
    let resp = client
        .get("https://tls.browserleaks.com/json")
        .await
        .expect("request to tls.browserleaks.com failed");
    assert_eq!(resp.status, 200, "expected 200 from browserleaks");
    serde_json::from_slice(&resp.body).expect("failed to parse fingerprint JSON")
}

fn assert_fingerprint(fp: &FingerprintResponse, expected: &Expected, profile_name: &str) {
    let mut failed = false;
    let mut msg = format!("Fingerprint mismatch for {profile_name}:\n");

    if fp.ja4 != expected.ja4 {
        msg.push_str(&format!(
            "  ja4:         actual={}\n               expected={}\n",
            fp.ja4, expected.ja4
        ));
        failed = true;
    }
    if fp.akamai_hash != expected.akamai_hash {
        msg.push_str(&format!(
            "  akamai_hash: actual={}\n               expected={}\n",
            fp.akamai_hash, expected.akamai_hash
        ));
        failed = true;
    }
    if fp.akamai_text != expected.akamai_text {
        msg.push_str(&format!(
            "  akamai_text: actual={}\n               expected={}\n",
            fp.akamai_text, expected.akamai_text
        ));
        failed = true;
    }

    if failed {
        msg.push_str(&format!(
            "\n  Debug info:\n    ja3_hash:  {}\n    ja3n_hash: {}\n    ja4:       {}\n    akamai:    {}\n    text:      {}",
            fp.ja3_hash, fp.ja3n_hash, fp.ja4, fp.akamai_hash, fp.akamai_text
        ));
        panic!("{msg}");
    }
}

// ========== Chrome Tests ==========

#[tokio::test]
#[ignore]
async fn test_chrome_131_fingerprint() {
    let client = Client::new(Chrome::v131_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &CHROME_OLD_ALPS, "Chrome 131");
}

#[tokio::test]
#[ignore]
async fn test_chrome_135_fingerprint() {
    let client = Client::new(Chrome::v135_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &CHROME_NEW_ALPS, "Chrome 135");
}

#[tokio::test]
#[ignore]
async fn test_chrome_145_fingerprint() {
    let client = Client::new(Chrome::v145_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &CHROME_NEW_ALPS, "Chrome 145");
}

// ========== Firefox Tests ==========

#[tokio::test]
#[ignore]
async fn test_firefox_135_fingerprint() {
    let client = Client::new(Firefox::v135_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &FIREFOX, "Firefox 135");
}

#[tokio::test]
#[ignore]
async fn test_firefox_147_fingerprint() {
    let client = Client::new(Firefox::v147_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &FIREFOX, "Firefox 147");
}

// ========== Safari Tests ==========
// Safari akamai_hash verified against real Safari 18.2 capture (curl_cffi#460).
// JA4 sigalg hash (3rd segment) differs from real Safari due to BoringSSL internals,
// so we only assert the JA4 prefix+cipher hash, plus the exact akamai fingerprint.

// Safari 15.6–16.0, 18.0: same TLS (legacy sigalgs), same H2 (4MB window)
const SAFARI_LEGACY_4MB: Expected = Expected {
    ja4: "t13d2014h2_a09f3c656075_2a6581477f52",
    akamai_hash: "959a7e813b79b909a1a0b00a38e8bba3",
    akamai_text: "2:0;4:4194304;3:100|10485760|0|m,s,p,a",
};

// Safari 17.0: same TLS, 2MB window
const SAFARI_LEGACY_2MB: Expected = Expected {
    ja4: "t13d2014h2_a09f3c656075_2a6581477f52",
    akamai_hash: "ad8424af1cc590e09f7b0c499bf7fcdb",
    akamai_text: "2:0;4:2097152;3:100|10485760|0|m,s,p,a",
};

// Safari 18.3: new sigalgs (ecdsa_sha1 removed), 4MB window
const SAFARI_V18_3: Expected = Expected {
    ja4: "t13d2014h2_a09f3c656075_cfb9b458de2a",
    akamai_hash: "959a7e813b79b909a1a0b00a38e8bba3",
    akamai_text: "2:0;4:4194304;3:100|10485760|0|m,s,p,a",
};

// ========== Edge Tests ==========

#[tokio::test]
#[ignore]
async fn test_edge_145_fingerprint() {
    // Edge uses the same Chromium TLS/H2 engine → same fingerprint hashes as Chrome
    let client = Client::new(Edge::v145_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &CHROME_NEW_ALPS, "Edge 145");
}

// ========== Safari Tests ==========

#[tokio::test]
#[ignore]
async fn test_safari_15_6_fingerprint() {
    let client = Client::new(Safari::v15_6_macos()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &SAFARI_LEGACY_4MB, "Safari 15.6");
}

#[tokio::test]
#[ignore]
async fn test_safari_17_0_fingerprint() {
    let client = Client::new(Safari::v17_0_macos()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &SAFARI_LEGACY_2MB, "Safari 17.0");
}

#[tokio::test]
#[ignore]
async fn test_safari_18_0_fingerprint() {
    let client = Client::new(Safari::v18_0_macos()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &SAFARI_LEGACY_4MB, "Safari 18.0");
}

#[tokio::test]
#[ignore]
async fn test_safari_18_3_fingerprint() {
    let client = Client::new(Safari::v18_3_macos()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &SAFARI_V18_3, "Safari 18.3");
}
