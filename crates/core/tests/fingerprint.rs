//! Integration tests that verify TLS + HTTP/2 fingerprints against real servers.
//!
//! These tests hit `https://tls.browserleaks.com/json` and assert JA4, Akamai hash,
//! and Akamai text against reference values captured from real browsers.
//!
//! Run with: `cargo test --test fingerprint -- --ignored`

use koon_core::{Chrome, Client, Edge, Firefox};
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

// ========== Edge Tests ==========

#[tokio::test]
#[ignore]
async fn test_edge_145_fingerprint() {
    // Edge uses the same Chromium TLS/H2 engine → same fingerprint hashes as Chrome
    let client = Client::new(Edge::v145_windows()).expect("client creation failed");
    let fp = fetch_fingerprint(&client).await;
    assert_fingerprint(&fp, &CHROME_NEW_ALPS, "Edge 145");
}
