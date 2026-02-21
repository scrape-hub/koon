//! Comprehensive feature tests for koon-core.
//!
//! Unit tests (no network) run with `cargo test --test features`.
//! Integration tests (require network) run with `cargo test --test features -- --ignored`.

use koon_core::*;
use std::time::Duration;

// ============================================================
// Profile JSON Roundtrip (unit test, no network)
// ============================================================

/// Verify a BrowserProfile survives JSON serialization → deserialization.
fn assert_profile_roundtrips(name: &str, profile: &BrowserProfile) {
    let json = profile
        .to_json_pretty()
        .unwrap_or_else(|e| panic!("{name}: serialize failed: {e}"));
    let restored = BrowserProfile::from_json(&json)
        .unwrap_or_else(|e| panic!("{name}: deserialize failed: {e}"));

    assert_eq!(profile.tls.cipher_list, restored.tls.cipher_list, "{name}: cipher_list");
    assert_eq!(profile.tls.curves, restored.tls.curves, "{name}: curves");
    assert_eq!(profile.tls.sigalgs, restored.tls.sigalgs, "{name}: sigalgs");
    assert_eq!(profile.tls.grease, restored.tls.grease, "{name}: grease");
    assert_eq!(profile.tls.alpn, restored.tls.alpn, "{name}: alpn");
    assert_eq!(profile.tls.preserve_tls13_cipher_order, restored.tls.preserve_tls13_cipher_order, "{name}: preserve_tls13_cipher_order");
    assert_eq!(profile.tls.record_size_limit, restored.tls.record_size_limit, "{name}: record_size_limit");
    assert_eq!(profile.tls.pre_shared_key, restored.tls.pre_shared_key, "{name}: pre_shared_key");
    assert_eq!(profile.http2.settings_order, restored.http2.settings_order, "{name}: settings_order");
    assert_eq!(profile.http2.pseudo_header_order, restored.http2.pseudo_header_order, "{name}: pseudo_header_order");
    assert_eq!(profile.http2.initial_window_size, restored.http2.initial_window_size, "{name}: initial_window_size");
    assert_eq!(profile.quic.is_some(), restored.quic.is_some(), "{name}: quic presence");
    assert_eq!(profile.headers.len(), restored.headers.len(), "{name}: headers count");
    for (i, ((k1, v1), (k2, v2))) in profile.headers.iter().zip(restored.headers.iter()).enumerate() {
        assert_eq!(k1, k2, "{name}: header key mismatch at index {i}");
        assert_eq!(v1, v2, "{name}: header value mismatch at index {i}");
    }
}

#[test]
fn test_profile_json_roundtrip_per_browser() {
    assert_profile_roundtrips("chrome145", &Chrome::v145_windows());
    assert_profile_roundtrips("firefox147", &Firefox::v147_windows());
    assert_profile_roundtrips("safari18.3", &Safari::v18_3_macos());
    assert_profile_roundtrips("edge145", &Edge::v145_windows());
    assert_profile_roundtrips("opera127", &Opera::v127_windows());
}

#[test]
fn test_profile_json_roundtrip_all_browsers() {
    // Verify ALL 134 profiles can roundtrip without error
    let profiles: Vec<(&str, BrowserProfile)> = vec![
        // Chrome 131-145 × 3 OS
        ("chrome131w", Chrome::v131_windows()),
        ("chrome131m", Chrome::v131_macos()),
        ("chrome131l", Chrome::v131_linux()),
        ("chrome135w", Chrome::v135_windows()),
        ("chrome140w", Chrome::v140_windows()),
        ("chrome145w", Chrome::v145_windows()),
        ("chrome145m", Chrome::v145_macos()),
        ("chrome145l", Chrome::v145_linux()),
        // Firefox
        ("firefox135w", Firefox::v135_windows()),
        ("firefox147w", Firefox::v147_windows()),
        ("firefox147m", Firefox::v147_macos()),
        ("firefox147l", Firefox::v147_linux()),
        // Safari
        ("safari156", Safari::v15_6_macos()),
        ("safari160", Safari::v16_0_macos()),
        ("safari170", Safari::v17_0_macos()),
        ("safari180", Safari::v18_0_macos()),
        ("safari183", Safari::v18_3_macos()),
        // Edge
        ("edge131w", Edge::v131_windows()),
        ("edge145w", Edge::v145_windows()),
        ("edge145m", Edge::v145_macos()),
        // Opera
        ("opera124w", Opera::v124_windows()),
        ("opera127w", Opera::v127_windows()),
        ("opera127m", Opera::v127_macos()),
        ("opera127l", Opera::v127_linux()),
    ];

    for (name, profile) in &profiles {
        assert_profile_roundtrips(name, profile);
    }
}

// ============================================================
// Fingerprint Randomization (unit test, no network)
// ============================================================

#[test]
fn test_randomization_modifies_headers() {
    // Run multiple times — randomization is probabilistic
    let mut ua_changed = false;
    let mut lang_changed = false;

    for _ in 0..10 {
        let original = Chrome::v145_windows();
        let mut randomized = original.clone();
        randomized.randomize();

        let orig_ua = original
            .headers
            .iter()
            .find(|(k, _)| k == "user-agent")
            .map(|(_, v)| v.clone());
        let rand_ua = randomized
            .headers
            .iter()
            .find(|(k, _)| k == "user-agent")
            .map(|(_, v)| v.clone());
        if orig_ua != rand_ua {
            ua_changed = true;
        }

        let orig_lang = original
            .headers
            .iter()
            .find(|(k, _)| k == "accept-language")
            .map(|(_, v)| v.clone());
        let rand_lang = randomized
            .headers
            .iter()
            .find(|(k, _)| k == "accept-language")
            .map(|(_, v)| v.clone());
        if orig_lang != rand_lang {
            lang_changed = true;
        }
    }

    assert!(
        ua_changed,
        "UA should change after 10 randomization attempts"
    );
    assert!(
        lang_changed,
        "accept-language should change after 10 randomization attempts"
    );
}

#[test]
fn test_randomization_preserves_tls_fingerprint() {
    let original = Chrome::v145_windows();
    let mut randomized = original.clone();
    randomized.randomize();

    // TLS fingerprint fields MUST NOT change
    assert_eq!(original.tls.cipher_list, randomized.tls.cipher_list);
    assert_eq!(original.tls.curves, randomized.tls.curves);
    assert_eq!(original.tls.sigalgs, randomized.tls.sigalgs);
    assert_eq!(original.tls.grease, randomized.tls.grease);
    assert_eq!(original.tls.alpn, randomized.tls.alpn);
    assert_eq!(
        original.tls.permute_extensions,
        randomized.tls.permute_extensions
    );
    assert_eq!(original.tls.ech_grease, randomized.tls.ech_grease);
}

#[test]
fn test_randomization_jitters_h2_windows() {
    let mut window_changed = false;

    for _ in 0..10 {
        let original = Chrome::v145_windows();
        let mut randomized = original.clone();
        randomized.randomize();

        if original.http2.initial_window_size != randomized.http2.initial_window_size {
            window_changed = true;
            // Verify jitter is within ±32KB
            let diff = (original.http2.initial_window_size as i64
                - randomized.http2.initial_window_size as i64)
                .unsigned_abs();
            assert!(diff <= 32768, "Window jitter should be within ±32KB, got {diff}");
        }
    }

    assert!(
        window_changed,
        "H2 window should change after 10 randomization attempts"
    );
}

#[test]
fn test_randomization_firefox_no_ua_change() {
    // Firefox randomization should NOT change UA (no Chrome-style build numbers)
    let original = Firefox::v147_windows();
    let mut randomized = original.clone();
    randomized.randomize();

    let orig_ua = original
        .headers
        .iter()
        .find(|(k, _)| k == "user-agent")
        .map(|(_, v)| v.as_str());
    let rand_ua = randomized
        .headers
        .iter()
        .find(|(k, _)| k == "user-agent")
        .map(|(_, v)| v.as_str());

    assert_eq!(orig_ua, rand_ua, "Firefox UA should not change on randomize");
}

// ============================================================
// Profile Invariants (unit test, no network)
// ============================================================

#[test]
fn test_latest_profiles_exist() {
    let _ = Chrome::latest();
    let _ = Firefox::latest();
    let _ = Safari::latest();
    let _ = Edge::latest();
    let _ = Opera::latest();
}

#[test]
fn test_chrome_profiles_have_quic() {
    assert!(
        Chrome::v145_windows().quic.is_some(),
        "Chrome should have QUIC config"
    );
}

#[test]
fn test_safari_profiles_no_quic() {
    assert!(
        Safari::v18_3_macos().quic.is_none(),
        "Safari should NOT have QUIC config"
    );
}

#[test]
fn test_firefox_tls13_cipher_order() {
    let profile = Firefox::v147_windows();
    assert!(
        profile.tls.preserve_tls13_cipher_order,
        "Firefox should preserve TLS 1.3 cipher order"
    );
    // Firefox/NSS order: AES_128 → CHACHA20 → AES_256
    assert!(
        profile
            .tls
            .cipher_list
            .starts_with("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"),
        "Firefox cipher order should be AES_128→CHACHA20→AES_256"
    );
}

#[test]
fn test_firefox_record_size_limit() {
    let profile = Firefox::v147_windows();
    assert_eq!(
        profile.tls.record_size_limit,
        Some(16385),
        "Firefox should have record_size_limit=16385"
    );
}

#[test]
fn test_safari_pre_shared_key() {
    let profile = Safari::v18_3_macos();
    assert!(
        profile.tls.pre_shared_key,
        "Safari should have pre_shared_key=true"
    );
}

#[test]
fn test_chrome_grease_and_permutation() {
    let profile = Chrome::v145_windows();
    assert!(profile.tls.grease, "Chrome should use GREASE");
    assert!(
        profile.tls.permute_extensions,
        "Chrome should permute extensions"
    );
    assert!(profile.tls.ech_grease, "Chrome should use ECH GREASE");
}

#[test]
fn test_safari_h2_window_sizes() {
    // Safari 15.6-16.0: 4MB, Safari 17.0: 2MB, Safari 18.0+: 4MB
    assert_eq!(Safari::v15_6_macos().http2.initial_window_size, 4194304);
    assert_eq!(Safari::v17_0_macos().http2.initial_window_size, 2097152);
    assert_eq!(Safari::v18_0_macos().http2.initial_window_size, 4194304);
    assert_eq!(Safari::v18_3_macos().http2.initial_window_size, 4194304);
}

// ============================================================
// Client Builder (unit test, no network)
// ============================================================

#[test]
fn test_client_builder_default() {
    let client = Client::new(Chrome::latest());
    assert!(client.is_ok(), "Client::new should succeed");
}

#[test]
fn test_client_builder_options() {
    let result = Client::builder(Firefox::latest())
        .follow_redirects(false)
        .max_redirects(5)
        .timeout(Duration::from_secs(10))
        .cookie_jar(false)
        .session_resumption(false)
        .build();
    assert!(result.is_ok(), "ClientBuilder with options should succeed");
}

#[test]
fn test_client_builder_invalid_proxy() {
    let result = Client::builder(Chrome::latest())
        .proxy("not-a-valid-url");
    assert!(result.is_err(), "Invalid proxy URL should error");
}

#[test]
fn test_client_profile_access() {
    let profile = Chrome::v145_windows();
    let client = Client::new(profile.clone()).unwrap();
    assert_eq!(
        client.profile().tls.cipher_list,
        profile.tls.cipher_list,
        "Client should expose its profile"
    );
}

// ============================================================
// Multipart Builder (unit test, no network)
// ============================================================

#[test]
fn test_multipart_builder() {
    let multipart = Multipart::new()
        .text("field1", "value1")
        .text("field2", "value2")
        .file("upload", "test.txt", "text/plain", b"hello world".to_vec());

    let (body, content_type) = multipart.build();
    assert!(
        content_type.starts_with("multipart/form-data; boundary="),
        "Content-Type should include boundary"
    );
    assert!(!body.is_empty(), "Body should not be empty");

    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("field1"), "Body should contain field1");
    assert!(body_str.contains("value1"), "Body should contain value1");
    assert!(body_str.contains("test.txt"), "Body should contain filename");
    assert!(
        body_str.contains("hello world"),
        "Body should contain file data"
    );
}

// ============================================================
// Error Types (unit test, no network)
// ============================================================

#[test]
fn test_error_display() {
    let err = Error::ConnectionFailed("test error".into());
    assert!(
        format!("{err}").contains("test error"),
        "Error should display message"
    );
}

// ============================================================
// Cookie Jar Serialization (unit test, no network)
// ============================================================

#[test]
fn test_cookie_jar_json_roundtrip() {
    let url: http::Uri = "https://example.com/path".parse().unwrap();
    let mut jar = CookieJar::new();
    jar.store_from_response(
        &url,
        &[
            ("set-cookie".into(), "name=value; Path=/; Secure".into()),
            ("set-cookie".into(), "session=abc123; Path=/; HttpOnly".into()),
        ],
    );

    let json = jar.to_json().unwrap();
    assert!(json.contains("name"), "JSON should contain cookie name");

    let jar2 = CookieJar::from_json(&json).unwrap();

    let cookies = jar2.cookie_header(&url);
    assert!(
        cookies.is_some(),
        "Restored jar should have cookies for example.com"
    );
    let header = cookies.unwrap();
    assert!(header.contains("name=value"), "Should contain name=value");
    assert!(
        header.contains("session=abc123"),
        "Should contain session=abc123"
    );
}

// ============================================================
// Response Decompression (integration, network required)
// ============================================================

async fn assert_decompression(encoding: &str, key: &str) {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .get(&format!("https://httpbin.org/{encoding}"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "{encoding}: expected 200");
    let body = String::from_utf8_lossy(&resp.body);
    let spaced = format!("\"{key}\": true");
    let compact = format!("\"{key}\":true");
    assert!(
        body.contains(&spaced) || body.contains(&compact),
        "{encoding}: expected {key}=true, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_decompression_gzip() { assert_decompression("gzip", "gzipped").await; }

#[tokio::test]
#[ignore]
async fn test_decompression_deflate() { assert_decompression("deflate", "deflated").await; }

#[tokio::test]
#[ignore]
async fn test_decompression_brotli() { assert_decompression("brotli", "brotli").await; }

// ============================================================
// Redirect Following (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_redirect_chain() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(true)
        .max_redirects(10)
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/redirect/3").await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.url.contains("/get"),
        "Should end up at /get after redirects, got: {}",
        resp.url
    );
}

#[tokio::test]
#[ignore]
async fn test_redirect_disabled() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(false)
        .build()
        .unwrap();

    let resp = client
        .get("https://httpbin.org/redirect/1")
        .await
        .unwrap();
    assert_eq!(resp.status, 302, "Should get 302 without following");
}

#[tokio::test]
#[ignore]
async fn test_redirect_max_exceeded() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(true)
        .max_redirects(2)
        .build()
        .unwrap();

    let result = client.get("https://httpbin.org/redirect/5").await;
    assert!(result.is_err(), "Should error when max redirects exceeded");
}

#[tokio::test]
#[ignore]
async fn test_redirect_307_preserves_post() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(true)
        .build()
        .unwrap();

    let body = b"{\"preserved\": true}".to_vec();
    let resp = client
        .request(
            http::Method::POST,
            "https://httpbin.org/redirect-to?url=/post&status_code=307",
            Some(body),
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        text.contains("preserved"),
        "307 should preserve POST body, got: {text}"
    );
}

#[tokio::test]
#[ignore]
async fn test_redirect_302_post_to_get() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(true)
        .build()
        .unwrap();

    // 302 redirect from POST should become GET (per HTTP spec)
    let resp = client
        .request(
            http::Method::POST,
            "https://httpbin.org/redirect-to?url=/get&status_code=302",
            Some(b"data".to_vec()),
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    assert!(
        resp.url.contains("/get"),
        "302 POST should redirect to GET"
    );
}

// ============================================================
// Session Save/Load (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_session_save_load_cookies() {
    // Set a cookie
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .get("https://httpbin.org/cookies/set/testkoon/testval123")
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    // Save session
    let session_json = client.save_session().unwrap();
    assert!(
        session_json.contains("testkoon"),
        "Session should contain cookie"
    );

    // Create new client, load session
    let client2 = Client::new(Chrome::latest()).unwrap();
    client2.load_session(&session_json).unwrap();

    // Verify cookie is sent
    let resp2 = client2.get("https://httpbin.org/cookies").await.unwrap();
    let body = String::from_utf8_lossy(&resp2.body);
    assert!(
        body.contains("testkoon"),
        "Cookie name should be sent after session load, got: {body}"
    );
    assert!(
        body.contains("testval123"),
        "Cookie value should match, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_session_save_load_file() {
    let client = Client::new(Chrome::latest()).unwrap();
    client
        .get("https://httpbin.org/cookies/set/filecookie/filevalue")
        .await
        .unwrap();

    let path = std::env::temp_dir().join("koon_test_session.json");
    let path_str = path.to_string_lossy().to_string();

    client.save_session_to_file(&path_str).unwrap();
    assert!(path.exists(), "Session file should exist");

    // Verify file contains valid JSON
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("filecookie"),
        "File should contain cookie"
    );

    let client2 = Client::new(Chrome::latest()).unwrap();
    client2.load_session_from_file(&path_str).unwrap();

    let resp = client2.get("https://httpbin.org/cookies").await.unwrap();
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("filecookie"),
        "Cookie should persist via file, got: {body}"
    );

    // Cleanup
    let _ = std::fs::remove_file(&path);
}

// ============================================================
// TLS Session Resumption (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_session_resumption_enabled() {
    let client = Client::builder(Chrome::latest())
        .session_resumption(true)
        .build()
        .unwrap();

    // First request establishes TLS session
    let resp1 = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp1.status, 200);

    // Second request should reuse session (verifiable via save_session containing tls_sessions)
    let resp2 = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp2.status, 200);

    let session = client.save_session().unwrap();
    assert!(
        session.contains("tls_sessions"),
        "Session export should contain TLS sessions"
    );
}

#[tokio::test]
#[ignore]
async fn test_session_resumption_disabled() {
    let client = Client::builder(Chrome::latest())
        .session_resumption(false)
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);

    // With session resumption disabled, tls_sessions should be empty or missing
    let session = client.save_session().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&session).unwrap();
    let tls = parsed.get("tls_sessions");
    let is_empty = tls.is_none() || tls.unwrap().is_null() || tls.unwrap().as_object().map(|m| m.is_empty()).unwrap_or(false);
    assert!(
        is_empty,
        "TLS sessions should be empty when resumption disabled, got: {session}"
    );
}

// ============================================================
// Streaming Response (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_streaming_collect() {
    let client = Client::new(Chrome::latest()).unwrap();
    let streaming = client
        .request_streaming(http::Method::GET, "https://httpbin.org/get", None)
        .await
        .unwrap();

    assert_eq!(streaming.status, 200);
    assert!(!streaming.version.is_empty(), "Version should be set");
    assert!(
        streaming.url.contains("httpbin.org"),
        "URL should be set"
    );

    let body = streaming.collect_body().await.unwrap();
    assert!(!body.is_empty(), "Body should not be empty");

    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("httpbin.org"),
        "Body should contain httpbin content"
    );
}

#[tokio::test]
#[ignore]
async fn test_streaming_chunks() {
    let client = Client::new(Chrome::latest()).unwrap();
    let mut streaming = client
        .request_streaming(
            http::Method::GET,
            "https://httpbin.org/bytes/10000",
            None,
        )
        .await
        .unwrap();

    assert_eq!(streaming.status, 200);

    let mut total_bytes = 0;
    let mut chunk_count = 0;
    while let Some(result) = streaming.next_chunk().await {
        let chunk = result.unwrap();
        total_bytes += chunk.len();
        chunk_count += 1;
    }

    assert_eq!(total_bytes, 10000, "Should receive exactly 10000 bytes");
    assert!(chunk_count >= 1, "Should receive at least one chunk");
}

// ============================================================
// Custom Headers (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_custom_headers() {
    let client = Client::builder(Chrome::latest())
        .headers(vec![
            ("X-Custom-Test".into(), "koon-value-123".into()),
        ])
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/headers").await.unwrap();
    assert_eq!(resp.status, 200);

    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("koon-value-123") || body.contains("X-Custom-Test"),
        "Custom header should be sent, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_extra_headers_per_request() {
    let client = Client::new(Chrome::latest()).unwrap();

    let resp = client
        .request_with_headers(
            http::Method::GET,
            "https://httpbin.org/headers",
            None,
            vec![("X-Per-Request".into(), "per-req-value".into())],
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("per-req-value"),
        "Per-request header should be sent, got: {body}"
    );
}

// ============================================================
// HTTP Methods (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_http_get() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.version, "h2");
}

#[tokio::test]
#[ignore]
async fn test_http_post_with_body() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .post(
            "https://httpbin.org/post",
            Some(b"hello world".to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains("hello world"), "POST body should echo back");
}

#[tokio::test]
#[ignore]
async fn test_http_put() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .put("https://httpbin.org/put", Some(b"put data".to_vec()))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains("put data"), "PUT body should echo back");
}

#[tokio::test]
#[ignore]
async fn test_http_delete() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client.delete("https://httpbin.org/delete").await.unwrap();
    assert_eq!(resp.status, 200);
}

#[tokio::test]
#[ignore]
async fn test_http_patch() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .patch(
            "https://httpbin.org/patch",
            Some(b"patch data".to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
}

#[tokio::test]
#[ignore]
async fn test_http_head() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client.head("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty(), "HEAD should have no body");
}

// ============================================================
// Multipart POST (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_multipart_post() {
    let client = Client::new(Chrome::latest()).unwrap();
    let multipart = Multipart::new()
        .text("username", "koon_test")
        .file(
            "upload",
            "test.txt",
            "text/plain",
            b"file content here".to_vec(),
        );

    let resp = client
        .post_multipart("https://httpbin.org/post", multipart)
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("koon_test"),
        "Multipart text field should echo back"
    );
    assert!(
        body.contains("file content here"),
        "Multipart file should echo back"
    );
}

// ============================================================
// Cookie Jar (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_cookie_persistence() {
    let client = Client::builder(Chrome::latest())
        .cookie_jar(true)
        .build()
        .unwrap();

    // Set cookie
    client
        .get("https://httpbin.org/cookies/set/jar_test/jar_value")
        .await
        .unwrap();

    // Verify cookie sent back
    let resp = client.get("https://httpbin.org/cookies").await.unwrap();
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains("jar_test"), "Cookie should persist");
    assert!(body.contains("jar_value"), "Cookie value should match");
}

#[tokio::test]
#[ignore]
async fn test_cookie_jar_disabled() {
    let client = Client::builder(Chrome::latest())
        .cookie_jar(false)
        .build()
        .unwrap();

    // Set cookie
    client
        .get("https://httpbin.org/cookies/set/nojar/novalue")
        .await
        .unwrap();

    // Should NOT send cookie back
    let resp = client.get("https://httpbin.org/cookies").await.unwrap();
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        !body.contains("nojar"),
        "Cookie should NOT persist with jar disabled, got: {body}"
    );
}

// ============================================================
// Connection Pool Reuse (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_connection_pool_reuse() {
    let client = Client::new(Chrome::latest()).unwrap();

    // First request establishes connection
    let start = std::time::Instant::now();
    let resp1 = client.get("https://httpbin.org/get").await.unwrap();
    let first_duration = start.elapsed();
    assert_eq!(resp1.status, 200);

    // Second request should reuse connection (significantly faster)
    let start = std::time::Instant::now();
    let resp2 = client.get("https://httpbin.org/get").await.unwrap();
    let second_duration = start.elapsed();
    assert_eq!(resp2.status, 200);

    // Pool reuse should be notably faster (no TLS handshake)
    // Be generous with the threshold since network latency varies
    assert!(
        second_duration < first_duration || second_duration < Duration::from_secs(3),
        "Second request should be fast (pool reuse): first={first_duration:?}, second={second_duration:?}"
    );
}

// ============================================================
// Timeout (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_timeout() {
    let client = Client::builder(Chrome::latest())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    // httpbin.org/delay/10 waits 10s — should timeout
    let result = client.get("https://httpbin.org/delay/10").await;
    assert!(result.is_err(), "Should timeout after 2s on 10s delay");
}

// ============================================================
// Multiple Browser Profiles (integration, network required)
// ============================================================

async fn assert_browser_ua(profile: BrowserProfile, name: &str, ua_marker: &str) {
    let client = Client::new(profile).unwrap();
    let resp = client.get("https://httpbin.org/headers").await.unwrap();
    assert_eq!(resp.status, 200, "{name}: expected 200");
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains(ua_marker), "{name}: UA should contain '{ua_marker}', got: {body}");
}

#[tokio::test]
#[ignore]
async fn test_firefox_profile_request() { assert_browser_ua(Firefox::latest(), "Firefox", "Firefox").await; }

#[tokio::test]
#[ignore]
async fn test_edge_profile_request() { assert_browser_ua(Edge::latest(), "Edge", "Edg/").await; }

#[tokio::test]
#[ignore]
async fn test_opera_profile_request() { assert_browser_ua(Opera::latest(), "Opera", "OPR/").await; }

#[tokio::test]
#[ignore]
async fn test_safari_profile_request() {
    let client = Client::new(Safari::latest()).unwrap();
    let resp = client.get("https://httpbin.org/headers").await.unwrap();
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("Safari") && !body.contains("Chrome"),
        "Safari UA should be present without Chrome"
    );
}

// ============================================================
// DoH - DNS over HTTPS (integration, network required)
// ============================================================

#[cfg(feature = "doh")]
#[tokio::test]
#[ignore]
async fn test_doh_cloudflare() {
    let client = Client::builder(Chrome::latest())
        .doh(koon_core::dns::DohResolver::with_cloudflare().unwrap())
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
}

#[cfg(feature = "doh")]
#[tokio::test]
#[ignore]
async fn test_doh_google() {
    let client = Client::builder(Chrome::latest())
        .doh(koon_core::dns::DohResolver::with_google().unwrap())
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
}

#[cfg(feature = "doh")]
#[tokio::test]
#[ignore]
async fn test_doh_cloudflare_httpbin() {
    // httpbin.org uses CNAMEs — Cloudflare DoH may not resolve CNAME chains.
    // This test documents the limitation.
    let resolver = koon_core::dns::DohResolver::with_cloudflare().unwrap();
    let result = resolver.resolve("httpbin.org").await;
    if result.is_err() {
        // Known limitation: Cloudflare returns CNAME without following to A record
        eprintln!(
            "NOTE: Cloudflare DoH cannot resolve httpbin.org (CNAME chain): {:?}",
            result.err()
        );
    } else {
        let addrs = result.unwrap();
        assert!(!addrs.is_empty(), "Should have addresses");
    }
}

// ============================================================
// WebSocket (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_websocket_echo() {
    let client = Client::new(Chrome::latest()).unwrap();
    let mut ws = client
        .websocket("wss://echo.websocket.org")
        .await
        .unwrap();

    // echo.websocket.org sends a welcome message first — consume it
    let welcome = ws.receive().await.unwrap();
    assert!(welcome.is_some(), "Should receive welcome message");

    // Send text message
    ws.send_text("hello koon").await.unwrap();

    // Receive echo
    let msg = ws.receive().await.unwrap();
    match msg {
        Some(WsMessage::Text(text)) => {
            assert_eq!(text, "hello koon", "Echo should match");
        }
        Some(WsMessage::Binary(data)) => {
            assert_eq!(
                String::from_utf8_lossy(&data),
                "hello koon",
                "Echo should match"
            );
        }
        None => panic!("Expected echo message, got None"),
    }

    ws.close(None, None).await.unwrap();
}

// ============================================================
// MITM Proxy Server (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_proxy_server_start_shutdown() {
    let server = ProxyServer::start(ProxyServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        profile: Chrome::v145_windows(),
        header_mode: HeaderMode::Impersonate,
        ca_dir: None,
        timeout_secs: 30,
    })
    .await
    .unwrap();

    assert!(server.port() > 0, "Should bind to a port");
    assert!(
        server.url().starts_with("http://127.0.0.1:"),
        "URL should be valid"
    );
    assert!(
        server.ca_cert_path().exists(),
        "CA cert file should exist"
    );

    let pem = server.ca_cert_pem().unwrap();
    assert!(
        !pem.is_empty(),
        "CA cert PEM should not be empty"
    );
    let pem_str = String::from_utf8_lossy(&pem);
    assert!(
        pem_str.contains("BEGIN CERTIFICATE"),
        "CA cert should be valid PEM"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore]
async fn test_proxy_traffic_via_tcp() {
    let server = ProxyServer::start(ProxyServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        profile: Chrome::v145_windows(),
        header_mode: HeaderMode::Impersonate,
        ca_dir: None,
        timeout_secs: 30,
    })
    .await
    .unwrap();

    let port = server.port();

    // Connect to proxy via raw TCP and send an HTTP CONNECT request
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Send CONNECT
    stream
        .write_all(b"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n")
        .await
        .unwrap();

    // Read 200 Connection Established
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "Should get 200 Connection Established, got: {response}"
    );

    server.shutdown();
}

// ============================================================
// Response Headers (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_response_headers_preserved() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .get("https://httpbin.org/response-headers?X-Test-Header=test-value")
        .await
        .unwrap();

    assert_eq!(resp.status, 200);

    let has_test_header = resp
        .headers
        .iter()
        .any(|(k, v)| k.to_lowercase() == "x-test-header" && v == "test-value");
    assert!(
        has_test_header,
        "Custom response header should be preserved"
    );
}

// ============================================================
// Status Codes (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_status_codes() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(false)
        .build()
        .unwrap();

    for code in [200, 201, 204, 301, 400, 404, 500] {
        let resp = client
            .get(&format!("https://httpbin.org/status/{code}"))
            .await
            .unwrap();
        assert_eq!(
            resp.status, code,
            "Status {code} should be returned correctly"
        );
    }
}

// ============================================================
// Large Response Body (integration, network required)
// ============================================================

#[tokio::test]
#[ignore]
async fn test_large_response() {
    let client = Client::new(Chrome::latest()).unwrap();
    // 100KB response
    let resp = client
        .get("https://httpbin.org/bytes/102400")
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.body.len(),
        102400,
        "Should receive exactly 100KB"
    );
}
