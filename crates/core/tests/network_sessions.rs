//! Network-required tests (`--ignored`) of session save/load (cookies) and
//! TLS session resumption, against httpbin.org.

mod common;

use koon_core::*;

// ============================================================
// Session save/load
// ============================================================

#[tokio::test]
#[ignore]
async fn session_save_load_cookies() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .get("https://httpbin.org/cookies/set/testkoon/testval123")
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    let session_json = client.save_session().unwrap();
    assert!(
        session_json.contains("testkoon"),
        "Session should contain cookie"
    );

    let client2 = Client::new(Chrome::latest()).unwrap();
    client2.load_session(&session_json).unwrap();

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
async fn session_save_load_file() {
    let client = Client::new(Chrome::latest()).unwrap();
    client
        .get("https://httpbin.org/cookies/set/filecookie/filevalue")
        .await
        .unwrap();

    // Removed with the session file at the end of the test, also on a panic.
    let dir = common::temp_dir("session");
    let path = dir.path().join("session.json");
    let path_str = path.to_string_lossy().to_string();

    client.save_session_to_file(&path_str).unwrap();
    assert!(path.exists(), "Session file should exist");

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
}

// ============================================================
// TLS session resumption
// ============================================================

#[tokio::test]
#[ignore]
async fn session_resumption_enabled() {
    let client = Client::builder(Chrome::latest())
        .session_resumption(true)
        .build()
        .unwrap();

    let resp1 = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp1.status, 200);

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
async fn session_resumption_disabled() {
    let client = Client::builder(Chrome::latest())
        .session_resumption(false)
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);

    // With session resumption disabled, tls_sessions should be empty or missing.
    let session = client.save_session().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&session).unwrap();
    let tls = parsed.get("tls_sessions");
    let is_empty = tls.is_none()
        || tls.unwrap().is_null()
        || tls
            .unwrap()
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(false);
    assert!(
        is_empty,
        "TLS sessions should be empty when resumption disabled, got: {session}"
    );
}
