//! Network-required tests (`--ignored`) of plain request/response behaviour
//! against httpbin.org: decompression, custom headers, HTTP methods,
//! multipart POST, cookie persistence, response headers, status codes and
//! large bodies.

use koon_core::*;

// ============================================================
// Response decompression
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
async fn decompression_gzip() {
    assert_decompression("gzip", "gzipped").await;
}

#[tokio::test]
#[ignore]
async fn decompression_deflate() {
    assert_decompression("deflate", "deflated").await;
}

#[tokio::test]
#[ignore]
async fn decompression_brotli() {
    assert_decompression("brotli", "brotli").await;
}

// ============================================================
// Custom headers
// ============================================================

#[tokio::test]
#[ignore]
async fn custom_headers() {
    let client = Client::builder(Chrome::latest())
        .headers(vec![("X-Custom-Test".into(), "koon-value-123".into())])
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
async fn extra_headers_per_request() {
    let client = Client::new(Chrome::latest()).unwrap();

    let resp = client
        .send(
            http::Method::GET,
            "https://httpbin.org/headers",
            None,
            RequestOptions {
                headers: vec![("X-Per-Request".into(), "per-req-value".into())],
                ..Default::default()
            },
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
// HTTP methods
// ============================================================

#[tokio::test]
#[ignore]
async fn http_get() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client.get("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.version, "h2");
}

#[tokio::test]
#[ignore]
async fn http_post_with_body() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .post("https://httpbin.org/post", Some(b"hello world".to_vec()))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains("hello world"), "POST body should echo back");
}

#[tokio::test]
#[ignore]
async fn http_put() {
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
async fn http_delete() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client.delete("https://httpbin.org/delete").await.unwrap();
    assert_eq!(resp.status, 200);
}

#[tokio::test]
#[ignore]
async fn http_patch() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .patch("https://httpbin.org/patch", Some(b"patch data".to_vec()))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
}

#[tokio::test]
#[ignore]
async fn http_head() {
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client.head("https://httpbin.org/get").await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty(), "HEAD should have no body");
}

// ============================================================
// Multipart POST
// ============================================================

#[tokio::test]
#[ignore]
async fn multipart_post() {
    let client = Client::new(Chrome::latest()).unwrap();
    let multipart = Multipart::new().text("username", "koon_test").file(
        "upload",
        "test.txt",
        "text/plain",
        b"file content here".to_vec(),
    );

    let resp = client
        .post_multipart(
            "https://httpbin.org/post",
            multipart,
            RequestOptions::default(),
        )
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
// Cookie jar
// ============================================================

#[tokio::test]
#[ignore]
async fn cookie_persistence() {
    let client = Client::builder(Chrome::latest())
        .cookie_jar(true)
        .build()
        .unwrap();

    client
        .get("https://httpbin.org/cookies/set/jar_test/jar_value")
        .await
        .unwrap();

    let resp = client.get("https://httpbin.org/cookies").await.unwrap();
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains("jar_test"), "Cookie should persist");
    assert!(body.contains("jar_value"), "Cookie value should match");
}

#[tokio::test]
#[ignore]
async fn cookie_jar_disabled() {
    let client = Client::builder(Chrome::latest())
        .cookie_jar(false)
        .build()
        .unwrap();

    client
        .get("https://httpbin.org/cookies/set/nojar/novalue")
        .await
        .unwrap();

    // Should NOT send the cookie back.
    let resp = client.get("https://httpbin.org/cookies").await.unwrap();
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        !body.contains("nojar"),
        "Cookie should NOT persist with jar disabled, got: {body}"
    );
}

// ============================================================
// Response headers, status codes, large bodies
// ============================================================

#[tokio::test]
#[ignore]
async fn response_headers_preserved() {
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

#[tokio::test]
#[ignore]
async fn status_codes() {
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

#[tokio::test]
#[ignore]
async fn large_response() {
    let client = Client::new(Chrome::latest()).unwrap();
    // 100KB response
    let resp = client
        .get("https://httpbin.org/bytes/102400")
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), 102400, "Should receive exactly 100KB");
}
