//! Network-required tests (`--ignored`) of redirect following against
//! httpbin.org.

use koon_core::*;

#[tokio::test]
#[ignore]
async fn redirect_chain() {
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
async fn redirect_disabled() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(false)
        .build()
        .unwrap();

    let resp = client.get("https://httpbin.org/redirect/1").await.unwrap();
    assert_eq!(resp.status, 302, "Should get 302 without following");
}

#[tokio::test]
#[ignore]
async fn redirect_max_exceeded() {
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
async fn redirect_307_preserves_post() {
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
async fn redirect_302_post_to_get() {
    let client = Client::builder(Chrome::latest())
        .follow_redirects(true)
        .build()
        .unwrap();

    // A 302 redirect from POST should become GET (per HTTP spec).
    let resp = client
        .request(
            http::Method::POST,
            "https://httpbin.org/redirect-to?url=/get&status_code=302",
            Some(b"data".to_vec()),
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    assert!(resp.url.contains("/get"), "302 POST should redirect to GET");
}
