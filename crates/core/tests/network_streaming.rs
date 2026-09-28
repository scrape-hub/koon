//! Network-required tests (`--ignored`) of streamed responses against
//! httpbin.org.

use koon_core::*;

#[tokio::test]
#[ignore]
async fn streaming_collect() {
    let client = Client::new(Chrome::latest()).unwrap();
    let mut streaming = client
        .send_streaming(
            http::Method::GET,
            "https://httpbin.org/get",
            None,
            RequestOptions::default(),
        )
        .await
        .unwrap();

    assert_eq!(streaming.status, 200);
    assert!(!streaming.version.is_empty(), "Version should be set");
    assert!(streaming.url.contains("httpbin.org"), "URL should be set");

    let body = streaming.collect_body().await.unwrap();
    assert!(!body.is_empty(), "Body should not be empty");
    assert!(streaming.bytes_received() >= body.len() as u64);

    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("httpbin.org"),
        "Body should contain httpbin content"
    );
}

#[tokio::test]
#[ignore]
async fn streaming_chunks() {
    let client = Client::new(Chrome::latest()).unwrap();
    let mut streaming = client
        .send_streaming(
            http::Method::GET,
            "https://httpbin.org/bytes/10000",
            None,
            RequestOptions::default(),
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
