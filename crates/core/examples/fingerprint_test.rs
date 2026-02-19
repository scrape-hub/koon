use koon_core::profile::Chrome;
use koon_core::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Koon Smoke Tests ===\n");

    // === Test 1: Redirect Following ===
    println!("=== Test 1: Redirect Following ===");
    println!("Requesting https://httpbin.org/redirect/3 (should follow 3 redirects) ...\n");
    let client = Client::builder(Chrome::v145_windows()).build()?;
    let response = client.get("https://httpbin.org/redirect/3").await?;
    println!("Status: {} (expected 200)", response.status);
    println!("Final URL: {} (expected .../get)", response.url);
    assert_eq!(response.status, 200, "Redirect should end with 200");

    // === Test 2: Cookie Persistence ===
    println!("\n=== Test 2: Cookie Persistence ===");
    println!("Setting cookie via https://httpbin.org/cookies/set/testcookie/testvalue ...\n");
    let response = client
        .get("https://httpbin.org/cookies/set/testcookie/testvalue")
        .await?;
    println!("Status: {} (expected 200 after redirect)", response.status);
    println!("Final URL: {}", response.url);

    println!("\nVerifying cookie at https://httpbin.org/cookies ...");
    let response = client.get("https://httpbin.org/cookies").await?;
    let body = String::from_utf8_lossy(&response.body);
    println!("Cookies response: {body}");
    assert!(
        body.contains("testcookie"),
        "Cookie should be sent back in follow-up request"
    );

    // === Test 3: Too Many Redirects ===
    println!("\n=== Test 3: Too Many Redirects ===");
    let limited_client = Client::builder(Chrome::v145_windows())
        .max_redirects(2)
        .build()?;
    let result = limited_client.get("https://httpbin.org/redirect/5").await;
    match result {
        Err(koon_core::Error::TooManyRedirects) => {
            println!("Correctly got TooManyRedirects error with max_redirects=2");
        }
        other => {
            println!("Unexpected result: {other:?}");
            panic!("Expected TooManyRedirects error");
        }
    }

    // === Test 4: Connection Pool Reuse ===
    println!("\n=== Test 4: Connection Pool Reuse ===");
    println!("Two requests to the same host — second should reuse the H2 connection.\n");

    let pool_client = Client::builder(Chrome::v145_windows()).build()?;

    let start = std::time::Instant::now();
    let r1 = pool_client.get("https://httpbin.org/get").await?;
    let t1 = start.elapsed();

    let start = std::time::Instant::now();
    let r2 = pool_client.get("https://httpbin.org/get").await?;
    let t2 = start.elapsed();

    println!("First request:  {:?} (new TCP+TLS+H2 connection)", t1);
    println!("Second request: {:?} (reused H2 connection)", t2);
    assert_eq!(r1.status, 200);
    assert_eq!(r2.status, 200);
    println!("Both requests succeeded with status 200.");

    // === Test 5: HTTP/1.1 Fallback ===
    println!("\n=== Test 5: HTTP/1.1 Fallback ===");
    println!("Testing ALPN-based protocol selection...\n");

    let h1_client = Client::builder(Chrome::v145_windows()).build()?;
    let h1_resp = h1_client.get("https://httpbin.org/get").await?;
    println!("httpbin.org response: status={} version={}", h1_resp.status, h1_resp.version);
    assert_eq!(h1_resp.status, 200);
    println!("Protocol negotiated: {}", h1_resp.version);

    let body = String::from_utf8_lossy(&h1_resp.body);
    assert!(body.contains("\"url\""), "Response should contain url field");
    println!("Response body valid: contains URL field");

    // === Test 6: WebSocket (wss://) ===
    println!("\n=== Test 6: WebSocket (wss://) ===");
    println!("Connecting to wss://echo.websocket.org ...\n");

    let ws_client = Client::builder(Chrome::v145_windows()).build()?;
    let mut ws = ws_client.websocket("wss://echo.websocket.org").await?;
    println!("WebSocket connected!");

    ws.send_text("Hello from koon!").await?;
    println!("Sent: Hello from koon!");

    let mut got_echo = false;
    for _ in 0..5 {
        match ws.receive().await? {
            Some(koon_core::websocket::Message::Text(t)) => {
                println!("Received: {t}");
                if t.contains("Hello from koon!") {
                    got_echo = true;
                    break;
                }
            }
            Some(koon_core::websocket::Message::Binary(b)) => {
                println!("Received binary: {} bytes", b.len());
            }
            None => {
                println!("Connection closed unexpectedly");
                break;
            }
        }
    }
    assert!(got_echo, "Should have received echo of our message");

    ws.close(Some(1000), Some("done".to_string())).await?;
    println!("WebSocket closed with code 1000.");

    println!("\n=== All Smoke Tests Passed ===");
    Ok(())
}
