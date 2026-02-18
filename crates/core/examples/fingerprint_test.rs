use koon_core::profile::{Chrome, Edge, Firefox, Safari};
use koon_core::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Koon Fingerprint Test ===\n");

    // Create client with Chrome 145 profile
    let profile = Chrome::v145_windows();
    println!("Profile: Chrome 145 (Windows)");
    println!("Cipher list: {}", profile.tls.cipher_list);
    println!("Curves: {}", profile.tls.curves);
    println!("GREASE: {}", profile.tls.grease);
    println!("ECH GREASE: {}", profile.tls.ech_grease);
    println!(
        "ALPS: {:?} (new codepoint: {})",
        profile.tls.alps, profile.tls.alps_use_new_codepoint
    );
    println!("Cert compression: {:?}", profile.tls.cert_compression);
    println!("Permute extensions: {}", profile.tls.permute_extensions);

    // Export profile to JSON and print
    let json = profile.to_json_pretty()?;
    println!("\n--- Profile JSON (first 500 chars) ---");
    println!("{}", &json[..json.len().min(500)]);
    println!("...\n");

    // Create client with builder (redirects + cookies enabled by default)
    let client = Client::builder(profile).build()?;

    // === Test 1: Fingerprint ===
    println!("=== Test 1: TLS Fingerprint ===");
    println!("Requesting https://tls.browserleaks.com/json ...\n");
    let response = client.get("https://tls.browserleaks.com/json").await?;

    println!("Status: {}", response.status);
    println!("Version: {}", response.version);
    println!("\nResponse headers:");
    for (name, value) in &response.headers {
        println!("  {name}: {value}");
    }

    let body = String::from_utf8_lossy(&response.body);
    println!("\n--- Response Body ---");
    println!("{body}");

    // === Test 2: Redirect Following ===
    println!("\n=== Test 2: Redirect Following ===");
    println!("Requesting https://httpbin.org/redirect/3 (should follow 3 redirects) ...\n");
    let response = client.get("https://httpbin.org/redirect/3").await?;
    println!("Status: {} (expected 200)", response.status);
    println!("Final URL: {} (expected .../get)", response.url);
    assert_eq!(response.status, 200, "Redirect should end with 200");

    // === Test 3: Cookie Persistence ===
    println!("\n=== Test 3: Cookie Persistence ===");
    println!("Setting cookie via https://httpbin.org/cookies/set/testcookie/testvalue ...\n");
    let response = client
        .get("https://httpbin.org/cookies/set/testcookie/testvalue")
        .await?;
    println!("Status: {} (expected 200 after redirect)", response.status);
    println!("Final URL: {}", response.url);

    // Now check that the cookie is sent back
    println!("\nVerifying cookie at https://httpbin.org/cookies ...");
    let response = client.get("https://httpbin.org/cookies").await?;
    let body = String::from_utf8_lossy(&response.body);
    println!("Cookies response: {body}");
    assert!(
        body.contains("testcookie"),
        "Cookie should be sent back in follow-up request"
    );

    // === Test 4: Too Many Redirects ===
    println!("\n=== Test 4: Too Many Redirects ===");
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

    // === Test 5: Connection Pool Reuse ===
    println!("\n=== Test 5: Connection Pool Reuse ===");
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

    // === Test 6: JSON Round-Trip ===
    println!("\n=== Test 6: JSON Round-Trip ===");
    let profile2 = Chrome::v145_windows();
    let exported = profile2.to_json_pretty()?;
    let reimported = koon_core::profile::BrowserProfile::from_json(&exported)?;
    let client2 = Client::new(reimported)?;
    let response2 = client2.get("https://tls.browserleaks.com/json").await?;
    println!("Round-trip status: {}", response2.status);
    println!("Round-trip version: {}", response2.version);

    // === Test 7: Firefox Profile ===
    println!("\n=== Test 7: Firefox 135 Profile ===");
    let ff_profile = Firefox::v135_windows();
    println!("Firefox GREASE: {}", ff_profile.tls.grease);
    println!("Firefox ECH GREASE: {}", ff_profile.tls.ech_grease);
    println!("Firefox cert compression: {:?}", ff_profile.tls.cert_compression);
    println!("Firefox delegated creds: {:?}", ff_profile.tls.delegated_credentials);
    println!("Firefox pseudo-header order: {:?}", ff_profile.http2.pseudo_header_order);

    let ff_client = Client::new(ff_profile)?;
    let ff_resp = ff_client.get("https://tls.browserleaks.com/json").await?;
    println!("Firefox status: {} version: {}", ff_resp.status, ff_resp.version);
    let ff_body = String::from_utf8_lossy(&ff_resp.body);
    println!("Firefox fingerprint: {}", &ff_body[..ff_body.len().min(200)]);

    // === Test 8: Safari Profile ===
    println!("\n=== Test 8: Safari 18.3 Profile ===");
    let sf_profile = Safari::v18_3_macos();
    println!("Safari GREASE: {}", sf_profile.tls.grease);
    println!("Safari cert compression: {:?}", sf_profile.tls.cert_compression);
    println!("Safari pseudo-header order: {:?}", sf_profile.http2.pseudo_header_order);
    println!("Safari PSK: {}", sf_profile.tls.pre_shared_key);
    println!("Safari session ticket: {}", sf_profile.tls.session_ticket);

    let sf_client = Client::new(sf_profile)?;
    let sf_resp = sf_client.get("https://tls.browserleaks.com/json").await?;
    println!("Safari status: {} version: {}", sf_resp.status, sf_resp.version);
    let sf_body = String::from_utf8_lossy(&sf_resp.body);
    println!("Safari fingerprint: {}", &sf_body[..sf_body.len().min(200)]);

    // === Test 9: Edge Profile ===
    println!("\n=== Test 9: Edge 131 Profile ===");
    let edge_profile = Edge::v131_windows();
    let edge_ua = edge_profile.headers.iter()
        .find(|(k, _)| k == "user-agent")
        .map(|(_, v)| v.as_str())
        .unwrap_or("?");
    println!("Edge user-agent: {edge_ua}");
    assert!(edge_ua.contains("Edg/"), "Edge UA should contain Edg/");

    let edge_sec_ch = edge_profile.headers.iter()
        .find(|(k, _)| k == "sec-ch-ua")
        .map(|(_, v)| v.as_str())
        .unwrap_or("?");
    println!("Edge sec-ch-ua: {edge_sec_ch}");
    assert!(edge_sec_ch.contains("Microsoft Edge"), "Edge sec-ch-ua should contain Microsoft Edge");

    let edge_client = Client::new(edge_profile)?;
    let edge_resp = edge_client.get("https://tls.browserleaks.com/json").await?;
    println!("Edge status: {} version: {}", edge_resp.status, edge_resp.version);

    // === Test 10: HTTP/1.1 Fallback ===
    println!("\n=== Test 10: HTTP/1.1 Fallback ===");
    println!("Testing ALPN-based protocol selection...\n");

    // httpbin.org supports both h2 and h1.1, so this tests the full ALPN flow.
    // The actual protocol depends on server negotiation.
    let h1_client = Client::builder(Chrome::v145_windows()).build()?;
    let h1_resp = h1_client.get("https://httpbin.org/get").await?;
    println!("httpbin.org response: status={} version={}", h1_resp.status, h1_resp.version);
    assert_eq!(h1_resp.status, 200);
    println!("Protocol negotiated: {}", h1_resp.version);

    // Verify response body is valid JSON
    let body = String::from_utf8_lossy(&h1_resp.body);
    assert!(body.contains("\"url\""), "Response should contain url field");
    println!("Response body valid: contains URL field");

    // === Test 11: WebSocket (wss://) ===
    println!("\n=== Test 11: WebSocket (wss://) ===");
    println!("Connecting to wss://echo.websocket.org ...\n");

    let ws_client = Client::builder(Chrome::v145_windows()).build()?;
    let mut ws = ws_client.websocket("wss://echo.websocket.org").await?;
    println!("WebSocket connected!");

    // Send a text message
    ws.send_text("Hello from koon!").await?;
    println!("Sent: Hello from koon!");

    // Receive echo (server may send a greeting first, skip non-echo messages)
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

    // Close with code 1000
    ws.close(Some(1000), Some("done".to_string())).await?;
    println!("WebSocket closed with code 1000.");

    println!("\n=== All Tests Passed ===");
    Ok(())
}
