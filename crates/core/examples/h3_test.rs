use koon_core::profile::Chrome;
use koon_core::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HTTP/3 Test ===\n");

    let profile = Chrome::v145_windows();
    let client = Client::builder(profile).build()?;

    // 1. First request via H2 — should discover Alt-Svc header
    println!("--- Request 1: H2 (should discover Alt-Svc) ---");
    let resp1 = client.get("https://cloudflare.com/cdn-cgi/trace").await?;
    println!("Status: {}", resp1.status);
    println!("Version: {}", resp1.version);

    let alt_svc = resp1
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("alt-svc"));
    if let Some((_, v)) = alt_svc {
        println!("Alt-Svc: {v}");
    } else {
        println!("Alt-Svc: NOT FOUND");
        println!("\nNo Alt-Svc header — server did not advertise H3.");
        println!("Trying google.com instead...\n");

        // Try Google
        let resp = client.get("https://www.google.com").await?;
        println!("Google Status: {} Version: {}", resp.status, resp.version);
        let alt_svc = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("alt-svc"));
        if let Some((_, v)) = alt_svc {
            println!("Google Alt-Svc: {v}");
        }
    }

    let body1 = String::from_utf8_lossy(&resp1.body);
    println!("Body (first 200 chars): {}", &body1[..body1.len().min(200)]);

    // 2. Second request to same origin — should attempt H3
    println!("\n--- Request 2: Same origin (should try H3) ---");
    let resp2 = client.get("https://cloudflare.com/cdn-cgi/trace").await?;
    println!("Status: {}", resp2.status);
    println!("Version: {}", resp2.version);

    let body2 = String::from_utf8_lossy(&resp2.body);
    println!("Body (first 200 chars): {}", &body2[..body2.len().min(200)]);

    if resp2.version == "h3" {
        println!("\n=== HTTP/3 WORKS! ===");
    } else {
        println!("\n--- H3 not used for second request (version: {}) ---", resp2.version);
        println!("This could mean: Alt-Svc not cached, H3 connection failed, or server quirk.");
    }

    // 3. Try another H3-capable server
    println!("\n--- Request 3: Google (another H3 server) ---");
    let resp3 = client.get("https://www.google.com/generate_204").await?;
    println!("Status: {}", resp3.status);
    println!("Version: {}", resp3.version);
    let alt_svc3 = resp3
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("alt-svc"));
    if let Some((_, v)) = alt_svc3 {
        println!("Alt-Svc: {v}");
    }

    // 4. Second request to Google — should try H3
    println!("\n--- Request 4: Google again (should try H3) ---");
    let resp4 = client.get("https://www.google.com/generate_204").await?;
    println!("Status: {}", resp4.status);
    println!("Version: {}", resp4.version);

    if resp4.version == "h3" {
        println!("\n=== HTTP/3 to Google WORKS! ===");
    }

    println!("\n=== Test Complete ===");
    Ok(())
}
