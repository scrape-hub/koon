use koon_core::profile::Chrome;
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
    println!("ALPS: {:?} (new codepoint: {})", profile.tls.alps, profile.tls.alps_use_new_codepoint);
    println!("Cert compression: {:?}", profile.tls.cert_compression);
    println!("Permute extensions: {}", profile.tls.permute_extensions);

    // Export profile to JSON and print
    let json = profile.to_json_pretty()?;
    println!("\n--- Profile JSON (first 500 chars) ---");
    println!("{}", &json[..json.len().min(500)]);
    println!("...\n");

    // Create client
    let client = Client::new(profile)?;

    // Make request to fingerprint service
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

    // Test JSON round-trip: export -> re-import -> request
    println!("\n=== JSON Round-Trip Test ===");
    let profile2 = Chrome::v145_windows();
    let exported = profile2.to_json_pretty()?;
    let reimported = koon_core::profile::BrowserProfile::from_json(&exported)?;
    let client2 = Client::new(reimported)?;
    let response2 = client2.get("https://tls.browserleaks.com/json").await?;
    println!("Round-trip status: {}", response2.status);
    println!("Round-trip version: {}", response2.version);

    println!("\n=== Test Complete ===");
    Ok(())
}
