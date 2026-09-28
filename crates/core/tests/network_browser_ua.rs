//! Network-required tests (`--ignored`) that each browser profile sends its
//! own User-Agent, against httpbin.org.

use koon_core::*;

async fn assert_browser_ua(profile: BrowserProfile, name: &str, ua_marker: &str) {
    let client = Client::new(profile).unwrap();
    let resp = client.get("https://httpbin.org/headers").await.unwrap();
    assert_eq!(resp.status, 200, "{name}: expected 200");
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains(ua_marker),
        "{name}: UA should contain '{ua_marker}', got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn firefox_profile_request() {
    assert_browser_ua(Firefox::latest(), "Firefox", "Firefox").await;
}

#[tokio::test]
#[ignore]
async fn edge_profile_request() {
    assert_browser_ua(Edge::latest(), "Edge", "Edg/").await;
}

#[tokio::test]
#[ignore]
async fn opera_profile_request() {
    assert_browser_ua(Opera::latest(), "Opera", "OPR/").await;
}

#[tokio::test]
#[ignore]
async fn safari_profile_request() {
    let client = Client::new(Safari::latest()).unwrap();
    let resp = client.get("https://httpbin.org/headers").await.unwrap();
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("Safari") && !body.contains("Chrome"),
        "Safari UA should be present without Chrome"
    );
}
