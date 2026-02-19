use super::chrome::{chrome_http2_base, chrome_quic, chrome_tls_v131};
use super::BrowserProfile;

/// Edge browser profile factory.
/// Edge uses the same Chromium engine as Chrome, so TLS and H2 are identical.
/// Only headers differ (brand string + user-agent suffix).
pub struct Edge;

impl Edge {
    /// Edge 131 on Windows.
    pub fn v131_windows() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v131(),
            http2: chrome_http2_base(),
            quic: Some(chrome_quic()),
            headers: edge_headers_v131_windows(),
        }
    }

    /// Edge 131 on macOS.
    pub fn v131_macos() -> BrowserProfile {
        BrowserProfile {
            tls: chrome_tls_v131(),
            http2: chrome_http2_base(),
            quic: Some(chrome_quic()),
            headers: edge_headers_v131_macos(),
        }
    }

    /// Latest Edge profile (currently v131 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v131_windows()
    }
}

fn edge_headers_base(
    sec_ch_ua: &str,
    platform: &str,
    mobile: &str,
    user_agent: &str,
) -> Vec<(String, String)> {
    vec![
        ("sec-ch-ua".into(), sec_ch_ua.into()),
        ("sec-ch-ua-mobile".into(), mobile.into()),
        ("sec-ch-ua-platform".into(), platform.into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("user-agent".into(), user_agent.into()),
        ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
    ]
}

fn edge_headers_v131_windows() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24""#;
    edge_headers_base(
        sec_ch_ua,
        "\"Windows\"",
        "?0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    )
}

fn edge_headers_v131_macos() -> Vec<(String, String)> {
    let sec_ch_ua = r#""Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24""#;
    edge_headers_base(
        sec_ch_ua,
        "\"macOS\"",
        "?0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    )
}
