use super::chrome::{chrome_http2, chrome_quic, chrome_tls_for_edge};
use super::BrowserProfile;

/// Edge browser profile factory.
///
/// Edge uses the same Chromium engine as Chrome, so TLS and H2 are identical.
/// Only headers differ (brand string + user-agent suffix).
/// Supports Edge 131–145 (same Chromium versions).
pub struct Edge;

impl Edge {
    // ========== Edge 131 ==========
    pub fn v131_windows() -> BrowserProfile { edge_profile(131, Os::Windows) }
    pub fn v131_macos() -> BrowserProfile { edge_profile(131, Os::MacOS) }

    // ========== Edge 132 ==========
    pub fn v132_windows() -> BrowserProfile { edge_profile(132, Os::Windows) }
    pub fn v132_macos() -> BrowserProfile { edge_profile(132, Os::MacOS) }

    // ========== Edge 133 ==========
    pub fn v133_windows() -> BrowserProfile { edge_profile(133, Os::Windows) }
    pub fn v133_macos() -> BrowserProfile { edge_profile(133, Os::MacOS) }

    // ========== Edge 134 ==========
    pub fn v134_windows() -> BrowserProfile { edge_profile(134, Os::Windows) }
    pub fn v134_macos() -> BrowserProfile { edge_profile(134, Os::MacOS) }

    // ========== Edge 135 ==========
    pub fn v135_windows() -> BrowserProfile { edge_profile(135, Os::Windows) }
    pub fn v135_macos() -> BrowserProfile { edge_profile(135, Os::MacOS) }

    // ========== Edge 136 ==========
    pub fn v136_windows() -> BrowserProfile { edge_profile(136, Os::Windows) }
    pub fn v136_macos() -> BrowserProfile { edge_profile(136, Os::MacOS) }

    // ========== Edge 137 ==========
    pub fn v137_windows() -> BrowserProfile { edge_profile(137, Os::Windows) }
    pub fn v137_macos() -> BrowserProfile { edge_profile(137, Os::MacOS) }

    // ========== Edge 138 ==========
    pub fn v138_windows() -> BrowserProfile { edge_profile(138, Os::Windows) }
    pub fn v138_macos() -> BrowserProfile { edge_profile(138, Os::MacOS) }

    // ========== Edge 139 ==========
    pub fn v139_windows() -> BrowserProfile { edge_profile(139, Os::Windows) }
    pub fn v139_macos() -> BrowserProfile { edge_profile(139, Os::MacOS) }

    // ========== Edge 140 ==========
    pub fn v140_windows() -> BrowserProfile { edge_profile(140, Os::Windows) }
    pub fn v140_macos() -> BrowserProfile { edge_profile(140, Os::MacOS) }

    // ========== Edge 141 ==========
    pub fn v141_windows() -> BrowserProfile { edge_profile(141, Os::Windows) }
    pub fn v141_macos() -> BrowserProfile { edge_profile(141, Os::MacOS) }

    // ========== Edge 142 ==========
    pub fn v142_windows() -> BrowserProfile { edge_profile(142, Os::Windows) }
    pub fn v142_macos() -> BrowserProfile { edge_profile(142, Os::MacOS) }

    // ========== Edge 143 ==========
    pub fn v143_windows() -> BrowserProfile { edge_profile(143, Os::Windows) }
    pub fn v143_macos() -> BrowserProfile { edge_profile(143, Os::MacOS) }

    // ========== Edge 144 ==========
    pub fn v144_windows() -> BrowserProfile { edge_profile(144, Os::Windows) }
    pub fn v144_macos() -> BrowserProfile { edge_profile(144, Os::MacOS) }

    // ========== Edge 145 ==========
    pub fn v145_windows() -> BrowserProfile { edge_profile(145, Os::Windows) }
    pub fn v145_macos() -> BrowserProfile { edge_profile(145, Os::MacOS) }

    /// Latest Edge profile (currently v145 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v145_windows()
    }
}

#[derive(Clone, Copy)]
enum Os {
    Windows,
    MacOS,
}

fn edge_profile(major: u32, os: Os) -> BrowserProfile {
    BrowserProfile {
        tls: chrome_tls_for_edge(major),
        http2: chrome_http2(),
        quic: Some(chrome_quic()),
        headers: edge_headers(major, os),
    }
}

/// Edge uses the same "Not A Brand" rotation as Chrome.
fn edge_brand(major: u32) -> &'static str {
    match major {
        136 | 145 => "Not/A)Brand",
        _ => "Not_A Brand",
    }
}

fn edge_headers(major: u32, os: Os) -> Vec<(String, String)> {
    let brand = edge_brand(major);
    let ver = major.to_string();

    let sec_ch_ua = format!(
        "\"Microsoft Edge\";v=\"{ver}\", \"Chromium\";v=\"{ver}\", \"{brand}\";v=\"24\""
    );

    let (platform, user_agent) = match os {
        Os::Windows => (
            "\"Windows\"",
            format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36 Edg/{ver}.0.0.0"),
        ),
        Os::MacOS => (
            "\"macOS\"",
            format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36 Edg/{ver}.0.0.0"),
        ),
    };

    vec![
        ("sec-ch-ua".into(), sec_ch_ua),
        ("sec-ch-ua-mobile".into(), "?0".into()),
        ("sec-ch-ua-platform".into(), platform.into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("user-agent".into(), user_agent),
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
