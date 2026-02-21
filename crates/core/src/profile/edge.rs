use super::chrome::{chrome_http2, chrome_quic, chromium_brand, chromium_headers, chromium_tls, chromium_ua};
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

    /// Resolve an Edge profile by version number and optional OS.
    /// Edge is available on Windows and macOS only.
    pub(super) fn resolve(major: u32, os: Option<&str>) -> Result<BrowserProfile, String> {
        if !(131..=145).contains(&major) {
            return Err(format!(
                "Unsupported Edge version: {major}. Supported: 131-145"
            ));
        }
        if os == Some("linux") {
            return Err("Edge is not available on Linux".to_string());
        }
        let os = match os {
            Some("macos") => Os::MacOS,
            _ => Os::Windows,
        };
        Ok(edge_profile(major, os))
    }

    pub(super) const LATEST_VERSION: u32 = 145;
}

#[derive(Clone, Copy)]
enum Os {
    Windows,
    MacOS,
}

fn edge_profile(major: u32, os: Os) -> BrowserProfile {
    BrowserProfile {
        tls: chromium_tls(major),
        http2: chrome_http2(),
        quic: Some(chrome_quic()),
        headers: edge_headers(major, os),
    }
}

fn edge_headers(major: u32, os: Os) -> Vec<(String, String)> {
    let brand = chromium_brand(major);
    let ver = major.to_string();

    let sec_ch_ua = format!(
        "\"Microsoft Edge\";v=\"{ver}\", \"Chromium\";v=\"{ver}\", \"{brand}\";v=\"24\""
    );

    let platform = match os {
        Os::Windows => "\"Windows\"",
        Os::MacOS => "\"macOS\"",
    };

    let ua_suffix = format!("Chrome/{ver}.0.0.0 Safari/537.36 Edg/{ver}.0.0.0");
    let user_agent = chromium_ua(platform, &ua_suffix);
    chromium_headers(sec_ch_ua, platform, user_agent)
}
