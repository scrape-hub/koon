use super::BrowserProfile;
use super::chrome::{
    chrome_http2, chrome_quic, chromium_headers, chromium_sec_ch_ua, chromium_tls, chromium_ua,
};

/// Opera browser profile factory.
///
/// Opera uses the same Chromium engine as Chrome, so TLS/H2/QUIC are identical.
/// Only headers differ (brand string + `OPR/` user-agent suffix).
/// Supports Opera 124–127 (Chromium 140–143).
pub struct Opera;

impl Opera {
    // ========== Opera 124 (Chromium 140) ==========
    pub fn v124_windows() -> BrowserProfile {
        opera_profile(124, 140, Os::Windows)
    }
    pub fn v124_macos() -> BrowserProfile {
        opera_profile(124, 140, Os::MacOS)
    }
    pub fn v124_linux() -> BrowserProfile {
        opera_profile(124, 140, Os::Linux)
    }

    // ========== Opera 125 (Chromium 141) ==========
    pub fn v125_windows() -> BrowserProfile {
        opera_profile(125, 141, Os::Windows)
    }
    pub fn v125_macos() -> BrowserProfile {
        opera_profile(125, 141, Os::MacOS)
    }
    pub fn v125_linux() -> BrowserProfile {
        opera_profile(125, 141, Os::Linux)
    }

    // ========== Opera 126 (Chromium 142) ==========
    pub fn v126_windows() -> BrowserProfile {
        opera_profile(126, 142, Os::Windows)
    }
    pub fn v126_macos() -> BrowserProfile {
        opera_profile(126, 142, Os::MacOS)
    }
    pub fn v126_linux() -> BrowserProfile {
        opera_profile(126, 142, Os::Linux)
    }

    // ========== Opera 127 (Chromium 143) ==========
    pub fn v127_windows() -> BrowserProfile {
        opera_profile(127, 143, Os::Windows)
    }
    pub fn v127_macos() -> BrowserProfile {
        opera_profile(127, 143, Os::MacOS)
    }
    pub fn v127_linux() -> BrowserProfile {
        opera_profile(127, 143, Os::Linux)
    }

    /// Latest Opera profile (currently v127 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v127_windows()
    }

    /// Resolve an Opera profile by version number and optional OS.
    pub(super) fn resolve(major: u32, os: Option<&str>) -> Result<BrowserProfile, String> {
        let chromium = match major {
            124 => 140,
            125 => 141,
            126 => 142,
            127 => 143,
            _ => {
                return Err(format!(
                    "Unsupported Opera version: {major}. Supported: 124-127"
                ));
            }
        };
        let os = match os {
            Some("macos") => Os::MacOS,
            Some("linux") => Os::Linux,
            _ => Os::Windows,
        };
        Ok(opera_profile(major, chromium, os))
    }

    pub(super) const LATEST_VERSION: u32 = 127;
}

#[derive(Clone, Copy)]
enum Os {
    Windows,
    MacOS,
    Linux,
}

fn opera_profile(opera_major: u32, chromium_major: u32, os: Os) -> BrowserProfile {
    BrowserProfile {
        tls: chromium_tls(chromium_major),
        http2: chrome_http2(),
        quic: Some(chrome_quic()),
        headers: opera_headers(opera_major, chromium_major, os),
    }
}

fn opera_headers(opera_major: u32, chromium_major: u32, os: Os) -> Vec<(String, String)> {
    let opera_ver = opera_major.to_string();
    let chrome_ver = chromium_major.to_string();
    let sec_ch_ua = chromium_sec_ch_ua(chromium_major, "Opera", &opera_ver);

    let platform = match os {
        Os::Windows => "\"Windows\"",
        Os::MacOS => "\"macOS\"",
        Os::Linux => "\"Linux\"",
    };

    let ua_suffix = format!("Chrome/{chrome_ver}.0.0.0 Safari/537.36 OPR/{opera_ver}.0.0.0");
    let user_agent = chromium_ua(platform, &ua_suffix);
    chromium_headers(sec_ch_ua, platform, user_agent)
}
