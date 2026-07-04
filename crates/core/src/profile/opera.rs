use super::BrowserProfile;
use super::chrome::{
    chrome_http2, chrome_quic, chromium_headers, chromium_sec_ch_ua, chromium_tls, chromium_ua,
};

/// Opera browser profile factory.
///
/// Opera uses the same Chromium engine as Chrome, so TLS/H2/QUIC are identical.
/// Only headers differ (brand string + `OPR/` user-agent suffix).
/// Supports Opera 124–133 (Chromium 140–149).
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

    // ========== Opera 128 (Chromium 144) ==========
    pub fn v128_windows() -> BrowserProfile {
        opera_profile(128, 144, Os::Windows)
    }
    pub fn v128_macos() -> BrowserProfile {
        opera_profile(128, 144, Os::MacOS)
    }
    pub fn v128_linux() -> BrowserProfile {
        opera_profile(128, 144, Os::Linux)
    }

    // ========== Opera 129 (Chromium 145) ==========
    pub fn v129_windows() -> BrowserProfile {
        opera_profile(129, 145, Os::Windows)
    }
    pub fn v129_macos() -> BrowserProfile {
        opera_profile(129, 145, Os::MacOS)
    }
    pub fn v129_linux() -> BrowserProfile {
        opera_profile(129, 145, Os::Linux)
    }

    // ========== Opera 130 (Chromium 146) ==========
    pub fn v130_windows() -> BrowserProfile {
        opera_profile(130, 146, Os::Windows)
    }
    pub fn v130_macos() -> BrowserProfile {
        opera_profile(130, 146, Os::MacOS)
    }
    pub fn v130_linux() -> BrowserProfile {
        opera_profile(130, 146, Os::Linux)
    }

    // ========== Opera 131 (Chromium 147) ==========
    pub fn v131_windows() -> BrowserProfile {
        opera_profile(131, 147, Os::Windows)
    }
    pub fn v131_macos() -> BrowserProfile {
        opera_profile(131, 147, Os::MacOS)
    }
    pub fn v131_linux() -> BrowserProfile {
        opera_profile(131, 147, Os::Linux)
    }

    // ========== Opera 132 (Chromium 148) ==========
    pub fn v132_windows() -> BrowserProfile {
        opera_profile(132, 148, Os::Windows)
    }
    pub fn v132_macos() -> BrowserProfile {
        opera_profile(132, 148, Os::MacOS)
    }
    pub fn v132_linux() -> BrowserProfile {
        opera_profile(132, 148, Os::Linux)
    }

    // ========== Opera 133 (Chromium 149) ==========
    pub fn v133_windows() -> BrowserProfile {
        opera_profile(133, 149, Os::Windows)
    }
    pub fn v133_macos() -> BrowserProfile {
        opera_profile(133, 149, Os::MacOS)
    }
    pub fn v133_linux() -> BrowserProfile {
        opera_profile(133, 149, Os::Linux)
    }

    /// Latest Opera profile (currently v133 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v133_windows()
    }

    /// Resolve an Opera profile by version number and optional OS.
    pub(super) fn resolve(major: u32, os: Option<&str>) -> Result<BrowserProfile, String> {
        let chromium = match major {
            124 => 140,
            125 => 141,
            126 => 142,
            127 => 143,
            128 => 144,
            129 => 145,
            130 => 146,
            131 => 147,
            132 => 148,
            133 => 149,
            _ => {
                return Err(format!(
                    "Unsupported Opera version: {major}. Supported: 124-133"
                ));
            }
        };
        let os = match os {
            Some("windows") => Os::Windows,
            Some("linux") => Os::Linux,
            _ => Os::MacOS, // macOS default — less blocked by WAFs than Windows
        };
        Ok(opera_profile(major, chromium, os))
    }

    pub(super) const LATEST_VERSION: u32 = 133;
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
