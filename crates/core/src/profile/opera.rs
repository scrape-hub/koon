use super::chrome::{chrome_http2, chrome_quic, chromium_tls};
use super::BrowserProfile;

/// Opera browser profile factory.
///
/// Opera uses the same Chromium engine as Chrome, so TLS/H2/QUIC are identical.
/// Only headers differ (brand string + `OPR/` user-agent suffix).
/// Supports Opera 124–127 (Chromium 140–143).
pub struct Opera;

impl Opera {
    // ========== Opera 124 (Chromium 140) ==========
    pub fn v124_windows() -> BrowserProfile { opera_profile(124, 140, Os::Windows) }
    pub fn v124_macos() -> BrowserProfile { opera_profile(124, 140, Os::MacOS) }
    pub fn v124_linux() -> BrowserProfile { opera_profile(124, 140, Os::Linux) }

    // ========== Opera 125 (Chromium 141) ==========
    pub fn v125_windows() -> BrowserProfile { opera_profile(125, 141, Os::Windows) }
    pub fn v125_macos() -> BrowserProfile { opera_profile(125, 141, Os::MacOS) }
    pub fn v125_linux() -> BrowserProfile { opera_profile(125, 141, Os::Linux) }

    // ========== Opera 126 (Chromium 142) ==========
    pub fn v126_windows() -> BrowserProfile { opera_profile(126, 142, Os::Windows) }
    pub fn v126_macos() -> BrowserProfile { opera_profile(126, 142, Os::MacOS) }
    pub fn v126_linux() -> BrowserProfile { opera_profile(126, 142, Os::Linux) }

    // ========== Opera 127 (Chromium 143) ==========
    pub fn v127_windows() -> BrowserProfile { opera_profile(127, 143, Os::Windows) }
    pub fn v127_macos() -> BrowserProfile { opera_profile(127, 143, Os::MacOS) }
    pub fn v127_linux() -> BrowserProfile { opera_profile(127, 143, Os::Linux) }

    /// Latest Opera profile (currently v127 on Windows).
    pub fn latest() -> BrowserProfile {
        Self::v127_windows()
    }
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

/// Opera uses the same "Not A Brand" rotation as Chrome, based on Chromium version.
fn opera_brand(chromium_major: u32) -> &'static str {
    match chromium_major {
        136 | 145 => "Not/A)Brand",
        _ => "Not_A Brand",
    }
}

fn opera_headers(opera_major: u32, chromium_major: u32, os: Os) -> Vec<(String, String)> {
    let brand = opera_brand(chromium_major);
    let opera_ver = opera_major.to_string();
    let chrome_ver = chromium_major.to_string();

    let sec_ch_ua = format!(
        "\"Opera\";v=\"{opera_ver}\", \"Chromium\";v=\"{chrome_ver}\", \"{brand}\";v=\"24\""
    );

    let (platform, user_agent) = match os {
        Os::Windows => (
            "\"Windows\"",
            format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36 OPR/{opera_ver}.0.0.0"),
        ),
        Os::MacOS => (
            "\"macOS\"",
            format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36 OPR/{opera_ver}.0.0.0"),
        ),
        Os::Linux => (
            "\"Linux\"",
            format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36 OPR/{opera_ver}.0.0.0"),
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
