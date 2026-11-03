use super::{BrowserProfile, Release, Stack};

const SAFARI_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

pub(super) fn safari_headers(
    fetch_metadata: bool,
    release: Release,
    user_agent: String,
) -> Vec<(String, String)> {
    let names: &[&str] = match (release.http, fetch_metadata) {
        (Stack::Sonoma, false) => &["user-agent", "accept", "accept-language", "accept-encoding"],
        (Stack::Sonoma, true) => &[
            "accept",
            "sec-fetch-site",
            "accept-encoding",
            "sec-fetch-mode",
            "user-agent",
            "accept-language",
            "sec-fetch-dest",
        ],
        _ => &[
            "sec-fetch-dest",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "accept-language",
            "priority",
            "accept-encoding",
        ],
    };
    let accept_encoding = if release.zstd {
        "gzip, deflate, br, zstd"
    } else {
        "gzip, deflate, br"
    };
    names
        .iter()
        .map(|&name| {
            let value = match name {
                "user-agent" => user_agent.as_str(),
                "accept" => SAFARI_ACCEPT,
                "accept-encoding" => accept_encoding,
                "accept-language" => "en-US,en;q=0.9",
                "sec-fetch-site" => "none",
                "sec-fetch-mode" => "navigate",
                "sec-fetch-dest" => "document",
                _ => "u=0, i",
            };
            (name.to_string(), value.to_string())
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SafariLayout {
    pub(crate) stack: Stack,
    pub(crate) ios: bool,
    pub(crate) fetch_metadata: bool,
    pub(crate) chips: bool,
}

impl SafariLayout {
    pub(crate) fn of(profile: &BrowserProfile) -> Self {
        let user_agent = profile.user_agent().unwrap_or("");
        let ios = user_agent.contains("iPhone") || user_agent.contains("iPad");
        let mut version = user_agent
            .split("Version/")
            .nth(1)
            .and_then(|version| version.split(' ').next())
            .unwrap_or("")
            .split('.')
            .map(|part| part.parse::<u32>().ok());
        let (major, minor) = (version.next().flatten(), version.next().flatten());
        let stack = match major {
            Some(major) if major <= 17 => Stack::Sonoma,
            Some(18) if !ios && minor == Some(0) => Stack::Sonoma,
            Some(18) => Stack::Sequoia,
            _ => Stack::Tahoe,
        };
        let fetch_metadata = profile
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-mode"));
        let chips = match (major, minor) {
            (Some(18), Some(4)) => true,
            (Some(26), minor) => minor.unwrap_or(0) >= 2,
            (Some(major), _) => major > 26,
            (None, _) => true,
        };
        Self {
            stack,
            ios,
            fetch_metadata,
            chips,
        }
    }
}
