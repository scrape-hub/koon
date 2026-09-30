//! Safari's request headers and per-connection layout.

use super::{BrowserProfile, Release, Stack};

const SAFARI_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// The headers of a navigation, in Safari's order (the request builder lays out the other requests,
/// see [`SafariLayout`]). `WebKit` adds fetch metadata from Safari 16.4 on; the network stack adds
/// `priority` from macOS 15 and iOS 18 on, and `zstd` from 26.3 on. Safari sends no
/// `upgrade-insecure-requests` to https URLs.
pub(super) fn safari_headers(
    fetch_metadata: bool,
    release: Release,
    user_agent: String,
) -> Vec<(String, String)> {
    let names: &[&str] = match (release.http, fetch_metadata) {
        // macOS 12 and 13 (captured): no fetch metadata yet (WebKit added it from Safari 16.4 on).
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

/// How the requests of a Safari profile are laid out: by the network stack of the OS release its
/// User-Agent's Safari version ships with (see [`Safari`]), and whether it names an iPhone. Safari
/// 17 and older take the stack of macOS 14 and iOS 17, 18 that of macOS 15 and iOS 18 (18.0 on
/// macOS that of macOS 14: it ships with macOS 15.0), 26 and newer that of macOS 26 and iOS 26, as
/// the built-in profiles do; a User-Agent without a `Version/` takes the newest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SafariLayout {
    pub(crate) stack: Stack,
    pub(crate) ios: bool,
    /// Whether `WebKit` sends fetch metadata (`sec-fetch-*`) at all: from Safari 16.4 on. Below
    /// that (macOS 12/13 and iOS 16.0/16.1's Sonoma stack, `fetch_metadata: false` in
    /// [`SafariVersion`](super::SafariVersion)), the request builder's hash order for a
    /// non-navigation request is a different one, calibrated on macOS 12.5/12.6/13.0 and the iOS
    /// 16.0/16.1 simulators: a captured header *set* changes `CFNetwork`'s hash order, and fetch
    /// metadata is the biggest such change within the Sonoma stack.
    pub(crate) fetch_metadata: bool,
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
        Self {
            stack,
            ios,
            fetch_metadata,
        }
    }
}
