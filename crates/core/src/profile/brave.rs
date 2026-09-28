use crate::Error;

use super::chrome::{
    ChromiumHeaders, chrome_http2, chromium_headers, chromium_quic, chromium_tls,
    chromium_ua_client_hints, set_header,
};
use super::{BrowserProfile, HeaderFamily, Os, table_version};

/// Brave browser profile factory.
///
/// Brave sends Chrome's TLS/HTTP2/HTTP3 fingerprint of the same Chromium version without
/// `trust_anchors` or the server padding trial, `sec-gpc: 1` requests, a farbled Accept-Language
/// ([`BrowserProfile::farble_accept_language`]), and client hints limited to the User-Agent ones
/// with reduced full versions. Profiles are named by the Chromium major Brave reports (`brave154`
/// is Brave 1.96).
pub struct Brave;

/// Every supported Brave release: the Chromium major it builds on (the profile's version), the last
/// Brave release on it and its Chromium full version. Only the major is read — Brave reduces every
/// full version to `{major}.0.0.0` on the wire; the other two columns are release-note provenance,
/// kept so the exact Brave build this profile was captured from stays on record.
pub(super) const BRAVE_CHROMIUM: &[(u32, &str, &str)] = &[
    (153, "1.95.104", "153.0.8010.53"),
    (154, "1.96.59", "154.0.8037.58"),
];

/// The client hints Brave sends when an origin asks for them: the User-Agent ones without
/// `Sec-CH-UA-Full-Version` and `Sec-CH-UA-Form-Factors`; no device, network or preference hints.
const BRAVE_SENT_HINTS: &[&str] = &[
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-ua-full-version-list",
];

impl Brave {
    /// Oldest supported Brave, by its Chromium major version.
    pub const MIN_VERSION: u32 = BRAVE_CHROMIUM[0].0;

    /// Newest supported Brave, by its Chromium major version.
    pub const LATEST_VERSION: u32 = BRAVE_CHROMIUM[BRAVE_CHROMIUM.len() - 1].0;

    /// Operating systems Brave profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Windows, Os::MacOS, Os::Linux, Os::Android];

    /// Brave on Chromium `major` on `os`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        let (major, ..) =
            table_version("Brave", major, os, Self::PLATFORMS, BRAVE_CHROMIUM, |t| t.0)?;
        Ok(brave_profile(major, os))
    }

    /// Latest Brave on the default OS (Windows): the profile the name `brave` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        brave_profile(Self::LATEST_VERSION, super::DEFAULT_OS)
    }
}

fn brave_profile(major: u32, os: Os) -> BrowserProfile {
    let tls = chromium_tls(major, None);
    let mut headers = chromium_headers(ChromiumHeaders {
        os,
        chromium_major: major,
        brand: "Brave",
        brand_major: major,
        ua_product: "",
    });
    // No signed exchanges.
    if let Some(accept) = headers.iter().find(|(k, _)| k == "accept") {
        let accept = accept
            .1
            .replace(",application/signed-exchange;v=b3;q=0.7", "");
        set_header(&mut headers, "accept", accept);
    }
    // The q value is added per request (farbling).
    set_header(&mut headers, "accept-language", "en-US,en");
    let accept = headers
        .iter()
        .position(|(k, _)| k == "accept")
        .expect("Chromium headers have an Accept");
    headers.insert(accept + 1, ("sec-gpc".into(), "1".into()));
    // Brave reports every full version as the major version.
    let reduced = format!("{major}.0.0.0");
    let mut hints = chromium_ua_client_hints(os, major, "Brave", &reduced, &reduced);
    hints.model = String::new();
    hints.sent_hints = Some(
        BRAVE_SENT_HINTS
            .iter()
            .copied()
            .map(ToString::to_string)
            .collect(),
    );
    BrowserProfile {
        farble_accept_language: true,
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(hints),
        quic: Some(chromium_quic(&tls)),
        tls,
        http2: chrome_http2(),
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Navigation headers of Brave 1.96.59 on Windows, without the q value Brave draws per site.
    #[test]
    fn brave_154_matches_capture() {
        let profile = Brave::version(154, Os::Windows).unwrap();
        let captured = [
            (
                "sec-ch-ua",
                "\"Chromium\";v=\"154\", \"Brave\";v=\"154\", \"Not A(Brand\";v=\"99\"",
            ),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", "\"Windows\""),
            ("upgrade-insecure-requests", "1"),
            (
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
            ),
            (
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            ),
            ("sec-gpc", "1"),
            ("sec-fetch-site", "none"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-user", "?1"),
            ("sec-fetch-dest", "document"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", "en-US,en"),
            ("priority", "u=0, i"),
        ];
        let headers: Vec<(&str, &str)> = profile
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(headers, captured);
        assert!(profile.farble_accept_language);
        let hints = profile.ua_client_hints.as_ref().unwrap();
        assert_eq!(
            hints.full_version_list,
            "\"Chromium\";v=\"154.0.0.0\", \"Brave\";v=\"154.0.0.0\", \"Not A(Brand\";v=\"99.0.0.0\""
        );
        assert_eq!(hints.model, "");
        assert_eq!(hints.platform_version, "19.0.0");
        // No trust_anchors and no server padding field trial.
        assert_eq!(profile.tls.trust_anchor_ids, None);
        assert_eq!(profile.tls.server_padding_trial, None);
        let quic = profile.quic.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(quic.trust_anchor_ids, None);
    }

    /// Brave 1.96.59 on Android: Chrome's mobile User-Agent, the Android platform version, no
    /// model.
    #[test]
    fn brave_mobile_154_matches_capture() {
        let profile = Brave::version(154, Os::Android).unwrap();
        assert_eq!(
            profile.user_agent(),
            Some(
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36"
            )
        );
        let hints = profile.ua_client_hints.as_ref().unwrap();
        assert_eq!(hints.platform_version, "17.0.0");
        assert_eq!(hints.model, "");
        assert_eq!(hints.full_version, "154.0.0.0");
    }
}
