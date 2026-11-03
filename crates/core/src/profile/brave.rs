use crate::Error;

use super::chrome::{
    ChromiumHeaders, chrome_http2, chromium_headers, chromium_quic, chromium_tls,
    chromium_ua_client_hints, set_header,
};
use super::{BrowserProfile, HeaderFamily, LanguageSource, Os, UiTable, table_version};

/// Brave browser profile factory.
///
/// Brave sends Chrome's TLS/HTTP2/HTTP3 fingerprint of the same Chromium version without
/// `trust_anchors` or the server padding trial, `sec-gpc: 1` requests, a farbled Accept-Language
/// ([`BrowserProfile::farble_accept_language`]), and client hints limited to the User-Agent ones
/// with reduced full versions. Profiles are named by the Chromium major Brave reports (`brave154`
/// is Brave 1.96).
pub struct Brave;

pub(super) use super::releases::BRAVE_CHROMIUM;

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
    if let Some(accept) = headers.iter().find(|(k, _)| k == "accept") {
        let accept = accept
            .1
            .replace(",application/signed-exchange;v=b3;q=0.7", "");
        set_header(&mut headers, "accept", accept);
    }
    set_header(&mut headers, "accept-language", "en-US,en");
    let accept = headers
        .iter()
        .position(|(k, _)| k == "accept")
        .expect("Chromium headers have an Accept");
    headers.insert(accept + 1, ("sec-gpc".into(), "1".into()));
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
        multipart: Some(crate::BoundaryStyle::WebKit),
        language_source: Some(match os {
            Os::Android => LanguageSource::DeviceThenTable(UiTable::ChromiumAndroid),
            _ => LanguageSource::UiTable(UiTable::Chromium),
        }),
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(hints),
        quic: Some(chromium_quic(&tls)),
        tls,
        http2: chrome_http2(),
        headers,
    }
}
