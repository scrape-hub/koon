use crate::Error;

use super::chrome::{
    ChromiumHeaders, ChromiumUaClientHints, Device, MACOS_DEVICE, WINDOWS_DEVICE, chrome_http2,
    chromium_headers, chromium_quic, chromium_tls, chromium_ua_client_hints_on,
};
use super::{BrowserProfile, HeaderFamily, LanguageSource, Os, UiTable, last_row, table_version};

/// Edge browser profile factory.
///
/// Edge uses the same Chromium engine as Chrome, so TLS and H2 are identical, except that Edge
/// never sends the `trust_anchors` extension or runs the server padding field trial. Headers differ
/// in the brand string and the user-agent suffix (`Edg/`, on Android `EdgA/` after Chrome's mobile
/// User-Agent). The Edge major version is the Chromium one.
pub struct Edge;

impl Edge {
    /// Oldest supported Edge major version.
    pub const MIN_VERSION: u32 = EDGE_FULL_VERSIONS[0].0;

    /// Newest supported Edge major version.
    pub const LATEST_VERSION: u32 = EDGE_FULL_VERSIONS[EDGE_FULL_VERSIONS.len() - 1].0;

    /// Operating systems Edge profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Windows, Os::MacOS, Os::Android];

    /// Edge `major` on `os`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        let row = table_version(
            "Edge",
            major,
            os,
            Self::PLATFORMS,
            EDGE_FULL_VERSIONS,
            |t| t.0,
        )?;
        Ok(edge_profile(row, os))
    }

    /// Latest Edge on the default OS (Windows): the profile the name `edge` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        edge_profile(last_row(EDGE_FULL_VERSIONS), super::DEFAULT_OS)
    }
}

use super::releases::EDGE_FULL_VERSIONS;

const EDGE_ANDROID_FULL_VERSIONS: &[(u32, &str)] = &[(153, "153.0.4234.49")];

fn edge_device(os: Os) -> Option<Device> {
    match os {
        Os::Windows => Some(WINDOWS_DEVICE.with_viewport((1238, 1263))),
        Os::MacOS => Some(MACOS_DEVICE.with_viewport((1016, 663))),
        _ => None,
    }
}

fn edge_profile(row: (u32, &'static str, &'static str), os: Os) -> BrowserProfile {
    let (major, mut full, chromium_full) = row;
    let tls = chromium_tls(major, None);
    if os == Os::Android {
        if let Some(&(_, android)) = EDGE_ANDROID_FULL_VERSIONS
            .iter()
            .find(|&&(m, _)| m == major)
        {
            full = android;
        }
    }
    let ua_product = if os == Os::Android {
        format!(" EdgA/{major}.0.0.0")
    } else {
        format!(" Edg/{major}.0.0.0")
    };
    BrowserProfile {
        farble_accept_language: false,
        multipart: Some(crate::BoundaryStyle::WebKit),
        language_source: Some(match os {
            Os::MacOS => LanguageSource::LanguageThenTable(UiTable::Edge),
            Os::Android => LanguageSource::DeviceThenTable(UiTable::Edge),
            _ => LanguageSource::UiTable(UiTable::Edge),
        }),
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(chromium_ua_client_hints_on(ChromiumUaClientHints {
            os,
            chromium_major: major,
            brand: "Microsoft Edge",
            brand_full: full,
            chromium_full,
            device: edge_device(os),
        })),
        quic: Some(chromium_quic(&tls)),
        tls,
        http2: chrome_http2(),
        headers: edge_headers(os, major, &ua_product),
    }
}

fn edge_headers(os: Os, major: u32, ua_product: &str) -> Vec<(String, String)> {
    let mut headers = chromium_headers(ChromiumHeaders {
        os,
        chromium_major: major,
        brand: "Microsoft Edge",
        brand_major: major,
        ua_product,
    });
    if let Some(accept) = headers.iter_mut().find(|(k, _)| k == "accept") {
        accept.1 = accept.1.replace("image/jxl,", "");
    }
    headers
}
