//! Chrome browser profile factory, split by concern: [`tls`], [`http2`], [`quic`], [`headers`],
//! [`client_hints`]. [`Edge`](super::Edge), [`Opera`](super::Opera),
//! [`OperaMobile`](super::OperaMobile), [`Brave`](super::Brave) and [`Samsung`](super::Samsung)
//! build on the re-exports here, since they share Chrome's TLS/HTTP2/QUIC fingerprint and
//! header/client-hint shape.

mod client_hints;
mod headers;
mod http2;
mod quic;
mod tls;

use crate::Error;
use crate::tls::config::{TrustAnchorId, TrustAnchorOrder};

use super::{BrowserProfile, HeaderFamily, Os, last_row, table_version};
pub(super) use client_hints::{
    ANDROID_DEVICE, ChromiumUaClientHints, Device, MACOS_DEVICE, WINDOWS_DEVICE,
    chromium_ua_client_hints, chromium_ua_client_hints_on,
};
use client_hints::{CHROME_FULL_VERSIONS, full_version_for_os};
pub(super) use headers::{
    BrandListKind, CHROMIUM_ACCEPT_ENCODING_NO_ZSTD, ChromiumHeaders, chromium_brand_list,
    chromium_headers, set_header,
};
pub(super) use http2::chrome_http2;
pub(super) use quic::chromium_quic;
use tls::{
    CHROME_152_MACOS_TRUST_ANCHOR_ORDER, CHROME_PQC_BANDWIDTH_VERSION,
    CHROME_TRUST_ANCHORS_VERSION, pqc_bandwidth_experiment,
};
pub(super) use tls::{chromium_tls, chromium_trust_anchor_ids};

/// Chrome browser profile factory.
///
/// The H2 and QUIC fingerprints are identical across
/// [`MIN_VERSION`](Self::MIN_VERSION)-[`LATEST_VERSION`](Self::LATEST_VERSION); the TLS
/// `ClientHello` is version-dependent. From 151 on a client may be drawn into the
/// `PqcBandwidthExperiment` field trial and ask for server padding.
pub struct Chrome;

impl Chrome {
    /// Oldest supported Chrome major version.
    pub const MIN_VERSION: u32 = CHROME_FULL_VERSIONS[0].0;

    /// Newest supported Chrome major version.
    pub const LATEST_VERSION: u32 = CHROME_FULL_VERSIONS[CHROME_FULL_VERSIONS.len() - 1].0;

    /// Operating systems Chrome profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Windows, Os::MacOS, Os::Linux, Os::Android];

    /// Chrome `major` on `os`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS, or if `major`'s Chrome Root
    /// Store is not embedded although it sends `trust_anchors`.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        let row = table_version(
            "Chrome",
            major,
            os,
            Self::PLATFORMS,
            CHROME_FULL_VERSIONS,
            |t| t.0,
        )?;
        let trust_anchor_ids =
            chromium_trust_anchor_ids(major, major >= CHROME_TRUST_ANCHORS_VERSION)?;
        Ok(chrome_profile(row, os, trust_anchor_ids))
    }

    /// Latest Chrome on the default OS (Windows): the profile the name `chrome` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        let row = last_row(CHROME_FULL_VERSIONS);
        let trust_anchor_ids =
            chromium_trust_anchor_ids(row.0, row.0 >= CHROME_TRUST_ANCHORS_VERSION)
                .expect("the latest Chrome version's Chrome Root Store is embedded");
        chrome_profile(row, super::DEFAULT_OS, trust_anchor_ids)
    }
}

fn chrome_profile(
    row: (u32, [&'static str; 4]),
    os: Os,
    trust_anchor_ids: Option<Vec<TrustAnchorId>>,
) -> BrowserProfile {
    let (major, versions) = row;
    // Chrome on Android sends the TLS, HTTP/2 and QUIC fingerprint of desktop Chrome.
    let mut tls = chromium_tls(major, trust_anchor_ids);
    if major >= CHROME_PQC_BANDWIDTH_VERSION {
        tls.server_padding_trial = Some(pqc_bandwidth_experiment());
    }
    let quic = chromium_quic(&tls);
    if os == Os::MacOS && major == 152 {
        tls.trust_anchor_ids = Some(
            CHROME_152_MACOS_TRUST_ANCHOR_ORDER
                .iter()
                .map(|id| TrustAnchorId::from_static(id))
                .collect(),
        );
        tls.trust_anchor_order = TrustAnchorOrder::Listed;
    }
    let full = full_version_for_os(versions, os);
    BrowserProfile {
        farble_accept_language: false,
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(chromium_ua_client_hints(
            os,
            major,
            "Google Chrome",
            full,
            full,
        )),
        quic: Some(quic),
        tls,
        http2: chrome_http2(),
        headers: chromium_headers(ChromiumHeaders {
            os,
            chromium_major: major,
            brand: "Google Chrome",
            brand_major: major,
            ua_product: "",
        }),
    }
}
