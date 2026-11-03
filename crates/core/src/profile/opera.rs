use crate::Error;
use crate::tls::config::TrustAnchorId;

use super::chrome::{
    ChromiumHeaders, chrome_http2, chromium_headers, chromium_quic, chromium_tls,
    chromium_trust_anchor_ids, chromium_ua_client_hints,
};
use super::{BrowserProfile, HeaderFamily, LanguageSource, Os, UiTable, last_row, table_version};

/// Opera browser profile factory.
///
/// Opera uses the same Chromium engine as Chrome, so TLS/H2/QUIC are identical to Chrome of the
/// same Chromium version, `trust_anchors` included (from Opera 136 on). Headers differ in the brand
/// string and the `OPR/` user-agent suffix.
pub struct Opera;

pub(super) use super::releases::OPERA_CHROMIUM;

const OPERA_TRUST_ANCHORS_VERSION: u32 = 136;

impl Opera {
    /// Oldest supported Opera major version.
    pub const MIN_VERSION: u32 = OPERA_CHROMIUM[0].0;

    /// Newest supported Opera major version.
    pub const LATEST_VERSION: u32 = OPERA_CHROMIUM[OPERA_CHROMIUM.len() - 1].0;

    /// Operating systems Opera profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Windows, Os::MacOS, Os::Linux];

    /// Opera `major` on `os`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS, or if `major`'s Chrome Root
    /// Store is not embedded although it sends `trust_anchors`.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        let row = table_version("Opera", major, os, Self::PLATFORMS, OPERA_CHROMIUM, |t| t.0)?;
        let trust_anchor_ids =
            chromium_trust_anchor_ids(row.1, major >= OPERA_TRUST_ANCHORS_VERSION)?;
        Ok(opera_profile(row, os, trust_anchor_ids))
    }

    /// Latest Opera on the default OS (Windows): the profile the name `opera` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        let row = last_row(OPERA_CHROMIUM);
        let trust_anchor_ids =
            chromium_trust_anchor_ids(row.1, row.0 >= OPERA_TRUST_ANCHORS_VERSION)
                .expect("the latest Opera version's Chrome Root Store is embedded");
        opera_profile(row, super::DEFAULT_OS, trust_anchor_ids)
    }
}

fn opera_profile(
    row: (u32, u32, &'static str, &'static str),
    os: Os,
    trust_anchor_ids: Option<Vec<TrustAnchorId>>,
) -> BrowserProfile {
    let (major, chromium, opera_full, chromium_full) = row;
    let tls = chromium_tls(chromium, trust_anchor_ids);
    BrowserProfile {
        farble_accept_language: false,
        multipart: Some(crate::BoundaryStyle::WebKit),
        language_source: Some(LanguageSource::UiTable(UiTable::Opera)),
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(chromium_ua_client_hints(
            os,
            chromium,
            "Opera",
            opera_full,
            chromium_full,
        )),
        quic: Some(chromium_quic(&tls)),
        tls,
        http2: chrome_http2(),
        headers: chromium_headers(ChromiumHeaders {
            os,
            chromium_major: chromium,
            brand: "Opera",
            brand_major: major,
            ua_product: &format!(" OPR/{major}.0.0.0"),
        }),
    }
}
