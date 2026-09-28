use crate::Error;
use crate::tls::config::TrustAnchorId;

use super::chrome::{
    ChromiumHeaders, chrome_http2, chromium_headers, chromium_quic, chromium_tls,
    chromium_trust_anchor_ids, chromium_ua_client_hints,
};
use super::{BrowserProfile, HeaderFamily, Os, last_row, table_version};

/// Opera browser profile factory.
///
/// Opera uses the same Chromium engine as Chrome, so TLS/H2/QUIC are identical to Chrome of the
/// same Chromium version, `trust_anchors` included (from Opera 136 on). Headers differ in the brand
/// string and the `OPR/` user-agent suffix.
pub struct Opera;

/// Every supported Opera release, oldest first: its major version, the Chromium major it is built
/// on, and the full versions of both its client hints report: the last Stable release of the major
/// (get.geo.opera.com/pub/opera/desktop/) and its Chromium from Opera's changelogs.
pub(super) const OPERA_CHROMIUM: &[(u32, u32, &str, &str)] = &[
    (124, 140, "124.0.5705.65", "140.0.7339.249"),
    (125, 141, "125.0.5729.49", "141.0.7390.125"),
    (126, 142, "126.0.5750.124", "142.0.7444.243"),
    (127, 143, "127.0.5778.125", "143.0.7499.194"),
    (128, 144, "128.0.5807.77", "144.0.7559.173"),
    (129, 145, "129.0.5823.65", "145.0.7632.117"),
    (130, 146, "130.0.5847.92", "146.0.7680.178"),
    (131, 147, "131.0.5877.116", "147.0.7727.138"),
    (132, 148, "132.0.5905.114", "148.0.7778.271"),
    (133, 149, "133.0.5932.85", "149.0.7827.201"),
    (134, 150, "134.0.5954.66", "150.0.7871.212"),
    (135, 151, "135.0.5973.142", "151.0.7922.170"),
    (136, 152, "136.0.6008.52", "152.0.7977.130"),
];

/// First Opera version that sends the `trust_anchors` extension.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_contiguous() {
        for pair in OPERA_CHROMIUM.windows(2) {
            assert_eq!(pair[1].0, pair[0].0 + 1, "gap after Opera {}", pair[0].0);
        }
    }

    /// Captured from Opera 136 on Windows.
    #[test]
    fn opera_136_matches_capture() {
        let profile = Opera::version(136, Os::Windows).unwrap();
        let value = |name: &str| {
            profile
                .headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(
            value("user-agent"),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 OPR/136.0.0.0"
        );
        assert_eq!(
            value("sec-ch-ua"),
            "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Opera\";v=\"136\""
        );
        assert_eq!(
            profile.tls.trust_anchor_ids.as_ref().map(Vec::len),
            Some(32)
        );
        assert!(profile.tls.grease_sigalgs);
        let opera_135 = Opera::version(135, Os::Windows).unwrap().tls;
        assert_eq!(opera_135.trust_anchor_ids, None);
        assert!(!opera_135.grease_sigalgs);
    }
}
