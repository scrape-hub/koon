use crate::Error;

use super::chrome::{
    ChromiumHeaders, ChromiumUaClientHints, Device, MACOS_DEVICE, WINDOWS_DEVICE, chrome_http2,
    chromium_headers, chromium_quic, chromium_tls, chromium_ua_client_hints_on,
};
use super::{BrowserProfile, HeaderFamily, Os, last_row, table_version};

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

/// Full version of the last Stable release of each Edge major, for Windows and macOS alike, next to
/// the Chromium full version the release reports for the "Chromium" brand of
/// `Sec-CH-UA-Full-Version-List`. `Edge::MIN_VERSION`/`LATEST_VERSION` are derived from this table,
/// and `table_version` looks a version up in it.
const EDGE_FULL_VERSIONS: &[(u32, &str, &str)] = &[
    (131, "131.0.2903.147", "131.0.6778.266"),
    (132, "132.0.2957.178", "132.0.6834.197"),
    (133, "133.0.3065.92", "133.0.6943.143"),
    (134, "134.0.3124.129", "134.0.6998.179"),
    (135, "135.0.3179.98", "135.0.7049.116"),
    (136, "136.0.3240.131", "136.0.7103.116"),
    (137, "137.0.3296.93", "137.0.7151.121"),
    (138, "138.0.3351.151", "138.0.7204.185"),
    (139, "139.0.3405.125", "139.0.7258.156"),
    (140, "140.0.3485.130", "140.0.7339.210"),
    (141, "141.0.3537.99", "141.0.7390.124"),
    (142, "142.0.3595.157", "142.0.7444.177"),
    (143, "143.0.3650.139", "143.0.7499.194"),
    (144, "144.0.3719.162", "144.0.7559.135"),
    (145, "145.0.3800.97", "145.0.7632.161"),
    (146, "146.0.3856.152", "146.0.7680.180"),
    (147, "147.0.3912.98", "147.0.7727.139"),
    (148, "148.0.3967.137", "148.0.7778.218"),
    (149, "149.0.4022.98", "149.0.7827.201"),
    (150, "150.0.4078.144", "150.0.7871.189"),
    (151, "151.0.4129.107", "151.0.7922.174"),
    // 152.0.4191.96 went out on the Extended Stable channel.
    (152, "152.0.4191.96", "152.0.7977.85"),
    (153, "153.0.4234.48", "153.0.8010.53"),
    (154, "154.0.4258.37", "154.0.8037.58"),
];

/// Edge on Android's full version where it differs from the desktop one of [`EDGE_FULL_VERSIONS`].
/// Other Android versions take the desktop ones.
const EDGE_ANDROID_FULL_VERSIONS: &[(u32, &str)] = &[(153, "153.0.4234.49")];

/// Edge's viewport, its toolbar being narrower than Chrome's.
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
        header_family: Some(HeaderFamily::Chromium),
        // Edge's own full version for its brand, the Chromium one it builds on for the Chromium
        // brand (captured). On www.google.com Edge presents itself as Chrome, which koon does not
        // reproduce.
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
        headers: chromium_headers(ChromiumHeaders {
            os,
            chromium_major: major,
            brand: "Microsoft Edge",
            brand_major: major,
            ua_product: &ua_product,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edge 153.0.4234.49 on Android (Pixel 9 Pro XL), captured.
    #[test]
    fn edge_mobile_153_matches_capture() {
        let profile = Edge::version(153, Os::Android).unwrap();
        assert_eq!(
            profile.user_agent(),
            Some(
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36 EdgA/153.0.0.0"
            )
        );
        let sec_ch_ua = profile
            .headers
            .iter()
            .find(|(k, _)| k == "sec-ch-ua")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            sec_ch_ua,
            Some("\"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"153\"")
        );
        let hints = profile.ua_client_hints.as_ref().unwrap();
        assert_eq!(
            hints.full_version_list,
            "\"Microsoft Edge\";v=\"153.0.4234.49\", \"Not_A Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"153.0.8010.53\""
        );
        assert_eq!(hints.model, "Pixel 9 Pro XL");
        assert_eq!(profile.tls.trust_anchor_ids, None);
        assert_eq!(profile.tls.server_padding_trial, None);
    }

    /// Navigation headers of Edge 152-154 on Windows, in wire order.
    #[test]
    fn edge_152_to_154_headers_match_capture() {
        for (major, sec_ch_ua) in [
            (
                152,
                "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Microsoft Edge\";v=\"152\"",
            ),
            (
                153,
                "\"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"153\"",
            ),
            (
                154,
                "\"Chromium\";v=\"154\", \"Microsoft Edge\";v=\"154\", \"Not A(Brand\";v=\"99\"",
            ),
        ] {
            let profile = Edge::version(major, Os::Windows).unwrap();
            let user_agent = format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36 Edg/{major}.0.0.0"
            );
            let captured = [
                ("sec-ch-ua", sec_ch_ua),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"Windows\""),
                ("upgrade-insecure-requests", "1"),
                ("user-agent", &user_agent),
                (
                    "accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                ),
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-user", "?1"),
                ("sec-fetch-dest", "document"),
                ("accept-encoding", "gzip, deflate, br, zstd"),
                ("accept-language", "en-US,en;q=0.9"),
                ("priority", "u=0, i"),
            ];
            let headers: Vec<(&str, &str)> = profile
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(headers, captured, "Edge {major}");
        }
    }

    /// Edge 152-154 put a GREASE value first in signature_algorithms, like Chrome from 152 on, and
    /// still send no trust_anchors extension.
    #[test]
    fn edge_152_to_154_tls_match_capture() {
        for major in [152, 153, 154] {
            let tls = Edge::version(major, Os::Windows).unwrap().tls;
            assert!(tls.grease_sigalgs, "Edge {major}");
            assert!(tls.sigalgs.starts_with("mldsa44:mldsa65:mldsa87:"));
            assert_eq!(tls.trust_anchor_ids, None);
        }
    }

    /// The high-entropy hints of Edge 154.0.4258.37 on Windows 11: Edge's version for its brand,
    /// Chromium's for the Chromium brand.
    #[test]
    fn edge_154_client_hints_match_capture() {
        let hints = Edge::version(154, Os::Windows)
            .unwrap()
            .ua_client_hints
            .unwrap();
        assert_eq!(hints.full_version, "154.0.4258.37");
        assert_eq!(
            hints.full_version_list,
            "\"Chromium\";v=\"154.0.8037.58\", \"Microsoft Edge\";v=\"154.0.4258.37\", \"Not A(Brand\";v=\"99.0.0.0\""
        );
    }

    #[test]
    fn full_versions_match_their_major() {
        for &(major, edge, chromium) in EDGE_FULL_VERSIONS {
            assert!(edge.starts_with(&format!("{major}.0.")), "{edge}");
            assert!(chromium.starts_with(&format!("{major}.0.")), "{chromium}");
        }
    }
}
