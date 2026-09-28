use crate::Error;

use super::chrome::{
    ANDROID_DEVICE, BrandListKind, CHROMIUM_ACCEPT_ENCODING_NO_ZSTD, ChromiumHeaders,
    ChromiumUaClientHints, chrome_http2, chromium_brand_list, chromium_headers, chromium_tls,
    chromium_ua_client_hints_on, set_header,
};
use super::{BrowserProfile, HeaderFamily, NetworkQuality, Os, last_row, table_version};

/// Samsung Internet for Android profile factory.
///
/// Sends Chrome on Android's TLS/HTTP2/header fingerprint with its own User-Agent, brands and
/// `Accept-Encoding` without zstd. Never uses HTTP/3 or a Finch field trial. Device client hints
/// report a Galaxy A33 5G, not the Pixel of the other Android profiles.
pub struct Samsung;

/// Every supported Samsung Internet release: its major version, the Chromium major it builds on,
/// and the full versions its client hints report for both. 30.0.2.61 is not used: it would not
/// install on the capture device.
pub(super) const SAMSUNG_CHROMIUM: &[(u32, u32, &str, &str)] = &[
    (29, 136, "29.0.5.3", "136.0.7103.127"),
    (30, 143, "30.0.2.30", "143.0.7499.194"),
];

/// The device of the Samsung Internet profiles: a Galaxy A33 5G (SM-A336B) on Android 15 (One UI
/// 7), not the Pixel of the other Android profiles. The User-Agent stays reduced (`Android 10; K`).
const GALAXY_A33_MODEL: &str = "SM-A336B";
const GALAXY_A33_PLATFORM_VERSION: &str = "15.0.0";

/// The Galaxy's memory, as its hints and `navigator.deviceMemory` report it.
const GALAXY_A33_MEMORY_MIB: u64 = 4 * 1024;

/// The Galaxy's device pixel ratio.
const GALAXY_A33_PIXEL_RATIO: f32 = 2.8125;

/// The page's viewport on the Galaxy in device pixels: 980×1738 CSS pixels for navigations, 384×681
/// for subresources, derived under the rules of `css_viewport`.
const GALAXY_A33_VIEWPORT_PX: (u32, u32) = (1080, 1916);

/// The network quality Samsung Internet's hints report: an RTT of 100 ms in the browser process and
/// none in the renderer, the capped downlink of 10 Mbit/s in both.
const SAMSUNG_NETWORK_QUALITY: NetworkQuality = NetworkQuality {
    navigation: (100, u32::MAX),
    subresource: (0, u32::MAX),
};

impl Samsung {
    /// Oldest supported Samsung Internet major version.
    pub const MIN_VERSION: u32 = SAMSUNG_CHROMIUM[0].0;

    /// Newest supported Samsung Internet major version.
    pub const LATEST_VERSION: u32 = SAMSUNG_CHROMIUM[SAMSUNG_CHROMIUM.len() - 1].0;

    /// Operating systems Samsung Internet profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Android];

    /// Samsung Internet `major` on `os` (Android).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        let row = table_version(
            "Samsung Internet",
            major,
            os,
            Self::PLATFORMS,
            SAMSUNG_CHROMIUM,
            |t| t.0,
        )?;
        Ok(samsung_profile(row))
    }

    /// Latest Samsung Internet on Android: the profile the name `samsung` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        samsung_profile(last_row(SAMSUNG_CHROMIUM))
    }
}

fn samsung_profile(row: (u32, u32, &'static str, &'static str)) -> BrowserProfile {
    let (_, chromium, full, chromium_full) = row;
    // Samsung reports its major and minor version as the brand version.
    let brand_version = full.splitn(3, '.').take(2).collect::<Vec<_>>().join(".");
    let mut headers = chromium_headers(ChromiumHeaders {
        os: Os::Android,
        chromium_major: chromium,
        brand: "Samsung Internet",
        brand_major: chromium,
        ua_product: "",
    });
    set_header(
        &mut headers,
        "sec-ch-ua",
        chromium_brand_list(
            chromium,
            "Samsung Internet",
            &brand_version,
            &chromium.to_string(),
            BrandListKind::Short,
        ),
    );
    if let Some(ua) = headers.iter().find(|(k, _)| k == "user-agent") {
        let ua = ua.1.replace(
            "(KHTML, like Gecko) Chrome/",
            &format!("(KHTML, like Gecko) SamsungBrowser/{brand_version} Chrome/"),
        );
        set_header(&mut headers, "user-agent", ua);
    }
    set_header(
        &mut headers,
        "accept-encoding",
        CHROMIUM_ACCEPT_ENCODING_NO_ZSTD,
    );
    let mut hints = chromium_ua_client_hints_on(ChromiumUaClientHints {
        os: Os::Android,
        chromium_major: chromium,
        brand: "Samsung Internet",
        brand_full: full,
        chromium_full,
        device: Some(ANDROID_DEVICE),
    });
    // Sec-CH-UA-Full-Version carries the Chromium version (captured).
    hints.full_version = chromium_full.to_string();
    hints.model = GALAXY_A33_MODEL.to_string();
    hints.platform_version = GALAXY_A33_PLATFORM_VERSION.to_string();
    hints.device_memory_mib = GALAXY_A33_MEMORY_MIB;
    hints.device_pixel_ratio = GALAXY_A33_PIXEL_RATIO;
    hints.viewport_px = GALAXY_A33_VIEWPORT_PX;
    hints.network_quality = Some(SAMSUNG_NETWORK_QUALITY);
    BrowserProfile {
        farble_accept_language: false,
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(hints),
        quic: None,
        tls: chromium_tls(chromium, None),
        http2: chrome_http2(),
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Headers and client hints of Samsung Internet 30.0.2.30.
    #[test]
    fn samsung_30_matches_capture() {
        let profile = Samsung::latest();
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
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/30.0 Chrome/143.0.0.0 Mobile Safari/537.36"
        );
        assert_eq!(
            value("sec-ch-ua"),
            "\"Samsung Internet\";v=\"30.0\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\""
        );
        assert_eq!(value("accept-encoding"), "gzip, deflate, br");
        let hints = profile.ua_client_hints.as_ref().unwrap();
        assert_eq!(
            hints.full_version_list,
            "\"Samsung Internet\";v=\"30.0.2.30\", \"Chromium\";v=\"143.0.7499.194\", \"Not A(Brand\";v=\"24.0.0.0\""
        );
        assert_eq!(hints.full_version, "143.0.7499.194");
        // The Galaxy A33 5G.
        assert_eq!(hints.model, "SM-A336B");
        assert_eq!(hints.platform_version, "15.0.0");
        assert_eq!(hints.form_factors, ["Mobile"]);
        assert_eq!(
            (hints.architecture.as_str(), hints.bitness.as_str()),
            ("", "")
        );
        assert_eq!(hints.device_memory_mib, 4096);
        assert_eq!(hints.device_pixel_ratio, 2.8125);
        assert_eq!(hints.viewport_px, (1080, 1916));
        // No HTTP/3, no trust_anchors, no field trial.
        assert!(profile.quic.is_none());
        assert_eq!(profile.tls.trust_anchor_ids, None);
        assert_eq!(profile.tls.server_padding_trial, None);
    }

    /// Samsung Internet 29.0.5.3: Chromium 136's brand order and GREASE brand, which differ from
    /// 30's.
    #[test]
    fn samsung_29_matches_capture() {
        let profile = Samsung::version(29, Os::Android).unwrap();
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
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/136.0.0.0 Mobile Safari/537.36"
        );
        assert_eq!(
            value("sec-ch-ua"),
            "\"Chromium\";v=\"136\", \"Samsung Internet\";v=\"29.0\", \"Not.A/Brand\";v=\"99\""
        );
        assert_eq!(value("accept-encoding"), "gzip, deflate, br");
        let hints = profile.ua_client_hints.as_ref().unwrap();
        assert_eq!(
            hints.full_version_list,
            "\"Chromium\";v=\"136.0.7103.127\", \"Samsung Internet\";v=\"29.0.5.3\", \"Not.A/Brand\";v=\"99.0.0.0\""
        );
        assert_eq!(hints.full_version, "136.0.7103.127");
        assert_eq!(hints.model, "SM-A336B");
        assert!(profile.quic.is_none());
        assert!(Samsung::version(28, Os::Android).is_err());
    }
}
