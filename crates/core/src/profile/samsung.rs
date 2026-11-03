use crate::Error;

use super::chrome::{
    ANDROID_DEVICE, BrandListKind, CHROMIUM_ACCEPT_ENCODING_NO_ZSTD, ChromiumHeaders,
    ChromiumUaClientHints, chrome_http2, chromium_brand_list, chromium_headers, chromium_tls,
    chromium_ua_client_hints_on, set_header,
};
use super::{
    BrowserProfile, HeaderFamily, LanguageSource, NetworkQuality, Os, last_row, table_version,
};

/// Samsung Internet for Android profile factory.
///
/// Sends Chrome on Android's TLS/HTTP2/header fingerprint with its own User-Agent, brands and
/// `Accept-Encoding` without zstd. Never uses HTTP/3 or a Finch field trial. Device client hints
/// report a Galaxy A33 5G, not the Pixel of the other Android profiles.
pub struct Samsung;

pub(super) use super::releases::SAMSUNG_CHROMIUM;

const GALAXY_A33_MODEL: &str = "SM-A336B";
const GALAXY_A33_PLATFORM_VERSION: &str = "15.0.0";

const GALAXY_A33_MEMORY_MIB: u64 = 4 * 1024;

const GALAXY_A33_PIXEL_RATIO: f32 = 2.8125;

const GALAXY_A33_VIEWPORT_PX: (u32, u32) = (1080, 1916);

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
    set_header(&mut headers, "accept-language", "en-US,en");
    let mut hints = chromium_ua_client_hints_on(ChromiumUaClientHints {
        os: Os::Android,
        chromium_major: chromium,
        brand: "Samsung Internet",
        brand_full: full,
        chromium_full,
        device: Some(ANDROID_DEVICE),
    });
    hints.full_version = chromium_full.to_string();
    hints.model = GALAXY_A33_MODEL.to_string();
    hints.platform_version = GALAXY_A33_PLATFORM_VERSION.to_string();
    hints.device_memory_mib = GALAXY_A33_MEMORY_MIB;
    hints.device_pixel_ratio = GALAXY_A33_PIXEL_RATIO;
    hints.viewport_px = GALAXY_A33_VIEWPORT_PX;
    hints.network_quality = Some(SAMSUNG_NETWORK_QUALITY);
    BrowserProfile {
        farble_accept_language: false,
        multipart: Some(crate::BoundaryStyle::WebKit),
        language_source: Some(LanguageSource::Samsung),
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(hints),
        quic: None,
        tls: chromium_tls(chromium, None),
        http2: chrome_http2(),
        headers,
    }
}
