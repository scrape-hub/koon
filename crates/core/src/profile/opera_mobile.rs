use crate::Error;

use super::chrome::{
    ANDROID_DEVICE, CHROMIUM_ACCEPT_ENCODING_NO_ZSTD, ChromiumHeaders, ChromiumUaClientHints,
    chrome_http2, chromium_headers, chromium_quic, chromium_tls, chromium_ua_client_hints_on,
    set_header,
};
use super::{BrowserProfile, HeaderFamily, Os, last_row, table_version};

/// Opera for Android profile factory.
///
/// Sends Chrome on Android's fingerprint without `trust_anchors` or the server padding trial, with
/// its own User-Agent, brands, client hints and an `ENABLE_PUSH`-free HTTP/2 SETTINGS. Numbered
/// apart from desktop Opera (profiles are named `opera-mobile102`); Android only.
pub struct OperaMobile;

/// Every supported Opera for Android release: its major version, the Chromium major it builds on,
/// the desktop Opera major its `Opera` brand reports, and the full versions its client hints report
/// for `OperaMobile`, Opera and Chromium. Only the captured release: the brand list is Opera's own,
/// with no known rule to derive other releases' from.
pub(super) const OPERA_MOBILE_CHROMIUM: &[(u32, u32, u32, &str, &str, &str)] = &[(
    102,
    152,
    137,
    "102.1.5206.90382",
    "137.0.6010.1",
    "152.0.7977.82",
)];

/// The page's viewport: its hints reported 980 on navigations and subresources alike. The height
/// was not captured; derived from Chrome's layout viewport of the same device.
const OPERA_MOBILE_VIEWPORT_PX: (u32, u32) = (2205, 4189);

impl OperaMobile {
    /// Oldest supported Opera for Android major version.
    pub const MIN_VERSION: u32 = OPERA_MOBILE_CHROMIUM[0].0;

    /// Newest supported Opera for Android major version.
    pub const LATEST_VERSION: u32 = OPERA_MOBILE_CHROMIUM[OPERA_MOBILE_CHROMIUM.len() - 1].0;

    /// Operating systems Opera for Android profiles exist for.
    pub const PLATFORMS: &'static [Os] = &[Os::Android];

    /// Opera for Android `major` on `os` (Android).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS.
    pub fn version(major: u32, os: Os) -> Result<BrowserProfile, Error> {
        let row = table_version(
            "Opera Mobile",
            major,
            os,
            Self::PLATFORMS,
            OPERA_MOBILE_CHROMIUM,
            |t| t.0,
        )?;
        Ok(opera_mobile_profile(row))
    }

    /// Latest Opera for Android: the profile the name `opera-mobile` resolves to.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        opera_mobile_profile(last_row(OPERA_MOBILE_CHROMIUM))
    }
}

/// The four brands Opera for Android reports, in its order, with `version` giving each brand's
/// version.
fn opera_mobile_brands(versions: [&str; 4]) -> String {
    let [mobile, opera, chromium, grease] = versions;
    format!(
        "\"OperaMobile\";v=\"{mobile}\", \"Opera\";v=\"{opera}\", \"Chromium\";v=\"{chromium}\", \" Not A;Brand\";v=\"{grease}\""
    )
}

fn opera_mobile_profile(
    row: (u32, u32, u32, &'static str, &'static str, &'static str),
) -> BrowserProfile {
    let (major, chromium, opera, full, opera_full, chromium_full) = row;
    let tls = chromium_tls(chromium, None);
    let mut headers = chromium_headers(ChromiumHeaders {
        os: Os::Android,
        chromium_major: chromium,
        brand: "OperaMobile",
        brand_major: major,
        ua_product: &format!(" OPR/{major}.0.0.0"),
    });
    set_header(
        &mut headers,
        "sec-ch-ua",
        opera_mobile_brands([
            &major.to_string(),
            &opera.to_string(),
            &chromium.to_string(),
            "99",
        ]),
    );
    set_header(
        &mut headers,
        "accept-encoding",
        CHROMIUM_ACCEPT_ENCODING_NO_ZSTD,
    );
    let mut hints = chromium_ua_client_hints_on(ChromiumUaClientHints {
        os: Os::Android,
        chromium_major: chromium,
        brand: "OperaMobile",
        brand_full: full,
        chromium_full,
        device: Some(ANDROID_DEVICE),
    });
    hints.full_version_list = opera_mobile_brands([full, opera_full, chromium_full, "99.0.0.0"]);
    hints.platform_version = "17".into();
    hints.form_factors = Vec::new();
    hints.viewport_px = OPERA_MOBILE_VIEWPORT_PX;
    let mut http2 = chrome_http2();
    http2.enable_push = None;
    http2.max_concurrent_streams = Some(1000);
    BrowserProfile {
        farble_accept_language: false,
        header_family: Some(HeaderFamily::Chromium),
        ua_client_hints: Some(hints),
        quic: Some(chromium_quic(&tls)),
        tls,
        http2,
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opera 102.1.5206.90382 on Android.
    #[test]
    fn opera_mobile_102_matches_capture() {
        let profile = OperaMobile::latest();
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
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36 OPR/102.0.0.0"
        );
        assert_eq!(
            value("sec-ch-ua"),
            "\"OperaMobile\";v=\"102\", \"Opera\";v=\"137\", \"Chromium\";v=\"152\", \" Not A;Brand\";v=\"99\""
        );
        assert_eq!(value("accept-encoding"), "gzip, deflate, br");
        assert!(value("accept").ends_with("application/signed-exchange;v=b3;q=0.7"));
        let hints = profile.ua_client_hints.as_ref().unwrap();
        assert_eq!(
            hints.full_version_list,
            "\"OperaMobile\";v=\"102.1.5206.90382\", \"Opera\";v=\"137.0.6010.1\", \"Chromium\";v=\"152.0.7977.82\", \" Not A;Brand\";v=\"99.0.0.0\""
        );
        assert_eq!(hints.full_version, "102.1.5206.90382");
        assert_eq!(hints.platform_version, "17");
        assert!(hints.form_factors.is_empty());
        assert_eq!(hints.model, "Pixel 9 Pro XL");
        // Chromium 152's ClientHello without trust_anchors and padding.
        assert_eq!(profile.tls.trust_anchor_ids, None);
        assert_eq!(profile.tls.server_padding_trial, None);
        assert!(profile.tls.grease_sigalgs);
        // SETTINGS 1, 3, 4, 6.
        assert_eq!(profile.http2.enable_push, None);
        assert_eq!(profile.http2.max_concurrent_streams, Some(1000));
    }
}
