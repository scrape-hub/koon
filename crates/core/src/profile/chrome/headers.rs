//! Chromium-family navigation headers (Chrome, Edge, Opera and derived browsers).

use crate::profile::Os;

/// First Chromium version whose Accept headers list `image/jxl`: `kJXLImageFormat` turns on by
/// default (`third_party/blink/common/features.cc`).
const CHROMIUM_JXL_VERSION: u32 = 155;

/// The navigation Accept of Chromium `chromium_major`.
pub(super) fn chromium_navigation_accept(chromium_major: u32) -> String {
    let jxl = if chromium_major >= CHROMIUM_JXL_VERSION {
        "image/jxl,"
    } else {
        ""
    };
    format!(
        "text/html,application/xhtml+xml,application/xml;q=0.9,{jxl}image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    )
}

/// Parameters for [`chromium_headers`]: what varies between Chrome and its Chromium-family
/// siblings. A named struct instead of five positional parameters, two of them (`chromium_major`,
/// `brand_major`) the same type with different meanings.
pub struct ChromiumHeaders<'a> {
    pub os: Os,
    /// The Chromium major version: `Chrome/{chromium_major}.0.0.0` in the User-Agent, and the
    /// Accept header's JPEG XL cutoff.
    pub chromium_major: u32,
    /// The product name in `sec-ch-ua` ("Google Chrome", "Microsoft Edge", "Opera").
    pub brand: &'a str,
    /// The brand's own major version in `sec-ch-ua` (the Chromium one for Chrome and Edge, the
    /// browser's own for Opera and Opera Mobile).
    pub brand_major: u32,
    /// Appended to the User-Agent (` Edg/151.0.0.0`, empty for Chrome).
    pub ua_product: &'a str,
}

/// Navigation headers of a Chromium-based browser.
pub fn chromium_headers(params: ChromiumHeaders<'_>) -> Vec<(String, String)> {
    let ChromiumHeaders {
        os,
        chromium_major,
        brand,
        brand_major,
        ua_product,
    } = params;
    let (platform, ua_os) = match os {
        Os::Windows => ("\"Windows\"", "Windows NT 10.0; Win64; x64"),
        Os::MacOS => ("\"macOS\"", "Macintosh; Intel Mac OS X 10_15_7"),
        Os::Linux => ("\"Linux\"", "X11; Linux x86_64"),
        Os::Android => ("\"Android\"", "Linux; Android 10; K"),
        Os::Ios => unreachable!("no Chromium profile for iOS"),
    };
    let mobile = os == Os::Android;
    let safari = if mobile {
        "Mobile Safari/537.36"
    } else {
        "Safari/537.36"
    };
    let user_agent = format!(
        "Mozilla/5.0 ({ua_os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chromium_major}.0.0.0 {safari}{ua_product}"
    );
    vec![
        (
            "sec-ch-ua".into(),
            chromium_sec_ch_ua(chromium_major, brand, brand_major),
        ),
        (
            "sec-ch-ua-mobile".into(),
            if mobile { "?1" } else { "?0" }.into(),
        ),
        ("sec-ch-ua-platform".into(), platform.into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("user-agent".into(), user_agent),
        ("accept".into(), chromium_navigation_accept(chromium_major)),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
    ]
}

/// The sec-ch-ua value of a Chromium-based browser, built with Chromium's GREASE algorithm
/// (`user_agent_utils.cc`): the Chromium major version seeds the GREASE brand and the order of the
/// brand list.
///
/// `brand` is the product name ("Google Chrome", "Microsoft Edge", "Opera"), `brand_major` its
/// major version (the Chromium one for Chrome and Edge).
fn chromium_sec_ch_ua(chromium_major: u32, brand: &str, brand_major: u32) -> String {
    chromium_brand_list(
        chromium_major,
        brand,
        &brand_major.to_string(),
        &chromium_major.to_string(),
        BrandListKind::Short,
    )
}

/// Set `name`'s value in `headers`, if present.
pub fn set_header(headers: &mut [(String, String)], name: &str, value: impl Into<String>) {
    if let Some((_, v)) = headers.iter_mut().find(|(k, _)| k == name) {
        *v = value.into();
    }
}

/// Accept-Encoding without zstd, as Opera for Android and Samsung Internet send it.
pub const CHROMIUM_ACCEPT_ENCODING_NO_ZSTD: &str = "gzip, deflate, br";

/// Which brand-list form [`chromium_brand_list`] builds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrandListKind {
    /// `sec-ch-ua`: major versions.
    Short,
    /// `sec-ch-ua-full-version-list`: full versions, the GREASE brand's with `.0.0.0` appended.
    Full,
}

/// The brand list of `sec-ch-ua` or, with [`BrandListKind::Full`], of
/// `sec-ch-ua-full-version-list`, where the GREASE brand's version gets `.0.0.0` appended
/// (`GetProcessedGreasedBrandVersion`).
pub fn chromium_brand_list(
    chromium_major: u32,
    brand: &str,
    brand_version: &str,
    chromium_version: &str,
    kind: BrandListKind,
) -> String {
    const GREASE_CHARS: [char; 11] = [' ', '(', ':', '-', '.', '/', ')', ';', '=', '?', '_'];
    const GREASE_VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let seed = chromium_major as usize;
    let grease_brand = format!(
        "Not{}A{}Brand",
        GREASE_CHARS[seed % 11],
        GREASE_CHARS[(seed + 1) % 11]
    );
    let grease_version = GREASE_VERSIONS[seed % 3];
    let grease_version = if kind == BrandListKind::Full {
        format!("{grease_version}.0.0.0")
    } else {
        grease_version.to_string()
    };
    let order = ORDERS[seed % 6];

    // Initial brand list: [GREASE, Chromium, Product]
    let items: [String; 3] = [
        format!("\"{grease_brand}\";v=\"{grease_version}\""),
        format!("\"Chromium\";v=\"{chromium_version}\""),
        format!("\"{brand}\";v=\"{brand_version}\""),
    ];

    // Shuffle: shuffled[order[i]] = items[i]
    let mut shuffled: [&str; 3] = [""; 3];
    for i in 0..3 {
        shuffled[order[i]] = &items[i];
    }

    format!("{}, {}, {}", shuffled[0], shuffled[1], shuffled[2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Chrome;

    /// Navigation headers and client hints of Chrome 155 on Windows, in wire order.
    #[test]
    fn chrome_155_headers_match_capture() {
        let profile = Chrome::version(155, Os::Windows).unwrap();
        let captured = [
            (
                "sec-ch-ua",
                "\"Google Chrome\";v=\"155\", \"Chromium\";v=\"155\", \"Not(A:Brand\";v=\"24\"",
            ),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", "\"Windows\""),
            ("upgrade-insecure-requests", "1"),
            (
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
            ),
            (
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
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
        assert_eq!(headers, captured);
        let hints = profile.ua_client_hints.unwrap();
        assert_eq!(
            hints.full_version_list,
            "\"Google Chrome\";v=\"155.0.8059.12\", \"Chromium\";v=\"155.0.8059.12\", \"Not(A:Brand\";v=\"24.0.0.0\""
        );
        // Chrome 154 did not list JPEG XL yet.
        let accept = |major| {
            Chrome::version(major, Os::Windows)
                .unwrap()
                .headers
                .into_iter()
                .find(|(k, _)| k == "accept")
                .unwrap()
                .1
        };
        assert!(!accept(154).contains("image/jxl"));
    }

    #[test]
    fn test_sec_ch_ua_chrome_145() {
        // As sent by a real Chrome 145.
        let result = chromium_sec_ch_ua(145, "Google Chrome", 145);
        assert_eq!(
            result,
            "\"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\""
        );
    }

    #[test]
    fn test_sec_ch_ua_chrome_131() {
        let result = chromium_sec_ch_ua(131, "Google Chrome", 131);
        assert_eq!(
            result,
            "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""
        );
    }

    #[test]
    fn test_sec_ch_ua_chrome_135() {
        let result = chromium_sec_ch_ua(135, "Google Chrome", 135);
        assert_eq!(
            result,
            "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\""
        );
    }

    #[test]
    fn test_sec_ch_ua_chrome_136() {
        let result = chromium_sec_ch_ua(136, "Google Chrome", 136);
        assert_eq!(
            result,
            "\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not.A/Brand\";v=\"99\""
        );
    }

    #[test]
    fn test_sec_ch_ua_edge_145() {
        let result = chromium_sec_ch_ua(145, "Microsoft Edge", 145);
        assert_eq!(
            result,
            "\"Not:A-Brand\";v=\"99\", \"Microsoft Edge\";v=\"145\", \"Chromium\";v=\"145\""
        );
    }

    #[test]
    fn test_sec_ch_ua_opera_127() {
        // Opera 127 uses Chromium 143.
        let result = chromium_sec_ch_ua(143, "Opera", 127);
        assert_eq!(
            result,
            "\"Opera\";v=\"127\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\""
        );
    }
}
