//! Chromium-family high-entropy client hints (Chrome, Edge, Opera and derived browsers).

use crate::profile::{Os, UaClientHints};

use super::headers::{BrandListKind, chromium_brand_list};

/// Full version of the last Stable release of each Chrome major, per platform (Windows, macOS,
/// Linux, Android), from Chromium Dash (`fetch_releases?channel=Stable`). Also the table
/// `Chrome::MIN_VERSION`/`LATEST_VERSION` are derived from, and `table_version` looks a version up
/// in.
pub(super) const CHROME_FULL_VERSIONS: &[(u32, [&str; 4])] = &[
    (
        131,
        [
            "131.0.6778.267",
            "131.0.6778.267",
            "131.0.6778.264",
            "131.0.6778.261",
        ],
    ),
    (
        132,
        [
            "132.0.6834.197",
            "132.0.6834.162",
            "132.0.6834.159",
            "132.0.6834.165",
        ],
    ),
    (
        133,
        [
            "133.0.6943.143",
            "133.0.6943.143",
            "133.0.6943.141",
            "133.0.6943.138",
        ],
    ),
    (
        134,
        [
            "134.0.6998.179",
            "134.0.6998.167",
            "134.0.6998.165",
            "134.0.6998.136",
        ],
    ),
    (
        135,
        [
            "135.0.7049.117",
            "135.0.7049.117",
            "135.0.7049.114",
            "135.0.7049.113",
        ],
    ),
    (
        136,
        [
            "136.0.7103.116",
            "136.0.7103.116",
            "136.0.7103.113",
            "136.0.7103.127",
        ],
    ),
    (
        137,
        [
            "137.0.7151.122",
            "137.0.7151.122",
            "137.0.7151.119",
            "137.0.7151.117",
        ],
    ),
    (
        138,
        [
            "138.0.7204.185",
            "138.0.7204.185",
            "138.0.7204.183",
            "138.0.7204.180",
        ],
    ),
    (
        139,
        [
            "139.0.7258.157",
            "139.0.7258.157",
            "139.0.7258.154",
            "139.0.7258.160",
        ],
    ),
    (
        140,
        [
            "140.0.7339.210",
            "140.0.7339.215",
            "140.0.7339.207",
            "140.0.7339.208",
        ],
    ),
    (
        141,
        [
            "141.0.7390.125",
            "141.0.7390.124",
            "141.0.7390.122",
            "141.0.7390.123",
        ],
    ),
    (
        142,
        [
            "142.0.7444.177",
            "142.0.7444.177",
            "142.0.7444.175",
            "142.0.7444.173",
        ],
    ),
    (
        143,
        [
            "143.0.7499.194",
            "143.0.7499.194",
            "143.0.7499.192",
            "143.0.7499.194",
        ],
    ),
    (
        144,
        [
            "144.0.7559.135",
            "144.0.7559.135",
            "144.0.7559.132",
            "144.0.7559.133",
        ],
    ),
    (
        145,
        [
            "145.0.7632.162",
            "145.0.7632.162",
            "145.0.7632.159",
            "145.0.7632.161",
        ],
    ),
    (
        146,
        [
            "146.0.7680.180",
            "146.0.7680.180",
            "146.0.7680.177",
            "146.0.7680.178",
        ],
    ),
    (
        147,
        [
            "147.0.7727.139",
            "147.0.7727.139",
            "147.0.7727.137",
            "147.0.7727.138",
        ],
    ),
    (
        148,
        [
            "148.0.7778.218",
            "148.0.7778.217",
            "148.0.7778.215",
            "148.0.7778.217",
        ],
    ),
    (
        149,
        [
            "149.0.7827.201",
            "149.0.7827.201",
            "149.0.7827.200",
            "149.0.7827.201",
        ],
    ),
    (
        150,
        [
            "150.0.7871.189",
            "150.0.7871.189",
            "150.0.7871.186",
            "150.0.7871.189",
        ],
    ),
    (
        151,
        [
            "151.0.7922.176",
            "151.0.7922.176",
            "151.0.7922.173",
            "151.0.7922.175",
        ],
    ),
    (
        152,
        [
            "152.0.7977.85",
            "152.0.7977.85",
            "152.0.7977.82",
            "152.0.7977.84",
        ],
    ),
    (
        153,
        [
            "153.0.8010.55",
            "153.0.8010.55",
            "153.0.8010.52",
            "153.0.8010.53",
        ],
    ),
    (
        154,
        [
            "154.0.8037.58",
            "154.0.8037.58",
            "154.0.8037.57",
            "154.0.8037.58",
        ],
    ),
    // No Linux Stable release of 155 yet: 155.0.8059.12 is the build of Windows and macOS Stable
    // and of Linux Beta.
    (
        155,
        [
            "155.0.8059.12",
            "155.0.8059.12",
            "155.0.8059.12",
            "155.0.8059.16",
        ],
    ),
];

/// `versions` (a [`CHROME_FULL_VERSIONS`] row) on `os`.
pub(super) fn full_version_for_os(versions: [&'static str; 4], os: Os) -> &'static str {
    let platform = match os {
        Os::Windows => 0,
        Os::MacOS => 1,
        Os::Linux => 2,
        Os::Android => 3,
        Os::Ios => unreachable!("no Chrome profile for iOS"),
    };
    versions[platform]
}

/// `Sec-CH-UA-Platform-Version` on Windows: the `UniversalApiContract` version, `19.0.0` from
/// Windows 11 24H2 on.
const WINDOWS_PLATFORM_VERSION: &str = "19.0.0";

/// On macOS the OS version (`major.minor.bugfix`): the last release of macOS 26.
const MACOS_PLATFORM_VERSION: &str = "26.7.0";

/// The Android device of the Chrome Mobile profiles: a Pixel 9 Pro XL on Android 17.
const ANDROID_PLATFORM_VERSION: &str = "17.0.0";
const ANDROID_MODEL: &str = "Pixel 9 Pro XL";

/// The device of a Chromium profile on an OS, for the device client hints: memory in MiB, device
/// pixel ratio and the page's viewport in device pixels (see [`UaClientHints`]).
#[derive(Clone, Copy)]
pub struct Device {
    memory_mib: u64,
    pixel_ratio: f32,
    viewport_px: (u32, u32),
}

impl Device {
    /// The same device with a browser's own viewport: its toolbar differs.
    pub const fn with_viewport(self, viewport_px: (u32, u32)) -> Self {
        Self {
            viewport_px,
            ..self
        }
    }
}

/// Windows: Chrome 154/155 in a default new window with a fresh profile.
pub const WINDOWS_DEVICE: Device = Device {
    memory_mib: 32 * 1024,
    pixel_ratio: 1.18,
    viewport_px: (1249, 1261),
};

/// macOS: Chrome 154, default new window; height assumed (capture display too narrow for the real
/// default window).
pub const MACOS_DEVICE: Device = Device {
    memory_mib: 16 * 1024,
    pixel_ratio: 1.0,
    viewport_px: (1024, 663),
};

/// Linux: Chrome 154 stable, default new window, under `WSLg`.
pub(super) const LINUX_DEVICE: Device = Device {
    memory_mib: 9944,
    pixel_ratio: 1.0,
    viewport_px: (1265, 1333),
};

/// Android: a Pixel 9 Pro XL (16 GB, which Chrome reports as 8); height hints follow
/// `css_viewport`'s rules rather than a direct capture.
pub const ANDROID_DEVICE: Device = Device {
    memory_mib: 16 * 1024,
    pixel_ratio: 2.25,
    viewport_px: (1008, 1915),
};

/// The high-entropy client hints of a Chromium-based browser on `os`
/// (`embedder_support::GetUserAgentMetadata`). `brand_full` is the browser's own full version,
/// `chromium_full` the one its Chromium brand carries. Architecture and bitness: x86-64 on Windows
/// and Linux, Apple Silicon on macOS (the User-Agent says Intel on every Mac), and empty on
/// Android, as Chromium reports them; the model only on Android.
pub fn chromium_ua_client_hints(
    os: Os,
    chromium_major: u32,
    brand: &str,
    brand_full: &str,
    chromium_full: &str,
) -> UaClientHints {
    chromium_ua_client_hints_on(ChromiumUaClientHints {
        os,
        chromium_major,
        brand,
        brand_full,
        chromium_full,
        device: None,
    })
}

/// Parameters for [`chromium_ua_client_hints_on`]: what varies between Chrome and its
/// Chromium-family siblings. A named struct instead of six positional parameters, three of them
/// (`brand_full`, `chromium_full`, and `brand`) `&str` with easily transposed meanings.
pub struct ChromiumUaClientHints<'a> {
    pub os: Os,
    pub chromium_major: u32,
    /// The product name ("Google Chrome", "Microsoft Edge", "Opera").
    pub brand: &'a str,
    /// The browser's own full version (`Sec-CH-UA-Full-Version`).
    pub brand_full: &'a str,
    /// The full version its Chromium brand carries.
    pub chromium_full: &'a str,
    /// Device hints of the browser's own, else Chrome's on `os`.
    pub device: Option<Device>,
}

/// [`chromium_ua_client_hints`] on a `device` of the browser's own, or of Chrome's on `os`.
pub fn chromium_ua_client_hints_on(params: ChromiumUaClientHints<'_>) -> UaClientHints {
    let ChromiumUaClientHints {
        os,
        chromium_major,
        brand,
        brand_full,
        chromium_full,
        device,
    } = params;
    let (platform_version, architecture, bitness, model, form_factor, chrome_device) = match os {
        Os::Windows => (
            WINDOWS_PLATFORM_VERSION,
            "x86",
            "64",
            "",
            "Desktop",
            WINDOWS_DEVICE,
        ),
        Os::MacOS => (
            MACOS_PLATFORM_VERSION,
            "arm",
            "64",
            "",
            "Desktop",
            MACOS_DEVICE,
        ),
        Os::Linux => ("", "x86", "64", "", "Desktop", LINUX_DEVICE),
        Os::Android => (
            ANDROID_PLATFORM_VERSION,
            "",
            "",
            ANDROID_MODEL,
            "Mobile",
            ANDROID_DEVICE,
        ),
        Os::Ios => unreachable!("no Chromium profile for iOS"),
    };
    let device = device.unwrap_or(chrome_device);
    UaClientHints {
        full_version: brand_full.to_string(),
        full_version_list: chromium_brand_list(
            chromium_major,
            brand,
            brand_full,
            chromium_full,
            BrandListKind::Full,
        ),
        platform_version: platform_version.to_string(),
        architecture: architecture.to_string(),
        bitness: bitness.to_string(),
        model: model.to_string(),
        wow64: false,
        form_factors: vec![form_factor.to_string()],
        device_memory_mib: device.memory_mib,
        device_pixel_ratio: device.pixel_ratio,
        viewport_px: device.viewport_px,
        sent_hints: None,
        network_quality: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Chrome;

    /// Matches a real Chrome 153.0.8010.53 capture on Windows.
    #[test]
    fn chrome_153_client_hints_match_capture() {
        let hints = chromium_ua_client_hints(
            Os::Windows,
            153,
            "Google Chrome",
            "153.0.8010.53",
            "153.0.8010.53",
        );
        assert_eq!(
            hints.full_version_list,
            "\"Google Chrome\";v=\"153.0.8010.53\", \"Not_A Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"153.0.8010.53\""
        );
        assert_eq!(hints.platform_version, "19.0.0");
        assert_eq!(
            (hints.architecture.as_str(), hints.bitness.as_str()),
            ("x86", "64")
        );
        assert_eq!(hints.model, "");
        assert!(!hints.wow64);
        assert_eq!(hints.form_factors, ["Desktop"]);
        let profile = Chrome::version(153, Os::Windows).unwrap();
        assert_eq!(
            profile.ua_client_hints.unwrap().full_version,
            "153.0.8010.55"
        );
    }

    #[test]
    fn full_versions_match_their_major() {
        for &(major, versions) in CHROME_FULL_VERSIONS {
            for &os in Chrome::PLATFORMS {
                let full = full_version_for_os(versions, os);
                assert!(full.starts_with(&format!("{major}.0.")), "{major} {os}");
            }
        }
    }
}
