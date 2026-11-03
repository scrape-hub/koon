//! Chromium-family high-entropy client hints (Chrome, Edge, Opera and derived browsers).

use crate::profile::{Os, UaClientHints};

use super::headers::{BrandListKind, chromium_brand_list};

pub(super) use crate::profile::releases::CHROME_FULL_VERSIONS;

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
