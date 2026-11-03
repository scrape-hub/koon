use crate::profile::{Os, UaClientHints};

use super::headers::{BrandListKind, chromium_brand_list};

pub(super) use crate::profile::releases::CHROME_FULL_VERSIONS;

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

const WINDOWS_PLATFORM_VERSION: &str = "19.0.0";

const MACOS_PLATFORM_VERSION: &str = "26.7.0";

const ANDROID_PLATFORM_VERSION: &str = "17.0.0";
const ANDROID_MODEL: &str = "Pixel 9 Pro XL";

#[derive(Clone, Copy)]
pub struct Device {
    memory_mib: u64,
    pixel_ratio: f32,
    viewport_px: (u32, u32),
}

impl Device {
    pub const fn with_viewport(self, viewport_px: (u32, u32)) -> Self {
        Self {
            viewport_px,
            ..self
        }
    }
}

pub const WINDOWS_DEVICE: Device = Device {
    memory_mib: 32 * 1024,
    pixel_ratio: 1.18,
    viewport_px: (1249, 1261),
};

pub const MACOS_DEVICE: Device = Device {
    memory_mib: 16 * 1024,
    pixel_ratio: 1.0,
    viewport_px: (1024, 663),
};

pub(super) const LINUX_DEVICE: Device = Device {
    memory_mib: 9944,
    pixel_ratio: 1.0,
    viewport_px: (1265, 1333),
};

pub const ANDROID_DEVICE: Device = Device {
    memory_mib: 16 * 1024,
    pixel_ratio: 2.25,
    viewport_px: (1008, 1915),
};

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

pub struct ChromiumUaClientHints<'a> {
    pub os: Os,
    pub chromium_major: u32,
    pub brand: &'a str,
    pub brand_full: &'a str,
    pub chromium_full: &'a str,
    pub device: Option<Device>,
}

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
