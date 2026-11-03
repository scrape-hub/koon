use crate::Error;
use crate::verify::Reference;
use crate::verify::references::{
    SAFARI_15_1, SAFARI_15_2, SAFARI_15_4, SAFARI_26, SAFARI_IOS16, SAFARI_IOS17,
    SAFARI_MACOS12_13, SAFARI_MACOS14, SAFARI_QUIC, SAFARI_QUIC_SHA1,
};

use super::{BrowserProfile, HeaderFamily, LanguageSource, Os, check_platform};

mod headers;
mod http2;
mod quic;
mod tls;

pub(crate) use headers::SafariLayout;
use headers::safari_headers;
use http2::safari_http2;
use quic::safari_quic;
use tls::safari_tls;

/// Safari browser profile factory.
///
/// Safari's fingerprint follows the OS network stack, not the Safari version, so each profile takes
/// the `Stack` generation of the OS release its version ships with. A release without its own
/// capture takes the nearest captured release's values ([`SafariVersion::captured`]).
pub struct Safari;

/// A Safari version supported by [`Safari`].
///
/// Both `tag` and `version` are accepted by the resolver, so `safari266` and `safari26.6` name the
/// same profile.
pub struct SafariVersion {
    /// Compact form without the dot, e.g. `"266"`.
    pub tag: &'static str,
    /// Dotted form, e.g. `"26.6"`; the iOS profile's `Version/…` User-Agent token.
    pub version: &'static str,
    /// The iOS profile of this version; `None` where no iOS profile exists.
    pub ios: Option<IosProfile>,
    macos_ua_version: &'static str,
    fetch_metadata: bool,
    macos: Release,
}

/// The iOS side of a [`SafariVersion`]: its User-Agent OS token and the release whose network
/// stack it reproduces, which must agree (one without the other cannot be built into a profile).
pub struct IosProfile {
    /// The OS version the iOS User-Agent reports (`CPU iPhone OS 18_7`). Up to iOS 18 it is the
    /// real one; iOS 26 froze it, at `18_6` for 26.0 and `18_7` from 26.1 on (`WebKit`'s
    /// `frozenVersion`).
    pub ua_os: &'static str,
    release: Release,
}

impl SafariVersion {
    /// The captured release whose fingerprint the profile of this version on `os` reproduces
    /// (`"macOS 26.6.2"`); `None` for a release without a capture of its own, which takes the
    /// values of the nearest captured one, and for an OS without a profile.
    pub fn captured(&self, os: Os) -> Option<&'static str> {
        self.release(os).and_then(|release| release.captured)
    }

    /// The captured release the QUIC transport parameters of the profile on `os` come from; `None`
    /// where they are those of another release (iOS 18.0 to 18.2 never sent QUIC in a capture) or
    /// the release has no capture.
    pub fn captured_quic(&self, os: Os) -> Option<&'static str> {
        self.release(os).and_then(|release| release.quic.captured)
    }

    pub(crate) fn references(&self, os: Os) -> Vec<&'static Reference> {
        let Some(release) = self.release(os) else {
            return Vec::new();
        };
        let mut references: Vec<&'static Reference> = release.reference.into_iter().collect();
        if release.quic_supported {
            references.extend(release.quic.reference);
        }
        references
    }

    fn release(&self, os: Os) -> Option<Release> {
        match os {
            Os::MacOS => Some(self.macos),
            Os::Ios => self.ios.as_ref().map(|ios| ios.release),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stack {
    Sonoma,
    Sequoia,
    Tahoe,
}

#[derive(Clone, Copy, Debug)]
struct Release {
    tls: Stack,
    http: Stack,
    connect_protocol: bool,
    zstd: bool,
    http2_enable_push: bool,
    quic: Quic,
    quic_supported: bool,
    captured: Option<&'static str>,
    reference: Option<&'static Reference>,
}

#[derive(Clone, Copy, Debug)]
struct Quic {
    streams_bidi: u64,
    streams_uni: u64,
    private_parameter: Option<u8>,
    idle_timeout_ms: u64,
    resumption: bool,
    alt_svc: bool,
    captured: Option<&'static str>,
    reference: Option<&'static Reference>,
}

const APPLE_PRIVATE_PARAMETER: u64 = 0xff08_0808;

const QUIC_SONOMA: Quic = Quic {
    streams_bidi: 0,
    streams_uni: 103,
    private_parameter: None,
    idle_timeout_ms: 0,
    resumption: false,
    alt_svc: true,
    captured: None,
    reference: None,
};
const QUIC_SEQUOIA: Quic = Quic {
    streams_bidi: 8,
    streams_uni: 8,
    ..QUIC_SONOMA
};
const QUIC_TAHOE: Quic = Quic {
    streams_bidi: 0,
    streams_uni: 8,
    resumption: true,
    ..QUIC_SONOMA
};

const MACOS_14: Release = Release {
    tls: Stack::Sonoma,
    http: Stack::Sonoma,
    connect_protocol: false,
    zstd: false,
    http2_enable_push: true,
    quic: Quic {
        captured: Some("macOS 14.6/14.7"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    quic_supported: true,
    captured: Some("macOS 14.6/14.7"),
    reference: Some(&SAFARI_MACOS14),
};
const MACOS_12: Release = Release {
    http2_enable_push: false,
    quic_supported: false,
    captured: Some("macOS 12.5/12.6"),
    reference: Some(&SAFARI_MACOS12_13),
    ..MACOS_14
};
const MACOS_13: Release = Release {
    http2_enable_push: false,
    quic: Quic {
        captured: Some("macOS 13.0"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    captured: Some("macOS 13.0"),
    reference: Some(&SAFARI_MACOS12_13),
    ..MACOS_14
};
const MACOS_13_6: Release = Release {
    captured: Some("macOS 13.6"),
    quic: Quic {
        captured: Some("macOS 13.6"),
        ..MACOS_13.quic
    },
    ..MACOS_13
};
const MACOS_15_0: Release = Release {
    quic: Quic {
        captured: Some("macOS 15.0"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    captured: Some("macOS 15.0"),
    ..MACOS_14
};
const MACOS_15_1: Release = Release {
    tls: Stack::Sonoma,
    http: Stack::Sequoia,
    connect_protocol: true,
    zstd: false,
    http2_enable_push: true,
    quic: Quic {
        alt_svc: false,
        captured: Some("macOS 15.1.1"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SEQUOIA
    },
    quic_supported: true,
    captured: Some("macOS 15.1.1"),
    reference: Some(&SAFARI_15_1),
};
const MACOS_15_2: Release = Release {
    tls: Stack::Sequoia,
    quic: Quic {
        alt_svc: false,
        captured: Some("macOS 15.2"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_SEQUOIA
    },
    captured: Some("macOS 15.2"),
    reference: Some(&SAFARI_15_2),
    ..MACOS_15_1
};
const MACOS_15_4: Release = Release {
    tls: Stack::Sequoia,
    http: Stack::Sequoia,
    connect_protocol: false,
    zstd: false,
    http2_enable_push: true,
    quic: Quic {
        private_parameter: Some(4),
        captured: Some("macOS 15.4"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_SEQUOIA
    },
    quic_supported: true,
    captured: Some("macOS 15.4"),
    reference: Some(&SAFARI_15_4),
};
const MACOS_15_5: Release = Release {
    quic: Quic {
        streams_bidi: 0,
        private_parameter: Some(4),
        captured: Some("macOS 15.5/15.6.1/15.8"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_SEQUOIA
    },
    captured: Some("macOS 15.5/15.6.1/15.8"),
    ..MACOS_15_4
};
const MACOS_26_1: Release = Release {
    tls: Stack::Tahoe,
    http: Stack::Tahoe,
    connect_protocol: false,
    zstd: false,
    http2_enable_push: true,
    quic: Quic {
        private_parameter: Some(7),
        captured: Some("macOS 26.1"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_TAHOE
    },
    quic_supported: true,
    captured: Some("macOS 26.1"),
    reference: Some(&SAFARI_26),
};
const MACOS_26_2: Release = Release {
    quic: Quic {
        captured: Some("macOS 26.2"),
        ..MACOS_26_1.quic
    },
    captured: Some("macOS 26.2"),
    ..MACOS_26_1
};
const MACOS_26_3: Release = Release {
    zstd: true,
    quic: Quic {
        captured: Some("macOS 26.3"),
        ..MACOS_26_1.quic
    },
    captured: Some("macOS 26.3"),
    ..MACOS_26_1
};
const MACOS_26_4: Release = Release {
    quic: Quic {
        captured: Some("macOS 26.4.1"),
        ..MACOS_26.quic
    },
    captured: Some("macOS 26.4.1"),
    ..MACOS_26
};
const MACOS_26_5: Release = Release {
    quic: Quic {
        captured: Some("macOS 26.5.1"),
        ..MACOS_26.quic
    },
    captured: Some("macOS 26.5.1"),
    ..MACOS_26
};
const MACOS_26: Release = Release {
    tls: Stack::Tahoe,
    http: Stack::Tahoe,
    connect_protocol: false,
    zstd: true,
    http2_enable_push: true,
    quic: Quic {
        captured: Some("macOS 26.6.2"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_TAHOE
    },
    quic_supported: true,
    captured: Some("macOS 26.6.2"),
    reference: Some(&SAFARI_26),
};
const MACOS_27: Release = Release {
    quic: Quic {
        idle_timeout_ms: 300_000,
        captured: Some("macOS 27.0"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_TAHOE
    },
    captured: Some("macOS 27.0"),
    ..MACOS_26
};
const IOS_16: Release = Release {
    http2_enable_push: false,
    captured: Some("iOS 16.0/16.1"),
    reference: Some(&SAFARI_IOS16),
    quic: Quic {
        captured: Some("iOS 16.0/16.1"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    ..MACOS_14
};
const IOS_16_4: Release = Release {
    captured: Some("iOS 16.4"),
    quic: Quic {
        captured: Some("iOS 16.4"),
        ..QUIC_SONOMA
    },
    ..IOS_16
};
const IOS_17: Release = Release {
    quic: Quic {
        captured: Some("iOS 17.0.1"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    captured: Some("iOS 17.0.1"),
    reference: Some(&SAFARI_IOS17),
    ..MACOS_14
};
const IOS_18_0: Release = Release {
    tls: Stack::Sonoma,
    http: Stack::Sequoia,
    connect_protocol: true,
    zstd: false,
    http2_enable_push: true,
    quic: Quic {
        alt_svc: false,
        ..QUIC_SEQUOIA
    },
    quic_supported: true,
    captured: Some("iOS 18.0"),
    reference: Some(&SAFARI_15_1),
};
const IOS_18_1: Release = Release {
    captured: Some("iOS 18.1"),
    ..IOS_18_0
};
const IOS_18_2: Release = Release {
    tls: Stack::Sequoia,
    captured: Some("iOS 18.2"),
    reference: Some(&SAFARI_15_2),
    ..IOS_18_0
};
const IOS_18_3: Release = Release {
    tls: Stack::Sequoia,
    quic: Quic {
        captured: Some("iOS 18.3.1"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_SEQUOIA
    },
    captured: Some("iOS 18.3.1"),
    reference: Some(&SAFARI_15_2),
    ..IOS_18_0
};
const MACOS_15_3: Release = Release {
    captured: Some("macOS 15.3"),
    quic: Quic {
        captured: Some("macOS 15.3"),
        ..IOS_18_3.quic
    },
    ..IOS_18_3
};
const IOS_18_4: Release = Release {
    tls: Stack::Sequoia,
    http: Stack::Sequoia,
    connect_protocol: false,
    zstd: false,
    http2_enable_push: true,
    quic: Quic {
        private_parameter: Some(6),
        captured: Some("iOS 18.4"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_SEQUOIA
    },
    quic_supported: true,
    captured: Some("iOS 18.4"),
    reference: Some(&SAFARI_15_4),
};
const IOS_18_5: Release = Release {
    quic: Quic {
        streams_bidi: 0,
        private_parameter: Some(6),
        captured: Some("iOS 18.5"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_SEQUOIA
    },
    captured: Some("iOS 18.5"),
    ..IOS_18_4
};
const MACOS_26_0: Release = Release {
    quic: Quic {
        captured: Some("macOS 26.0"),
        ..MACOS_26_1.quic
    },
    captured: Some("macOS 26.0"),
    ..MACOS_26_1
};
const IOS_26_0: Release = Release {
    quic: Quic {
        captured: Some("iOS 26.0"),
        ..MACOS_26_1.quic
    },
    captured: Some("iOS 26.0"),
    ..MACOS_26_1
};
const IOS_26_1: Release = Release {
    quic: Quic {
        captured: Some("iOS 26.1"),
        ..IOS_26_0.quic
    },
    captured: Some("iOS 26.1"),
    ..IOS_26_0
};
const IOS_26_2: Release = Release {
    quic: Quic {
        captured: Some("iOS 26.2"),
        ..IOS_26_0.quic
    },
    captured: Some("iOS 26.2"),
    ..IOS_26_0
};
const IOS_26_3: Release = Release {
    zstd: true,
    quic: Quic {
        captured: Some("iOS 26.3.1"),
        ..IOS_26_0.quic
    },
    captured: Some("iOS 26.3.1"),
    ..IOS_26_0
};
const IOS_26_4: Release = Release {
    quic: Quic {
        captured: Some("iOS 26.4.1"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_TAHOE
    },
    captured: Some("iOS 26.4.1"),
    ..MACOS_26
};
const IOS_26_5: Release = Release {
    quic: Quic {
        captured: Some("iOS 26.5"),
        reference: Some(&SAFARI_QUIC),
        ..QUIC_TAHOE
    },
    captured: Some("iOS 26.5"),
    ..MACOS_26
};
const IOS_27: Release = Release {
    quic: Quic {
        captured: Some("iOS 27.0"),
        ..MACOS_27.quic
    },
    captured: Some("iOS 27.0"),
    ..MACOS_27
};

const fn derived(nearest: Release) -> Release {
    Release {
        quic: Quic {
            captured: None,
            reference: None,
            ..nearest.quic
        },
        captured: None,
        reference: None,
        ..nearest
    }
}

#[rustfmt::skip]
mod versions;
pub use versions::SAFARI_VERSIONS;

impl Safari {
    /// Operating systems Safari profiles exist for (iOS only for the versions marked in
    /// [`SAFARI_VERSIONS`]).
    pub const PLATFORMS: &'static [Os] = &[Os::MacOS, Os::Ios];

    /// Safari `version` on `os`. The version is a tag (`"266"`) or dotted (`"26.6"`), see
    /// [`SAFARI_VERSIONS`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an unsupported version or OS.
    pub fn version(version: &str, os: Os) -> Result<BrowserProfile, Error> {
        check_platform("Safari", os, Self::PLATFORMS)?;
        let ios = os == Os::Ios;
        let entry = find_version(version)?;
        if ios && entry.ios.is_none() {
            return Err(Error::InvalidArgument(
                format!(
                    "Safari {} iOS is not available. Supported iOS: {}",
                    entry.version,
                    supported_list(true)
                ),
                None,
            ));
        }
        Ok(safari_profile(entry, ios))
    }

    /// Latest Safari on macOS.
    #[must_use]
    pub fn latest() -> BrowserProfile {
        safari_profile(LATEST, false)
    }
}

pub(super) const LATEST: &SafariVersion = &SAFARI_VERSIONS[SAFARI_VERSIONS.len() - 1];

pub(super) fn find_version(version: &str) -> Result<&'static SafariVersion, Error> {
    SAFARI_VERSIONS
        .iter()
        .find(|v| v.tag == version || v.version == version)
        .ok_or_else(|| {
            Error::InvalidArgument(
                format!(
                    "Unsupported Safari version: '{version}'. Supported: {}",
                    supported_list(false)
                ),
                None,
            )
        })
}

fn supported_list(ios_only: bool) -> String {
    SAFARI_VERSIONS
        .iter()
        .filter(|v| !ios_only || v.ios.is_some())
        .map(|v| v.version)
        .collect::<Vec<_>>()
        .join(", ")
}

fn safari_profile(entry: &SafariVersion, ios: bool) -> BrowserProfile {
    let (release, user_agent) = if ios {
        let profile = entry
            .ios
            .as_ref()
            .expect("iOS profile checked against the table");
        let user_agent = format!(
            "Mozilla/5.0 (iPhone; CPU iPhone OS {} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Mobile/15E148 Safari/604.1",
            profile.ua_os, entry.version
        );
        (profile.release, user_agent)
    } else {
        let user_agent = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Safari/605.1.15",
            entry.macos_ua_version
        );
        (entry.macos, user_agent)
    };
    BrowserProfile {
        farble_accept_language: false,
        multipart: Some(crate::BoundaryStyle::WebKit),
        language_source: Some(LanguageSource::Apple { ios }),
        header_family: Some(HeaderFamily::Safari),
        ua_client_hints: None,
        tls: safari_tls(release.tls),
        http2: safari_http2(release, ios),
        quic: release
            .quic_supported
            .then(|| safari_quic(release.quic, ios)),
        headers: safari_headers(entry.fetch_metadata, release, user_agent),
    }
}
