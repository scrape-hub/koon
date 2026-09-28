use crate::Error;
#[cfg(test)]
use crate::http2::config::{HeaderCompression, HeadersPriority, SettingId};
#[cfg(test)]
use crate::quic::QuicStack;
#[cfg(test)]
use crate::tls::config::TlsVersion;
use crate::verify::{
    Reference, SAFARI_15_1, SAFARI_15_2, SAFARI_15_4, SAFARI_26, SAFARI_IOS_16, SAFARI_IOS_17,
    SAFARI_MACOS_12_13, SAFARI_MACOS_14, SAFARI_QUIC, SAFARI_QUIC_SHA1,
};

use super::{BrowserProfile, HeaderFamily, Os, check_platform};

mod headers;
mod http2;
mod quic;
mod tls;

pub(crate) use headers::SafariLayout;
use headers::safari_headers;
use http2::safari_http2;
#[cfg(test)]
use quic::IOS_QUERIES_HTTPS_RECORDS;
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
    /// The `Version/…` of the macOS User-Agent, with the patch level of the captured release
    /// (`26.6.2`; `26.0.1` as captured on macOS 15.7).
    macos_ua_version: &'static str,
    /// `WebKit` sends fetch metadata (`sec-fetch-*`) from Safari 16.4 on.
    fetch_metadata: bool,
    /// The network stack of the macOS release the version ships with.
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

    /// The captured references this version's profile on `os` matches: the TLS/HTTP2 one, and the
    /// QUIC one where its transport parameters were captured and it supports HTTP/3 at all. Empty
    /// for an OS without a profile or a release without a capture of its own.
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

/// A generation of Safari's network stack, named after the macOS release that brought it (the iOS
/// release of the same year has it too).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stack {
    /// macOS 14 Sonoma and iOS 17, the older releases, and macOS 15.0.
    Sonoma,
    /// macOS 15 Sequoia from 15.1 on and iOS 18.
    Sequoia,
    /// macOS 26 Tahoe and iOS 26, and macOS 27 and iOS 27.
    Tahoe,
}

/// What the network stack of one OS release sends.
#[derive(Clone, Copy, Debug)]
struct Release {
    /// The TLS `ClientHello`.
    tls: Stack,
    /// The HTTP/2 layer and the request headers.
    http: Stack,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` = 1 (macOS 15.1 and 15.2, iOS 18.0 to 18.3).
    connect_protocol: bool,
    /// `zstd` in Accept-Encoding.
    zstd: bool,
    /// Sends `SETTINGS_ENABLE_PUSH` (value 0); from macOS 14 and iOS 17 on. macOS 12 and 13 send
    /// no such setting at all.
    http2_enable_push: bool,
    /// Apple's QUIC stack.
    quic: Quic,
    /// Supports HTTP/3 at all; macOS 12 never sent a single QUIC packet or DNS HTTPS query in any
    /// capture (macOS 13 does, with the transport parameters of [`QUIC_SONOMA`]).
    quic_supported: bool,
    /// The captured release the values come from; `None` when they are those of the nearest
    /// captured one.
    captured: Option<&'static str>,
    /// The TLS/HTTP2 fingerprint reference this release matches, next to `captured`: `Some` exactly
    /// where `captured` is (`verify::references_for` reads this instead of a separately maintained
    /// range table).
    reference: Option<&'static Reference>,
}

/// What Apple's QUIC stack of one OS release sends besides what every release sends (see
/// [`safari_quic`]).
#[derive(Clone, Copy, Debug)]
struct Quic {
    /// `initial_max_streams_bidi`; 0 sends none.
    streams_bidi: u64,
    /// `initial_max_streams_uni`.
    streams_uni: u64,
    /// The value (one byte) of the private transport parameter [`APPLE_PRIVATE_PARAMETER`], sent
    /// after the others.
    private_parameter: Option<u8>,
    /// `max_idle_timeout`, milliseconds; 0 sends none.
    idle_timeout_ms: u64,
    /// Offers the TLS session of an earlier connection, and 0-RTT.
    resumption: bool,
    /// Switches to HTTP/3 when a server advertises it with Alt-Svc.
    alt_svc: bool,
    /// The captured release the transport parameters come from; `None` when they are those of
    /// another release.
    captured: Option<&'static str>,
    /// The QUIC fingerprint reference this release matches, next to `captured`: `Some` exactly
    /// where `captured` is.
    reference: Option<&'static Reference>,
}

/// Safari's private transport parameter (macOS 15.4 to 26.3, iOS 18.4 to 26.3.1).
const APPLE_PRIVATE_PARAMETER: u64 = 0xff08_0808;

/// macOS 14 and iOS 17 (captured on macOS 14.7, iOS 17.0.1 and 17.5).
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
/// macOS 15 and iOS 18 up to 15.4 and 18.4.
const QUIC_SEQUOIA: Quic = Quic {
    streams_bidi: 8,
    streams_uni: 8,
    ..QUIC_SONOMA
};
/// macOS 26 and iOS 26 from 26.4 on.
const QUIC_TAHOE: Quic = Quic {
    streams_bidi: 0,
    streams_uni: 8,
    resumption: true,
    ..QUIC_SONOMA
};

/// macOS 14 Sonoma: also what 14.6 sends (Safari 17.6, the last Safari 17), confirmed identical
/// in every layer checked — TLS/QUIC JA4, HTTP/2 SETTINGS and WINDOW_UPDATE, QUIC transport
/// parameters, and request headers over HTTP/2, HTTP/3 and WebSocket.
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
    reference: Some(&SAFARI_MACOS_14),
};
/// macOS 12 Monterey: the TLS and HTTP/2 layer of macOS 14 (same JA4, same HEADERS layout), but
/// without `SETTINGS_ENABLE_PUSH` and without HTTP/3 at all — no QUIC packet and no DNS HTTPS
/// query in any phase of a capture (`H`, `R`'s racing test, both HTTPS-record and Alt-Svc routes).
/// Confirmed on 12.6 too (Safari 15.6.1, the version that ships on that image before the 16.0
/// update): same TLS/QUIC/SETTINGS as 12.5, zero QUIC packets again.
const MACOS_12: Release = Release {
    http2_enable_push: false,
    quic_supported: false,
    captured: Some("macOS 12.5/12.6"),
    reference: Some(&SAFARI_MACOS_12_13),
    ..MACOS_14
};
/// macOS 13 Ventura: the TLS and HTTP/2 layer of macOS 14 without `SETTINGS_ENABLE_PUSH` (like
/// macOS 12), but with HTTP/3: the QUIC transport parameters and JA4 of [`QUIC_SONOMA`], reached
/// through the DNS HTTPS record and Alt-Svc alike.
const MACOS_13: Release = Release {
    http2_enable_push: false,
    quic: Quic {
        captured: Some("macOS 13.0"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    captured: Some("macOS 13.0"),
    reference: Some(&SAFARI_MACOS_12_13),
    ..MACOS_14
};
/// macOS 13.6: captured to send exactly the stack of macOS 13.0 (TLS with `ecdsa_sha1`, no
/// `SETTINGS_ENABLE_PUSH`, the QUIC transport parameters and JA4 of [`QUIC_SONOMA`]). Only the
/// header layer differs from the macOS 13.0/Safari 16.1 profile: Safari 16.4 added fetch metadata
/// (`sec-fetch-*`), which this capture (Safari 16.6) already sends — a `WebKit` version change, not
/// a network-stack one.
const MACOS_13_6: Release = Release {
    captured: Some("macOS 13.6"),
    quic: Quic {
        captured: Some("macOS 13.6"),
        ..MACOS_13.quic
    },
    ..MACOS_13
};
/// macOS 15.0 still sends the stack of macOS 14 in every layer: TLS, HTTP/2, request headers, QUIC
/// (103 unidirectional streams, Alt-Svc followed) and HTTP/3; the macOS 15 layout starts with 15.1.
const MACOS_15_0: Release = Release {
    quic: Quic {
        captured: Some("macOS 15.0"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    captured: Some("macOS 15.0"),
    ..MACOS_14
};
/// The TLS of macOS 14, the HTTP/2 layer of macOS 15; HTTP/3 only through HTTPS records.
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
/// Also what macOS 15.6.1, 15.7, 15.7.9 and 15.8 send: same TLS JA4, HTTP/2 SETTINGS (no
/// `ENABLE_CONNECT_PROTOCOL`), QUIC transport parameters (private parameter `4`) and
/// `accept-encoding` (no zstd) as the 15.5 capture — 15.8 confirmed with stock Safari 18.6 (a
/// pure OS point update, no Safari version change), request headers included (navigation,
/// fetch/subresource, CORS/preflight, plain http, WebSocket).
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
/// iOS 16.0 and 16.1: captured to send exactly the TLS and QUIC of iOS 17.0.1 (same JA4, same
/// transport parameter values), but no `SETTINGS_ENABLE_PUSH` — like macOS 12 and 13,
/// `http2_enable_push` is macOS 14/iOS 17 on, not from iOS 16.x on despite the shared Sonoma stack.
const IOS_16: Release = Release {
    http2_enable_push: false,
    captured: Some("iOS 16.0/16.1"),
    reference: Some(&SAFARI_IOS_16),
    quic: Quic {
        captured: Some("iOS 16.0/16.1"),
        reference: Some(&SAFARI_QUIC_SHA1),
        ..QUIC_SONOMA
    },
    ..MACOS_14
};
/// iOS 16.4: `IOS_16` with fetch metadata (its `SafariVersion` sets `fetch_metadata: true`, like
/// macOS 13.6) — every other layer (TLS, QUIC, the header hash order fetch metadata picks) matches
/// the iOS 17.0.1 capture exactly, `SETTINGS_ENABLE_PUSH` still absent. Its own captured release,
/// standing in for 16.5 and 16.6 (`derived`; their simulators are no longer downloadable — Apple's
/// network stack does not change within a patch release, but this is not itself verified).
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
    reference: Some(&SAFARI_IOS_17),
    ..MACOS_14
};
/// The TLS of iOS 17, the HTTP/2 layer of iOS 18. iOS 18.0 to 18.2 sent no QUIC in any capture
/// (they ignore Alt-Svc, and the simulators asked for no HTTPS record): the transport parameters
/// are those of iOS 18.3.1.
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
/// macOS 15.3: captured to send exactly the stack of iOS 18.3 (TLS, HTTP/2 SETTINGS and header
/// order, and QUIC transport parameters all matched the iOS 18.3.1 capture).
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
/// macOS 26.0: captured to send exactly the stack of macOS 26.1 (TLS, HTTP/2 SETTINGS and header
/// order, and QUIC transport parameters, including the private parameter `7`, all matched).
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

/// A release without a capture, with the values of the same release on the other OS where that was
/// captured, otherwise of the nearest captured release on the same OS (the earlier one when two are
/// as near).
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

/// Every supported Safari version, oldest first.
///
/// Single source of truth for the resolver, its error messages and the CLI's profile listing.
/// Safari 17.0 on macOS takes the capture of macOS 14.7 (the same TLS and HTTP/2 as macOS 14.8.9);
/// iOS 17.0.1 and 17.5 show that stack unchanged within 17.
pub const SAFARI_VERSIONS: &[SafariVersion] = &[
    // macOS 12 Monterey; no iOS profile.
    SafariVersion {
        tag: "156",
        version: "15.6",
        ios: None,
        macos_ua_version: "15.6",
        fetch_metadata: false,
        macos: MACOS_12,
    },
    // Safari 16.0 shipped as an update for macOS 12.6 Monterey (Ventura came with 16.1), iOS 16.0.
    // Captured directly: the real Safari16.0MontereyAuto.pkg (Apple code signature verified,
    // chaining to Apple Root CA) installed on the macOS 12.6 capture VM sends the same TLS/HTTP-2
    // layer and header order as the Safari 15.6.1 that ships on that image (`MACOS_12`, not
    // `derived`).
    SafariVersion {
        tag: "160",
        version: "16.0",
        ios: Some(IosProfile {
            ua_os: "16_0",
            release: IOS_16,
        }),
        macos_ua_version: "16.0",
        fetch_metadata: false,
        macos: MACOS_12,
    },
    // macOS 13 Ventura, iOS 16.1.
    SafariVersion {
        tag: "161",
        version: "16.1",
        ios: Some(IosProfile {
            ua_os: "16_1",
            release: IOS_16,
        }),
        macos_ua_version: "16.1",
        fetch_metadata: false,
        macos: MACOS_13,
    },
    // Safari 16.6 shipped as an update for macOS 13.6 Ventura; no iOS capture yet (16.5/16.6
    // simulators are no longer downloadable), so its profile takes the values of the nearest
    // captured iOS release (iOS 16.4).
    SafariVersion {
        tag: "166",
        version: "16.6",
        ios: Some(IosProfile {
            ua_os: "16_6",
            release: derived(IOS_16_4),
        }),
        macos_ua_version: "16.6",
        fetch_metadata: true,
        macos: MACOS_13_6,
    },
    // macOS 14 Sonoma, iOS 17.
    SafariVersion {
        tag: "170",
        version: "17.0",
        ios: Some(IosProfile {
            ua_os: "17_0",
            release: IOS_17,
        }),
        macos_ua_version: "17.0",
        fetch_metadata: true,
        macos: MACOS_14,
    },
    // Safari 17.6, the last Safari 17: captured on macOS 14.6, sending exactly the stack of
    // macOS 14.7. No iOS 17.6 capture; iOS 17.0.1 and 17.5 already showed the stack unchanged
    // within 17.
    SafariVersion {
        tag: "176",
        version: "17.6",
        ios: Some(IosProfile {
            ua_os: "17_6",
            release: derived(IOS_17),
        }),
        macos_ua_version: "17.6",
        fetch_metadata: true,
        macos: MACOS_14,
    },
    // macOS 15 Sequoia, iOS 18.
    SafariVersion {
        tag: "180",
        version: "18.0",
        ios: Some(IosProfile {
            ua_os: "18_0",
            release: IOS_18_0,
        }),
        macos_ua_version: "18.0",
        fetch_metadata: true,
        macos: MACOS_15_0,
    },
    SafariVersion {
        tag: "181",
        version: "18.1",
        ios: Some(IosProfile {
            ua_os: "18_1",
            release: IOS_18_1,
        }),
        macos_ua_version: "18.1.1",
        fetch_metadata: true,
        macos: MACOS_15_1,
    },
    SafariVersion {
        tag: "182",
        version: "18.2",
        ios: Some(IosProfile {
            ua_os: "18_2",
            release: IOS_18_2,
        }),
        macos_ua_version: "18.2",
        fetch_metadata: true,
        macos: MACOS_15_2,
    },
    SafariVersion {
        tag: "183",
        version: "18.3",
        ios: Some(IosProfile {
            ua_os: "18_3",
            release: IOS_18_3,
        }),
        macos_ua_version: "18.3",
        fetch_metadata: true,
        macos: MACOS_15_3,
    },
    SafariVersion {
        tag: "184",
        version: "18.4",
        ios: Some(IosProfile {
            ua_os: "18_4",
            release: IOS_18_4,
        }),
        macos_ua_version: "18.4",
        fetch_metadata: true,
        macos: MACOS_15_4,
    },
    SafariVersion {
        tag: "185",
        version: "18.5",
        ios: Some(IosProfile {
            ua_os: "18_5",
            release: IOS_18_5,
        }),
        macos_ua_version: "18.5",
        fetch_metadata: true,
        macos: MACOS_15_5,
    },
    // Safari 18.6, the long-lived last Safari 18: captured on macOS 15.6.1, sending exactly the
    // stack of 18.5 (same JA4, HTTP/2 SETTINGS and QUIC transport parameters). No iOS capture yet.
    SafariVersion {
        tag: "186",
        version: "18.6",
        ios: Some(IosProfile {
            ua_os: "18_6",
            release: derived(IOS_18_5),
        }),
        macos_ua_version: "18.6",
        fetch_metadata: true,
        macos: MACOS_15_5,
    },
    // macOS 26 Tahoe, iOS 26.
    SafariVersion {
        tag: "260",
        version: "26.0",
        ios: Some(IosProfile {
            ua_os: "18_6",
            release: IOS_26_0,
        }),
        macos_ua_version: "26.0",
        fetch_metadata: true,
        macos: MACOS_26_0,
    },
    SafariVersion {
        tag: "261",
        version: "26.1",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: IOS_26_1,
        }),
        macos_ua_version: "26.1",
        fetch_metadata: true,
        macos: MACOS_26_1,
    },
    SafariVersion {
        tag: "262",
        version: "26.2",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: IOS_26_2,
        }),
        macos_ua_version: "26.2",
        fetch_metadata: true,
        macos: MACOS_26_2,
    },
    SafariVersion {
        tag: "263",
        version: "26.3",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: IOS_26_3,
        }),
        macos_ua_version: "26.3",
        fetch_metadata: true,
        macos: MACOS_26_3,
    },
    SafariVersion {
        tag: "264",
        version: "26.4",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: IOS_26_4,
        }),
        macos_ua_version: "26.4",
        fetch_metadata: true,
        macos: MACOS_26_4,
    },
    SafariVersion {
        tag: "265",
        version: "26.5",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: IOS_26_5,
        }),
        macos_ua_version: "26.5",
        fetch_metadata: true,
        macos: MACOS_26_5,
    },
    SafariVersion {
        tag: "266",
        version: "26.6",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: derived(MACOS_26),
        }),
        macos_ua_version: "26.6.2",
        fetch_metadata: true,
        macos: MACOS_26,
    },
    // macOS 27, iOS 27.
    SafariVersion {
        tag: "270",
        version: "27.0",
        ios: Some(IosProfile {
            ua_os: "18_7",
            release: IOS_27,
        }),
        macos_ua_version: "27.0",
        fetch_metadata: true,
        macos: MACOS_27,
    },
];

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

/// The newest entry of [`SAFARI_VERSIONS`].
pub(super) const LATEST: &SafariVersion = &SAFARI_VERSIONS[SAFARI_VERSIONS.len() - 1];

/// The entry of a Safari version, by tag (`266`) or dotted version (`26.6`).
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

/// Comma-separated list of supported versions, for error messages. With `ios_only`, lists just the
/// versions that have an iOS profile.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn user_agent(profile: &BrowserProfile) -> &str {
        profile
            .headers
            .iter()
            .find(|(k, _)| k == "user-agent")
            .map(|(_, v)| v.as_str())
            .expect("profile has a user-agent")
    }

    /// Every version in the table resolves under both spellings, on iOS exactly when the table says
    /// an iOS profile exists.
    #[test]
    fn every_table_entry_resolves() {
        for entry in SAFARI_VERSIONS {
            assert!(entry.macos_ua_version.starts_with(entry.version));
            for spelling in [entry.tag, entry.version] {
                let profile = Safari::version(spelling, Os::MacOS)
                    .unwrap_or_else(|e| panic!("macOS {spelling}: {e}"));
                let ua = user_agent(&profile);
                assert!(
                    ua.contains(&format!("Version/{} ", entry.macos_ua_version)),
                    "macOS {spelling} carries the wrong version: {ua}"
                );

                match Safari::version(spelling, Os::Ios) {
                    Ok(profile) => {
                        let os_version = entry
                            .ios
                            .as_ref()
                            .unwrap_or_else(|| panic!("iOS {spelling} should not exist"))
                            .ua_os;
                        let ua = user_agent(&profile);
                        assert!(
                            ua.contains(&format!("iPhone OS {os_version} "))
                                && ua.contains(&format!("Version/{} ", entry.version)),
                            "iOS {spelling} carries the wrong version: {ua}"
                        );
                        assert_eq!(profile.http2.initial_window_size, 2_097_152);
                    }
                    Err(e) => assert!(entry.ios.is_none(), "iOS {spelling}: {e}"),
                }
            }
        }
    }

    /// Up to iOS 18 the User-Agent reports the real iOS version; iOS 26 froze it, at 18_6 in 26.0
    /// and 18_7 from 26.1 on. macOS reports the patch level of the captured release.
    #[test]
    fn user_agents_report_the_captured_versions() {
        let ua = |version, os| user_agent(&Safari::version(version, os).unwrap()).to_string();
        assert_eq!(
            ua("26.0", Os::Ios),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
        );
        assert!(ua("26.1", Os::Ios).contains("CPU iPhone OS 18_7 like Mac OS X"));
        assert_eq!(
            ua("27.0", Os::Ios),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1"
        );
        assert!(ua("18.3", Os::Ios).contains("CPU iPhone OS 18_3 like Mac OS X"));
        assert_eq!(
            ua("18.4", Os::Ios),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1"
        );
        assert_eq!(
            ua("26.6", Os::MacOS),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15"
        );
        assert_eq!(
            ua("18.1", Os::MacOS),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15"
        );
        assert!(ua("27.0", Os::MacOS).contains("Version/27.0 Safari/605.1.15"));
        assert!(ua("26.0", Os::MacOS).contains("Version/26.0 Safari/605.1.15"));
        assert!(ua("26.4", Os::MacOS).contains("Version/26.4 Safari/605.1.15"));
        for entry in SAFARI_VERSIONS {
            if let Some(ios) = &entry.ios {
                assert!(
                    !ios.ua_os.starts_with("26"),
                    "{}: {}",
                    entry.version,
                    ios.ua_os
                );
            }
        }
    }

    /// The unversioned `safari` / `safari-mobile` names track the newest entry in the table.
    #[test]
    fn latest_is_the_last_table_entry() {
        let newest = SAFARI_VERSIONS.last().expect("table is not empty");
        for name in ["safari", "safari-mobile"] {
            let profile = BrowserProfile::resolve(name).unwrap();
            let ua = user_agent(&profile);
            assert!(
                ua.contains(&format!("Version/{}", newest.version)),
                "{name} is not {}: {ua}",
                newest.version
            );
        }
        assert_eq!(
            user_agent(&Safari::latest()),
            user_agent(&BrowserProfile::resolve("safari").unwrap())
        );
    }

    /// The request builder's layout, taken from the User-Agent, is the one of the release the
    /// profile reproduces.
    #[test]
    fn layout_follows_the_release() {
        for entry in SAFARI_VERSIONS {
            let ios_release = entry.ios.as_ref().map(|ios| ios.release);
            for (os, release) in [(Os::MacOS, Some(entry.macos)), (Os::Ios, ios_release)] {
                let Some(release) = release else { continue };
                let profile = Safari::version(entry.tag, os).unwrap();
                assert_eq!(
                    SafariLayout::of(&profile),
                    SafariLayout {
                        stack: release.http,
                        ios: os == Os::Ios,
                        fetch_metadata: entry.fetch_metadata
                    },
                    "{} {os}",
                    entry.version
                );
            }
        }
    }

    #[test]
    fn captured_releases() {
        let entry = |version: &str| {
            SAFARI_VERSIONS
                .iter()
                .find(|v| v.version == version)
                .unwrap()
        };
        let captured = |version: &str, os| entry(version).captured(os);
        for (version, os, release) in [
            ("15.6", Os::MacOS, "macOS 12.5/12.6"),
            ("16.0", Os::MacOS, "macOS 12.5/12.6"),
            ("16.1", Os::MacOS, "macOS 13.0"),
            ("16.6", Os::MacOS, "macOS 13.6"),
            ("17.0", Os::MacOS, "macOS 14.6/14.7"),
            ("17.6", Os::MacOS, "macOS 14.6/14.7"),
            ("18.0", Os::MacOS, "macOS 15.0"),
            ("18.1", Os::MacOS, "macOS 15.1.1"),
            ("18.2", Os::MacOS, "macOS 15.2"),
            ("18.3", Os::MacOS, "macOS 15.3"),
            ("18.4", Os::MacOS, "macOS 15.4"),
            ("18.5", Os::MacOS, "macOS 15.5/15.6.1/15.8"),
            ("18.6", Os::MacOS, "macOS 15.5/15.6.1/15.8"),
            ("26.0", Os::MacOS, "macOS 26.0"),
            ("26.1", Os::MacOS, "macOS 26.1"),
            ("26.2", Os::MacOS, "macOS 26.2"),
            ("26.3", Os::MacOS, "macOS 26.3"),
            ("26.5", Os::MacOS, "macOS 26.5.1"),
            ("26.6", Os::MacOS, "macOS 26.6.2"),
            ("16.0", Os::Ios, "iOS 16.0/16.1"),
            ("16.1", Os::Ios, "iOS 16.0/16.1"),
            ("17.0", Os::Ios, "iOS 17.0.1"),
            ("18.0", Os::Ios, "iOS 18.0"),
            ("18.3", Os::Ios, "iOS 18.3.1"),
            ("26.0", Os::Ios, "iOS 26.0"),
            ("26.1", Os::Ios, "iOS 26.1"),
            ("26.3", Os::Ios, "iOS 26.3.1"),
            ("26.4", Os::Ios, "iOS 26.4.1"),
            ("27.0", Os::Ios, "iOS 27.0"),
        ] {
            assert_eq!(captured(version, os), Some(release), "{version} {os}");
        }
        for (version, os) in [
            ("15.6", Os::Ios),
            ("16.6", Os::Ios),
            ("17.6", Os::Ios),
            ("18.6", Os::Ios),
            ("26.6", Os::Ios),
            ("26.6", Os::Windows),
        ] {
            assert_eq!(captured(version, os), None, "{version} {os}");
        }
        // iOS 18.0 to 18.2 never sent QUIC: their transport parameters are those of iOS 18.3.1.
        for version in ["18.0", "18.1", "18.2"] {
            assert_eq!(entry(version).captured_quic(Os::Ios), None, "{version}");
        }
        assert_eq!(entry("18.3").captured_quic(Os::Ios), Some("iOS 18.3.1"));
        assert_eq!(entry("18.3").captured_quic(Os::MacOS), Some("macOS 15.3"));
        assert_eq!(entry("26.0").captured_quic(Os::MacOS), Some("macOS 26.0"));
        assert_eq!(entry("16.6").captured_quic(Os::MacOS), Some("macOS 13.6"));
        assert_eq!(
            entry("17.6").captured_quic(Os::MacOS),
            Some("macOS 14.6/14.7")
        );
        assert_eq!(entry("17.6").captured_quic(Os::Ios), None);
        assert_eq!(entry("16.0").captured_quic(Os::Ios), Some("iOS 16.0/16.1"));
        assert_eq!(entry("16.1").captured_quic(Os::Ios), Some("iOS 16.0/16.1"));
        assert_eq!(entry("16.6").captured_quic(Os::Ios), None);
        assert_eq!(
            entry("18.6").captured_quic(Os::MacOS),
            Some("macOS 15.5/15.6.1/15.8")
        );
        assert_eq!(entry("18.6").captured_quic(Os::Ios), None);
        assert_eq!(entry("18.1").captured_quic(Os::MacOS), Some("macOS 15.1.1"));
        assert_eq!(entry("18.0").captured_quic(Os::MacOS), Some("macOS 15.0"));
    }

    #[test]
    fn tls_per_stack() {
        let tls = |version, os| Safari::version(version, os).unwrap().tls;
        let sonoma = tls("17.0", Os::MacOS);
        assert!(sonoma.sigalgs.contains("ecdsa_sha1"));
        assert_eq!(sonoma.min_version, TlsVersion::Tls10);
        assert!(!sonoma.curves.contains("MLKEM"));
        // macOS 15.0 and 15.1 and iOS 18.0 and 18.1 still had the TLS of macOS 14.
        for (version, os) in [
            ("18.0", Os::Ios),
            ("18.1", Os::Ios),
            ("18.1", Os::MacOS),
            ("18.0", Os::MacOS),
            ("16.6", Os::MacOS),
        ] {
            assert_eq!(tls(version, os), sonoma, "{version} {os}");
        }
        let sequoia = tls("18.2", Os::MacOS);
        assert!(!sequoia.sigalgs.contains("ecdsa_sha1"));
        assert_eq!(sequoia.min_version, TlsVersion::Tls10);
        for (version, os) in [
            ("18.2", Os::Ios),
            ("18.3", Os::Ios),
            ("18.5", Os::MacOS),
            ("18.5", Os::Ios),
        ] {
            assert_eq!(tls(version, os), sequoia, "{version} {os}");
        }
        let tahoe = tls("27.0", Os::MacOS);
        assert!(tahoe.cipher_list.starts_with("TLS_AES_256_GCM_SHA384:"));
        assert!(tahoe.curves.starts_with("X25519MLKEM768:"));
        assert_eq!(tahoe.min_version, TlsVersion::Tls12);
        assert_eq!(tls("26.0", Os::Ios), tahoe);
        assert_eq!(tls("26.2", Os::MacOS), tahoe);
    }

    #[test]
    fn http2_and_headers_per_stack() {
        let profile = |version, os| Safari::version(version, os).unwrap();
        let names = |p: &BrowserProfile| -> Vec<String> {
            p.headers.iter().map(|(k, _)| k.clone()).collect()
        };
        let value = |p: &BrowserProfile, name: &str| {
            p.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };

        let old = profile("16.0", Os::MacOS);
        assert_eq!(
            names(&old),
            ["user-agent", "accept", "accept-language", "accept-encoding"]
        );
        let sonoma = profile("17.0", Os::MacOS);
        assert_eq!(sonoma.http2.initial_window_size, 4_194_304);
        assert_eq!(
            profile("17.0", Os::Ios).http2.initial_window_size,
            2_097_152
        );
        assert_eq!(sonoma.http2.initial_conn_window_size - 65535, 10_485_760);
        assert_eq!(
            sonoma.http2.headers_priority,
            Some(HeadersPriority::SafariSonoma)
        );
        assert!(!names(&sonoma).contains(&"priority".to_string()));
        // macOS 15.0 still has the HTTP/2 layer and headers of macOS 14.
        let macos_15_0 = profile("18.0", Os::MacOS);
        assert_eq!(
            format!("{:?}", macos_15_0.http2),
            format!("{:?}", sonoma.http2)
        );
        assert_eq!(names(&macos_15_0), names(&sonoma));
        assert_eq!(
            SafariLayout::of(&macos_15_0),
            SafariLayout {
                stack: Stack::Sonoma,
                ios: false,
                fetch_metadata: true
            }
        );
        assert_eq!(
            SafariLayout::of(&profile("18.0", Os::Ios)).stack,
            Stack::Sequoia
        );

        let sequoia = profile("18.5", Os::MacOS);
        assert_eq!(sequoia.http2.initial_conn_window_size - 65535, 10420225);
        assert_eq!(
            sequoia.http2.headers_priority,
            Some(HeadersPriority::SafariSequoia)
        );
        assert_eq!(value(&sequoia, "priority").as_deref(), Some("u=0, i"));
        // macOS 15.1 and 15.2 and iOS 18.0 to 18.3 enabled the CONNECT protocol, before NO_RFC7540;
        // macOS 15.4 and iOS 18.4 no longer.
        for (version, os, connect) in [
            ("18.0", Os::Ios, true),
            ("18.1", Os::MacOS, true),
            ("18.1", Os::Ios, true),
            ("18.2", Os::MacOS, true),
            ("18.3", Os::Ios, true),
            ("18.4", Os::MacOS, false),
            ("18.4", Os::Ios, false),
            ("18.5", Os::Ios, false),
        ] {
            let http2 = profile(version, os).http2;
            assert_eq!(
                http2.enable_connect_protocol,
                connect.then_some(true),
                "{version} {os}"
            );
            let tail: &[SettingId] = if connect {
                &[
                    SettingId::EnableConnectProtocol,
                    SettingId::NoRfc7540Priorities,
                ]
            } else {
                &[SettingId::NoRfc7540Priorities]
            };
            assert_eq!(http2.settings_order[3..], *tail, "{version} {os}");
        }

        let tahoe = profile("27.0", Os::MacOS);
        assert_eq!(tahoe.http2.enable_connect_protocol, None);
        assert_eq!(tahoe.http2.headers_priority, None);
        assert_eq!(
            tahoe.http2.header_compression,
            Some(HeaderCompression::Safari)
        );
        assert_eq!(
            value(&tahoe, "accept-encoding").as_deref(),
            Some("gzip, deflate, br, zstd")
        );
        // zstd from 26.3 on.
        for (version, os, zstd) in [
            ("18.5", Os::MacOS, false),
            ("26.1", Os::MacOS, false),
            ("26.2", Os::Ios, false),
            ("26.2", Os::MacOS, false),
            ("26.3", Os::Ios, true),
            ("26.3", Os::MacOS, true),
            ("26.4", Os::Ios, true),
            ("26.5", Os::MacOS, true),
            ("26.6", Os::Ios, true),
        ] {
            let encoding = value(&profile(version, os), "accept-encoding").unwrap();
            assert_eq!(encoding.ends_with("zstd"), zstd, "{version} {os}");
        }
    }

    /// macOS 12 has no HTTP/3; macOS 13 has.
    #[test]
    fn http3_from_macos_13() {
        for (version, http3) in [("15.6", false), ("16.0", false), ("16.1", true)] {
            let profile = Safari::version(version, Os::MacOS).unwrap();
            assert_eq!(profile.quic.is_some(), http3, "{version}");
        }
    }

    /// `SETTINGS_ENABLE_PUSH` is macOS 14/iOS 17 on, not from iOS 16.x despite sharing the Sonoma
    /// TLS/HTTP-2 layer with macOS 12/13 (captured on the iOS 16.0 and 16.1 simulators).
    #[test]
    fn no_enable_push_before_macos_14_or_ios_17() {
        for (version, os) in [
            ("16.0", Os::Ios),
            ("16.1", Os::Ios),
            ("16.6", Os::Ios),
            ("15.6", Os::MacOS),
            ("16.0", Os::MacOS),
            ("16.1", Os::MacOS),
            ("16.6", Os::MacOS),
        ] {
            let profile = Safari::version(version, os).unwrap();
            assert_eq!(profile.http2.enable_push, None, "{version} {os}");
        }
        for (version, os) in [
            ("17.0", Os::MacOS),
            ("17.0", Os::Ios),
            ("17.6", Os::MacOS),
            ("17.6", Os::Ios),
        ] {
            let profile = Safari::version(version, os).unwrap();
            assert_eq!(profile.http2.enable_push, Some(false), "{version} {os}");
        }
    }

    /// Apple's QUIC stack per release: stream limits, the private transport parameter, session
    /// resumption and whether Alt-Svc leads to HTTP/3.
    #[test]
    fn quic_per_release() {
        for (version, os, bidi, uni, private, resumption, alt_svc) in [
            ("16.1", Os::MacOS, 0, 103, None, false, true),
            ("16.6", Os::MacOS, 0, 103, None, false, true),
            ("16.0", Os::Ios, 0, 103, None, false, true),
            ("16.1", Os::Ios, 0, 103, None, false, true),
            ("16.6", Os::Ios, 0, 103, None, false, true),
            ("17.0", Os::MacOS, 0, 103, None, false, true),
            ("17.6", Os::MacOS, 0, 103, None, false, true),
            ("17.0", Os::Ios, 0, 103, None, false, true),
            ("18.0", Os::MacOS, 0, 103, None, false, true),
            ("18.0", Os::Ios, 8, 8, None, false, false),
            ("18.1", Os::MacOS, 8, 8, None, false, false),
            ("18.2", Os::MacOS, 8, 8, None, false, false),
            ("18.2", Os::Ios, 8, 8, None, false, false),
            ("18.3", Os::MacOS, 8, 8, None, false, true),
            ("18.3", Os::Ios, 8, 8, None, false, true),
            ("18.4", Os::MacOS, 8, 8, Some(4), false, true),
            ("18.4", Os::Ios, 8, 8, Some(6), false, true),
            ("18.5", Os::MacOS, 0, 8, Some(4), false, true),
            ("18.5", Os::Ios, 0, 8, Some(6), false, true),
            ("18.6", Os::MacOS, 0, 8, Some(4), false, true),
            ("26.0", Os::Ios, 0, 8, Some(7), true, true),
            ("26.1", Os::MacOS, 0, 8, Some(7), true, true),
            ("26.3", Os::MacOS, 0, 8, Some(7), true, true),
            ("26.3", Os::Ios, 0, 8, Some(7), true, true),
            ("26.4", Os::MacOS, 0, 8, None, true, true),
            ("26.4", Os::Ios, 0, 8, None, true, true),
            ("26.6", Os::Ios, 0, 8, None, true, true),
        ] {
            let quic = Safari::version(version, os).unwrap().quic.unwrap();
            assert_eq!(quic.stack, QuicStack::Apple);
            assert_eq!(
                (quic.initial_max_streams_bidi, quic.initial_max_streams_uni),
                (bidi, uni),
                "{version} {os}"
            );
            let expected: Vec<(u64, Vec<u8>)> = private
                .map(|value| (APPLE_PRIVATE_PARAMETER, vec![value]))
                .into_iter()
                .collect();
            assert_eq!(quic.extra_transport_parameters, expected, "{version} {os}");
            assert_eq!(quic.session_resumption, resumption, "{version} {os}");
            assert_eq!(quic.alt_svc, alt_svc, "{version} {os}");
            assert_eq!(quic.max_idle_timeout_ms, 0, "{version} {os}");
        }
        for os in [Os::MacOS, Os::Ios] {
            let quic = Safari::version("27.0", os).unwrap().quic.unwrap();
            assert_eq!(quic.max_idle_timeout_ms, 300_000);
        }
    }

    /// Every macOS profile with HTTP/3 at all queries HTTPS DNS records (macOS 12 has no QUIC
    /// support whatsoever, so the question does not apply to it); iOS follows
    /// [`IOS_QUERIES_HTTPS_RECORDS`].
    /// macOS 15.1 and 15.2 have this on although `alt_svc` is off: they reach HTTP/3 only through
    /// it.
    #[test]
    fn https_rr_follows_the_os() {
        for entry in SAFARI_VERSIONS {
            let Some(macos) = Safari::version(entry.tag, Os::MacOS).unwrap().quic else {
                continue;
            };
            assert!(macos.https_rr, "macOS {}", entry.version);
            if entry.ios.is_some() {
                let ios = Safari::version(entry.tag, Os::Ios).unwrap().quic.unwrap();
                assert_eq!(
                    ios.https_rr, IOS_QUERIES_HTTPS_RECORDS,
                    "iOS {}",
                    entry.version
                );
            }
        }
        for version in ["18.1", "18.2"] {
            let quic = Safari::version(version, Os::MacOS).unwrap().quic.unwrap();
            assert!(!quic.alt_svc);
            assert!(quic.https_rr);
        }
    }
}
