mod brave;
mod chrome;
mod edge;
mod firefox;
mod okhttp;
mod opera;
mod opera_mobile;
mod safari;
mod samsung;

pub use brave::Brave;
pub use chrome::Chrome;
pub use edge::Edge;
pub(crate) use firefox::FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION;
pub use firefox::Firefox;
pub use okhttp::OkHttp;
pub use opera::Opera;
pub use opera_mobile::OperaMobile;
pub use safari::{SAFARI_VERSIONS, Safari, SafariVersion};
pub(crate) use safari::{SafariLayout, Stack as SafariStack};
pub use samsung::Samsung;

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::http2::Http2Config;
use crate::quic::QuicConfig;
use crate::tls::TlsConfig;

/// A complete browser fingerprint profile: TLS, HTTP/2, HTTP/3 and header configuration for a
/// specific browser version on a specific OS.
///
/// Serializable to/from JSON, so a built-in profile ([`BrowserProfile::names`] lists every one) can
/// be exported, customized and reloaded. Loading JSON with a field the profile does not have fails,
/// naming the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserProfile {
    /// TLS fingerprint settings (JA3/JA4).
    pub tls: TlsConfig,

    /// HTTP/2 fingerprint settings (Akamai H2).
    pub http2: Http2Config,

    /// QUIC/HTTP/3 transport settings. When None, HTTP/3 is disabled for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<QuicConfig>,

    /// Headers of a top-level navigation. For the Chromium, Firefox, Safari and `OkHttp`
    /// [`header_family`](Self::header_family) the request builder places every header itself, so
    /// this list's order does not reach the wire; for other clients it does.
    pub headers: Vec<(String, String)>,

    /// The rules the request headers follow (see [`HeaderFamily`]). Every built-in profile names
    /// its family. Without one (custom profile JSON) a client detects it once, when it is built,
    /// with [`HeaderFamily::detect`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_family: Option<HeaderFamily>,

    /// The high-entropy User-Agent client hints of a Chromium profile, which it sends when a site
    /// asks for them. `None` sends only the low-entropy hints of [`headers`](Self::headers)
    /// (`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ua_client_hints: Option<UaClientHints>,

    /// Brave's Accept-Language fingerprinting protection (Shields): sends only the first language
    /// and its base language, with a q value drawn per client and site
    /// (`FarbleAcceptLanguageHeader`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub farble_accept_language: bool,
}

/// The high-entropy User-Agent client hints and device hints of a Chromium browser, sent only to
/// origins that ask for them (`Accept-CH`, Critical-CH, or an `ACCEPT_CH` ALPS frame). A request
/// header the caller sets overrides its hint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UaClientHints {
    /// `Sec-CH-UA-Full-Version`: the browser's own full version (`153.0.8010.53`).
    pub full_version: String,
    /// `Sec-CH-UA-Full-Version-List`, the header value: the brands of `sec-ch-ua`, in its order,
    /// with full versions.
    pub full_version_list: String,
    /// `Sec-CH-UA-Platform-Version`: the Windows `UniversalApiContract` version, the macOS or
    /// Android version, empty on Linux.
    pub platform_version: String,
    /// `Sec-CH-UA-Arch`: `x86` or `arm`; empty on Android.
    pub architecture: String,
    /// `Sec-CH-UA-Bitness`: `64`; empty on Android.
    pub bitness: String,
    /// `Sec-CH-UA-Model`: the device model on Android, else empty.
    pub model: String,
    /// `Sec-CH-UA-WoW64`: a 32-bit browser on 64-bit Windows.
    pub wow64: bool,
    /// `Sec-CH-UA-Form-Factors`: `Desktop` or `Mobile`.
    pub form_factors: Vec<String>,
    /// The device's memory in MiB (`Sec-CH-Device-Memory`, `Device-Memory`), rounded by Chromium to
    /// a power of two in GiB. 0 sends neither.
    #[serde(default)]
    pub device_memory_mib: u64,
    /// The device pixel ratio (`Sec-CH-DPR`, `DPR`). 0 sends neither.
    #[serde(default)]
    pub device_pixel_ratio: f32,
    /// The page's viewport in device pixels, width and height (`Sec-CH-Viewport-Width`,
    /// `Viewport-Width`, `Sec-CH-Viewport-Height`). A 0 sends no width or no height.
    #[serde(default)]
    pub viewport_px: (u32, u32),
    /// The hints the browser sends when an origin asks for them, as header names; `None`: every
    /// hint Chromium knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_hints: Option<Vec<String>>,
    /// The network quality the `RTT` and `Downlink` hints report; `None`: Chromium's defaults
    /// before a measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_quality: Option<NetworkQuality>,
}

/// The network quality a Chromium browser's `RTT` and `Downlink` hints report before its per-host
/// noise: HTTP RTT in milliseconds, downlink in kbit/s (capped at 10 Mbit/s); `u32::MAX` means no
/// estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkQuality {
    /// RTT and downlink of navigations.
    pub navigation: (u32, u32),
    /// RTT and downlink of subresources and `fetch()`.
    pub subresource: (u32, u32),
}

/// The rules a profile's requests are built by.
///
/// Decides which client's header order applies, whether the browser rules of the Fetch standard
/// (Origin, fetch metadata, secure contexts) apply, and the multipart boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HeaderFamily {
    /// Chrome, Edge, Opera: Chromium's header order for navigations, form submissions and
    /// `fetch()`, captured from Chrome.
    Chromium,
    /// Firefox's header order, captured from Firefox.
    Firefox,
    /// Safari's header order, captured from Safari on macOS and iOS; which one follows from the
    /// Safari version of the User-Agent.
    Safari,
    /// `OkHttp`: the application's headers, then `OkHttp`'s own; no browser rules.
    #[serde(rename = "okhttp")]
    OkHttp,
    /// Any other client: the profile's header list in wire order, no browser rules.
    Other,
}

impl HeaderFamily {
    /// The family of a profile, from its headers: a `sec-ch-ua` header makes it Chromium; otherwise
    /// the User-Agent decides (`Firefox/` -> Firefox, starting with `okhttp` -> `OkHttp`, `Safari/` ->
    /// Safari, anything else -> Other). Chromium's User-Agent contains `Safari/` too, so a Chromium
    /// profile without client hints needs an explicit [`BrowserProfile::header_family`].
    #[must_use]
    pub fn detect(profile: &BrowserProfile) -> Self {
        let header = |name: &str| {
            profile
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        let ua = header("user-agent").unwrap_or("");
        if header("sec-ch-ua").is_some() {
            Self::Chromium
        } else if ua.contains("Firefox/") {
            Self::Firefox
        } else if ua.starts_with("okhttp") {
            Self::OkHttp
        } else if ua.contains("Safari/") {
            Self::Safari
        } else {
            Self::Other
        }
    }
}

/// Operating system a browser profile impersonates. Profile names without an OS resolve to the
/// browser's [`Browser::default_os`] (Windows for Chrome, Firefox, Edge and Opera).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Os {
    /// Windows 10/11 (`windows`).
    Windows,
    /// macOS (`macos`).
    MacOS,
    /// Desktop Linux (`linux`).
    Linux,
    /// Android (`android`), the mobile profiles of Chrome, Firefox, Edge and Brave, Samsung
    /// Internet and `OkHttp`.
    Android,
    /// iOS (`ios`), the mobile profiles of Safari.
    Ios,
}

impl Os {
    /// Every OS, in the order profile names list them.
    pub const ALL: [Self; 5] = [
        Self::Windows,
        Self::MacOS,
        Self::Linux,
        Self::Android,
        Self::Ios,
    ];

    /// The name used in profile names (`chrome152-windows`) and accepted by [`FromStr`].
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOS => "macos",
            Self::Linux => "linux",
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Os {
    type Err = Error;

    /// Parse an OS name (`windows`, `macos`, `linux`, `android`, `ios`), ignoring case.
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|os| os.name().eq_ignore_ascii_case(s))
            .ok_or_else(|| {
                Error::InvalidArgument(
                    format!("Unknown OS: '{s}'. Supported: {}", os_names(&Self::ALL)),
                    None,
                )
            })
    }
}

/// Comma-separated OS names, for error messages.
fn os_names(platforms: &[Os]) -> String {
    platforms
        .iter()
        .map(|os| os.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Reject a major version outside the supported range of a browser.
fn check_version(browser: &str, major: u32, min: u32, latest: u32) -> Result<(), Error> {
    if (min..=latest).contains(&major) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(
            format!("Unsupported {browser} version: {major}. Supported: {min}-{latest}"),
            None,
        ))
    }
}

/// Reject an OS the browser has no profile for.
fn check_platform(browser: &str, os: Os, platforms: &[Os]) -> Result<(), Error> {
    if platforms.contains(&os) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(
            format!(
                "{browser} is not available on {os}. Supported: {}",
                os_names(platforms)
            ),
            None,
        ))
    }
}

/// A table's newest row, for `latest()` (the table is never empty).
fn last_row<T: Copy>(table: &[T]) -> T {
    *table.last().expect("at least one version")
}

/// The one lookup a gapped browser's `version()` and profile builder share, so a gap in the table
/// cannot both pass validation and panic building the profile (Opera, Opera Mobile, Brave, Samsung).
fn table_version<T: Copy>(
    browser: &str,
    major: u32,
    os: Os,
    platforms: &[Os],
    table: &[T],
    major_of: fn(T) -> u32,
) -> Result<T, Error> {
    let row = table
        .iter()
        .copied()
        .find(|&row| major_of(row) == major)
        .ok_or_else(|| {
            let majors: Vec<u32> = table.iter().copied().map(major_of).collect();
            Error::InvalidArgument(
                format!(
                    "Unsupported {browser} version: {major}. Supported: {}",
                    version_ranges(&majors)
                ),
                None,
            )
        })?;
    check_platform(browser, os, platforms)?;
    Ok(row)
}

/// Ascending majors as ranges (`"29-30, 32"`), for [`table_version`]'s error: a contiguous table
/// (every one, today) reads like the plain `"min-max"` it stands in for.
fn version_ranges(majors: &[u32]) -> String {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < majors.len() {
        let start = majors[i];
        while i + 1 < majors.len() && majors[i + 1] == majors[i] + 1 {
            i += 1;
        }
        ranges.push(if start == majors[i] {
            start.to_string()
        } else {
            format!("{start}-{}", majors[i])
        });
        i += 1;
    }
    ranges.join(", ")
}

/// A browser (or HTTP client) koon has profiles of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Browser {
    /// Google Chrome (`chrome`).
    Chrome,
    /// Mozilla Firefox (`firefox`).
    Firefox,
    /// Apple Safari (`safari`).
    Safari,
    /// Microsoft Edge (`edge`).
    Edge,
    /// Opera (`opera`).
    Opera,
    /// Opera for Android (`opera-mobile`), numbered apart from desktop Opera.
    OperaMobile,
    /// Brave (`brave`).
    Brave,
    /// Samsung Internet for Android (`samsung`).
    Samsung,
    /// `OkHttp`, the HTTP client of Android apps (`okhttp`).
    OkHttp,
}

impl Browser {
    /// Every browser, in the order [`BrowserProfile::names`] lists them.
    pub const ALL: [Self; 9] = [
        Self::Chrome,
        Self::Firefox,
        Self::Safari,
        Self::Edge,
        Self::Opera,
        Self::OperaMobile,
        Self::Brave,
        Self::Samsung,
        Self::OkHttp,
    ];

    /// The name profile names start with (`chrome`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Edge => "edge",
            Self::Opera => "opera",
            Self::OperaMobile => "opera-mobile",
            Self::Brave => "brave",
            Self::Samsung => "samsung",
            Self::OkHttp => "okhttp",
        }
    }

    /// The product name (`Chrome`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari",
            Self::Edge => "Edge",
            Self::Opera => "Opera",
            Self::OperaMobile => "Opera Mobile",
            Self::Brave => "Brave",
            Self::Samsung => "Samsung Internet",
            Self::OkHttp => "OkHttp",
        }
    }

    /// The operating systems it has profiles for.
    #[must_use]
    pub const fn platforms(self) -> &'static [Os] {
        match self {
            Self::Chrome => Chrome::PLATFORMS,
            Self::Firefox => Firefox::PLATFORMS,
            Self::Safari => Safari::PLATFORMS,
            Self::Edge => Edge::PLATFORMS,
            Self::Opera => Opera::PLATFORMS,
            Self::OperaMobile => OperaMobile::PLATFORMS,
            Self::Brave => Brave::PLATFORMS,
            Self::Samsung => Samsung::PLATFORMS,
            Self::OkHttp => OkHttp::PLATFORMS,
        }
    }

    /// The OS of its profile names without one, and of its `latest()` profile: [`DEFAULT_OS`],
    /// macOS for Safari, Android for Opera for Android, Samsung Internet and `OkHttp`.
    #[must_use]
    pub const fn default_os(self) -> Os {
        match self {
            Self::Safari => Os::MacOS,
            Self::OperaMobile | Self::Samsung | Self::OkHttp => Os::Android,
            Self::Chrome | Self::Firefox | Self::Edge | Self::Opera | Self::Brave => DEFAULT_OS,
        }
    }
}

impl fmt::Display for Browser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A built-in profile, as [`BrowserProfile::names`] lists it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileName {
    /// The name that resolves to exactly this profile: `chrome154-windows`, `safari266-ios`,
    /// `okhttp5`.
    pub name: String,
    pub browser: Browser,
    /// The version: the major version (`154`, `5` for `OkHttp`), for Safari the dotted one
    /// (`26.6`).
    pub version: String,
    /// The operating system (Android for `OkHttp`).
    pub os: Os,
}

/// Name prefixes accepted by [`BrowserProfile::resolve`], with the OS a mobile alias implies.
/// Mobile aliases precede the desktop prefix that would match them too.
const PREFIXES: &[(&str, Browser, Option<Os>)] = &[
    ("chrome-mobile", Browser::Chrome, Some(Os::Android)),
    ("chromemobile", Browser::Chrome, Some(Os::Android)),
    ("firefox-mobile", Browser::Firefox, Some(Os::Android)),
    ("firefoxmobile", Browser::Firefox, Some(Os::Android)),
    ("safari-mobile", Browser::Safari, Some(Os::Ios)),
    ("safarimobile", Browser::Safari, Some(Os::Ios)),
    ("edge-mobile", Browser::Edge, Some(Os::Android)),
    ("edgemobile", Browser::Edge, Some(Os::Android)),
    ("brave-mobile", Browser::Brave, Some(Os::Android)),
    ("bravemobile", Browser::Brave, Some(Os::Android)),
    ("opera-mobile", Browser::OperaMobile, None),
    ("operamobile", Browser::OperaMobile, None),
    ("chrome", Browser::Chrome, None),
    ("firefox", Browser::Firefox, None),
    ("safari", Browser::Safari, None),
    ("edge", Browser::Edge, None),
    ("opera", Browser::Opera, None),
    ("brave", Browser::Brave, None),
    ("samsung", Browser::Samsung, None),
    ("okhttp", Browser::OkHttp, None),
];

/// The browser names [`BrowserProfile::resolve`] accepts, for its error message.
fn prefix_names() -> String {
    PREFIXES
        .iter()
        .map(|(prefix, ..)| *prefix)
        .collect::<Vec<_>>()
        .join(", ")
}

/// OS of a Chrome, Firefox, Edge or Opera profile name without an OS suffix (`chrome`,
/// `firefox154`), and of their `latest()` profiles (see [`Browser::default_os`] for the other
/// browsers).
pub const DEFAULT_OS: Os = Os::Windows;

/// Split an optional OS suffix off the version part of a profile name: `152-windows`, `152windows`
/// (Node.js/Python style), `-ios` or `152`.
fn split_os(rest: &str) -> Result<(&str, Option<Os>), Error> {
    if let Some((version, os)) = rest.rsplit_once('-') {
        return Ok((version, Some(os.parse()?)));
    }
    Ok(Os::ALL
        .into_iter()
        .find_map(|os| Some((rest.strip_suffix(os.name())?, Some(os))))
        .unwrap_or((rest, None)))
}

/// Parse the major version of a profile name; an empty version means the latest one.
fn parse_major(browser: &str, version: &str, min: u32, latest: u32) -> Result<u32, Error> {
    if version.is_empty() {
        return Ok(latest);
    }
    version.parse().map_err(|e| {
        let message =
            format!("Invalid {browser} version: '{version}'. Expected a number ({min}-{latest})");
        Error::InvalidArgument(message, crate::error::boxed(e))
    })
}

/// A numbered profile's entry, named as [`BrowserProfile::names`] lists it.
fn numbered(
    browser: Browser,
    os: Os,
    major: u32,
    profile: BrowserProfile,
) -> (ProfileName, BrowserProfile) {
    let name = match browser {
        Browser::OkHttp => format!("{browser}{major}"),
        _ => format!("{browser}{major}-{os}"),
    };
    let entry = ProfileName {
        name,
        browser,
        version: major.to_string(),
        os,
    };
    (entry, profile)
}

/// How a browser's profiles are versioned, the one mapping [`BrowserProfile::resolve`] and
/// [`BrowserProfile::names`] share.
enum Scheme {
    /// One profile per major version and OS, built by `build(major, os)`; `majors` is ascending and
    /// never empty (the version constants and capture tables are).
    Numbered {
        majors: Vec<u32>,
        build: fn(u32, Os) -> Result<BrowserProfile, Error>,
    },
    /// The entries of [`SAFARI_VERSIONS`], per OS.
    Safari,
    /// One profile per major version, Android only, named without the OS.
    OkHttp,
}

impl Scheme {
    fn of(browser: Browser) -> Self {
        let range = |min, latest| (min..=latest).collect();
        let (majors, build): (Vec<u32>, fn(u32, Os) -> Result<BrowserProfile, Error>) =
            match browser {
                Browser::Chrome => (
                    range(Chrome::MIN_VERSION, Chrome::LATEST_VERSION),
                    Chrome::version,
                ),
                Browser::Firefox => (
                    range(Firefox::MIN_VERSION, Firefox::LATEST_VERSION),
                    Firefox::version,
                ),
                Browser::Edge => (
                    range(Edge::MIN_VERSION, Edge::LATEST_VERSION),
                    Edge::version,
                ),
                Browser::Opera => (
                    opera::OPERA_CHROMIUM.iter().map(|row| row.0).collect(),
                    Opera::version,
                ),
                Browser::OperaMobile => (
                    opera_mobile::OPERA_MOBILE_CHROMIUM
                        .iter()
                        .map(|row| row.0)
                        .collect(),
                    OperaMobile::version,
                ),
                Browser::Brave => (
                    brave::BRAVE_CHROMIUM.iter().map(|row| row.0).collect(),
                    Brave::version,
                ),
                Browser::Samsung => (
                    samsung::SAMSUNG_CHROMIUM.iter().map(|row| row.0).collect(),
                    Samsung::version,
                ),
                Browser::Safari => return Self::Safari,
                Browser::OkHttp => return Self::OkHttp,
            };
        Self::Numbered { majors, build }
    }
}

/// Every profile name of one browser, oldest version first (see [`BrowserProfile::names`]).
fn profile_names(browser: Browser) -> Vec<ProfileName> {
    match Scheme::of(browser) {
        Scheme::Numbered { majors, .. } => majors
            .into_iter()
            .flat_map(|major| {
                browser.platforms().iter().map(move |&os| ProfileName {
                    name: format!("{browser}{major}-{os}"),
                    browser,
                    version: major.to_string(),
                    os,
                })
            })
            .collect(),
        Scheme::Safari => SAFARI_VERSIONS
            .iter()
            .flat_map(|entry| {
                Safari::PLATFORMS
                    .iter()
                    .filter(move |&&os| os != Os::Ios || entry.ios.is_some())
                    .map(move |&os| ProfileName {
                        name: format!("safari{}-{os}", entry.tag),
                        browser,
                        version: entry.version.to_string(),
                        os,
                    })
            })
            .collect(),
        Scheme::OkHttp => (OkHttp::MIN_VERSION..=OkHttp::LATEST_VERSION)
            .map(|major| ProfileName {
                name: format!("okhttp{major}"),
                browser,
                version: major.to_string(),
                os: Os::Android,
            })
            .collect(),
    }
}

/// A pinned group of Chrome's `PqcBandwidthExperiment` server-padding field trial (see
/// [`BrowserProfile::pin_server_padding`]), instead of drawing one when the client is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPadding {
    /// Not in the trial, like 94 % of real Chrome installs.
    None,
    /// In the trial, asking servers to pad their `EncryptedExtensions` with this many bytes (one
    /// of 0, 6000, 9000, 12000, 14000, 16000).
    Bytes(u16),
}

impl FromStr for ServerPadding {
    type Err = Error;

    /// Accepts `"none"`, case-insensitive, or a number of bytes (0-65535).
    fn from_str(s: &str) -> Result<Self, Error> {
        if s.eq_ignore_ascii_case("none") {
            return Ok(Self::None);
        }
        s.parse::<u16>().map(Self::Bytes).map_err(|e| {
            let message = format!(
                "Invalid server padding: '{s}'. Must be 'none' or a number of bytes (0-65535)"
            );
            Error::InvalidArgument(message, crate::error::boxed(e))
        })
    }
}

impl BrowserProfile {
    /// Resolve a browser profile by name.
    ///
    /// Accepts formats like:
    /// - `"chrome"`, `"firefox"`, `"edge"`, `"opera"`: latest version, Windows
    ///   ([`DEFAULT_OS`]); `"safari"`: latest version, macOS
    /// - `"chrome152"`, `"firefox154"`: specific version, Windows
    /// - `"chrome152-windows"`, `"chrome152-macos"`, `"chrome152-linux"`: specific version + OS
    /// - `"chrome152windows"`, `"chrome152macos"`: the same without a dash (Node.js/Python)
    /// - `"chrome-mobile152"`, `"firefox-mobile154"`, `"safari-mobile26.6"`,
    ///   `"edge-mobile153"`, `"brave-mobile154"`: Android/iOS
    /// - `"brave154"`: Brave by the Chromium major it reports; `"samsung"`,
    ///   `"samsung30"`: Samsung Internet; `"opera-mobile102"`: Opera for Android (Android)
    /// - `"safari266"`, `"safari18.3"`: Safari version formats
    /// - `"okhttp"`, `"okhttp4"`, `"okhttp5"`, also with `-android`
    ///
    /// Case-insensitive. [`names`](Self::names) lists every profile.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for a version or OS the browser has no profile for.
    pub fn resolve(name: &str) -> Result<Self, Error> {
        Self::resolve_with_name(name).map(|(_, profile)| profile)
    }

    /// The entry of [`names`](Self::names) a name resolves to: `chrome` -> `chrome154-windows`,
    /// `safari-mobile26.6` -> `safari266-ios`, `okhttp4-android` -> `okhttp4`. Accepts what
    /// [`resolve`](Self::resolve) accepts.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve).
    pub fn resolve_name(name: &str) -> Result<ProfileName, Error> {
        Self::resolve_with_name(name).map(|(entry, _)| entry)
    }

    /// `json`, a serialized custom profile, if given, else `name` via [`resolve`](Self::resolve).
    /// A caller that reads `json` from a file (the CLI's `--profile FILE`) reads it itself and
    /// passes the file's content here; [`from_file`](Self::from_file) is the direct equivalent for
    /// that case.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve) if `json` is `None`; [`Error::Json`] if `json` is invalid.
    pub fn from_name_or_json(name: &str, json: Option<&str>) -> Result<Self, Error> {
        match json {
            Some(json) => Self::from_json(json).map_err(Error::Json),
            None => Self::resolve(name),
        }
    }

    /// The profile a name denotes and its entry of [`names`](Self::names).
    fn resolve_with_name(name: &str) -> Result<(ProfileName, Self), Error> {
        let lower = name.to_ascii_lowercase();
        let Some(&(prefix, browser, implied_os)) =
            PREFIXES.iter().find(|(p, ..)| lower.starts_with(p))
        else {
            return Err(Error::InvalidArgument(
                format!("Unknown browser: '{name}'. Supported: {}", prefix_names()),
                None,
            ));
        };
        let rest = &lower[prefix.len()..];
        let (version, os) = match (browser, implied_os) {
            // OkHttp is an Android client: its names take no other OS.
            (Browser::OkHttp, _) => {
                let (version, os) = split_os(rest)?;
                if let Some(os) = os {
                    check_platform("OkHttp", os, OkHttp::PLATFORMS)?;
                }
                (version, Os::Android)
            }
            (_, Some(os)) => (rest, os),
            (_, None) => {
                let (version, os) = split_os(rest)?;
                (version, os.unwrap_or_else(|| browser.default_os()))
            }
        };

        match Scheme::of(browser) {
            Scheme::Numbered { majors, build } => {
                let (min, latest) = (majors[0], majors[majors.len() - 1]);
                let major = parse_major(browser.label(), version, min, latest)?;
                Ok(numbered(browser, os, major, build(major, os)?))
            }
            Scheme::Safari => {
                let version = if version.is_empty() {
                    safari::LATEST.tag
                } else {
                    version
                };
                let profile = Safari::version(version, os)?;
                let entry = safari::find_version(version)?;
                let name = ProfileName {
                    name: format!("safari{}-{os}", entry.tag),
                    browser,
                    version: entry.version.to_string(),
                    os,
                };
                Ok((name, profile))
            }
            Scheme::OkHttp => {
                let major = parse_major(
                    "OkHttp",
                    version,
                    OkHttp::MIN_VERSION,
                    OkHttp::LATEST_VERSION,
                )?;
                Ok(numbered(browser, os, major, OkHttp::version(major)?))
            }
        }
    }

    /// Every built-in profile, each once: every browser version on every OS it has a profile for,
    /// grouped by browser and oldest first. Names without a version or an OS, and the mobile
    /// aliases (`chrome-mobile154`), resolve to profiles of this list.
    pub fn names() -> impl Iterator<Item = ProfileName> {
        Browser::ALL.into_iter().flat_map(profile_names)
    }

    /// The User-Agent header the profile sends, if it has one.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.as_str())
    }

    /// Pins the profile's server-padding field trial (Chrome's `PqcBandwidthExperiment`) to
    /// `padding`, over TCP and QUIC, instead of letting the client draw a group when it is built.
    /// Does nothing for a profile that does not run the trial (anything but Chrome, Edge and
    /// Opera on Chromium 151+).
    pub fn pin_server_padding(&mut self, padding: ServerPadding) {
        let padding = match padding {
            ServerPadding::None => None,
            ServerPadding::Bytes(bytes) => Some(bytes),
        };
        let pin = |tls: &mut TlsConfig| {
            if tls.server_padding_trial.take().is_some() {
                tls.server_padding = padding;
            }
        };
        pin(&mut self.tls);
        if let Some(tls) = self.quic.as_mut().and_then(|q| q.tls.as_mut()) {
            pin(tls);
        }
    }

    /// Deserialize a profile from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the profile to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load a profile from a JSON file. [`Error::Io`] if unreadable, [`Error::Json`] if invalid.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        let contents = std::fs::read_to_string(path).map_err(crate::Error::Io)?;
        serde_json::from_str(&contents).map_err(crate::Error::Json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_agent(profile: &BrowserProfile) -> &str {
        profile.user_agent().expect("profile has a user-agent")
    }

    fn err(name: &str) -> String {
        match BrowserProfile::resolve(name) {
            Ok(_) => panic!("{name} resolved"),
            Err(e) => {
                assert_eq!(e.code(), "INVALID_ARGUMENT", "{name}");
                e.to_string()
            }
        }
    }

    #[test]
    fn name_formats() {
        let ua = |name| user_agent(&BrowserProfile::resolve(name).unwrap()).to_string();
        assert!(ua("chrome").contains("Windows NT 10.0; Win64; x64"));
        assert!(ua("chrome").contains(&format!("Chrome/{}.", Chrome::LATEST_VERSION)));
        assert!(ua("chrome-macos").contains("Macintosh"));
        assert!(ua("firefox154macos").contains("Macintosh; Intel Mac OS X"));
        assert!(ua("chrome140-windows").contains("Windows NT 10.0; Win64; x64"));
        assert!(ua("Chrome140Windows").contains("Chrome/140."));
        assert!(ua("chrome-windows").contains("Windows NT"));
        assert!(ua("chrome-mobile150").contains("Android"));
        assert!(ua("chromemobile").contains("Mobile Safari"));
        assert!(ua("firefox150-linux").contains("X11; Linux x86_64; rv:150.0"));
        assert!(ua("firefox-mobile152").contains("Android 17; Mobile"));
        assert!(ua("safari18.3").contains("Version/18.3 Safari"));
        assert!(ua("safari183-ios").contains("iPhone OS 18_3"));
        assert!(ua("safari-mobile").contains("iPhone"));
        assert!(ua("edge151-windows").contains("Edg/151"));
        assert!(ua("opera136linux").contains("OPR/136"));
        assert!(ua("edge-mobile153").contains("Mobile Safari/537.36 EdgA/153.0.0.0"));
        assert!(ua("edge153-android").contains("EdgA/153"));
        assert!(ua("brave154-macos").contains("Macintosh"));
        assert!(ua("brave-mobile").contains("Android 10; K"));
        assert!(ua("samsung").contains("SamsungBrowser/30.0 Chrome/143.0.0.0 Mobile"));
        assert!(ua("samsung30-android").contains("SamsungBrowser/30.0"));
        assert!(ua("samsung29").contains("SamsungBrowser/29.0 Chrome/136.0.0.0"));
        assert!(ua("opera-mobile").contains("Mobile Safari/537.36 OPR/102.0.0.0"));
        assert!(ua("operamobile102-android").contains("Chrome/152.0.0.0"));
        assert!(ua("opera136").contains("OPR/136"));
        assert_eq!(ua("okhttp"), "okhttp/5.5.0");
        assert_eq!(ua("okhttp4"), "okhttp/4.12.0");
    }

    #[test]
    fn error_ranges_follow_the_version_constants() {
        let (min, max) = (Chrome::MIN_VERSION, Chrome::LATEST_VERSION);
        assert!(err("chromex").contains(&format!("({min}-{max})")));
        assert!(err("chrome999").contains(&format!("Supported: {min}-{max}")));
        let (min, max) = (Firefox::MIN_VERSION, Firefox::LATEST_VERSION);
        assert!(err("firefox-mobilex").contains(&format!("({min}-{max})")));
        let (min, max) = (Opera::MIN_VERSION, Opera::LATEST_VERSION);
        assert!(err("opera1").contains(&format!("Supported: {min}-{max}")));
    }

    #[test]
    fn unsupported_platforms_are_errors() {
        for name in [
            "chrome152-ios",
            "chrome152ios",
            "firefox154-ios",
            "edge151-linux",
            "opera134-ios",
            "opera134-android",
            "samsung30-windows",
            "opera-mobile102-windows",
            "safari26.6-windows",
            "safari-android",
        ] {
            assert!(err(name).contains("is not available on"), "{name}");
        }
        assert!(err("chrome152-beos").contains("Unknown OS: 'beos'"));
        assert!(err("okhttp5-windows").contains("OkHttp is not available on windows"));
        assert!(err("okhttpx").contains("Invalid OkHttp version"));
        let unknown = err("netscape4");
        assert!(unknown.contains("Unknown browser"));
        for (prefix, ..) in PREFIXES {
            assert!(unknown.contains(prefix), "{unknown}");
        }
    }

    #[test]
    fn okhttp_takes_android_as_its_os() {
        let ua = |name| user_agent(&BrowserProfile::resolve(name).unwrap()).to_string();
        assert_eq!(ua("okhttp-android"), "okhttp/5.5.0");
        assert_eq!(ua("okhttp4-android"), "okhttp/4.12.0");
        assert_eq!(ua("OkHttp4Android"), "okhttp/4.12.0");
    }

    /// Every listed name resolves, to a profile of its OS and version; no profile is listed twice.
    #[test]
    fn names_list_every_profile_once() {
        let names: Vec<ProfileName> = BrowserProfile::names().collect();
        let unique: std::collections::HashSet<&str> =
            names.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(unique.len(), names.len());
        for entry in &names {
            let profile = BrowserProfile::resolve(&entry.name)
                .unwrap_or_else(|e| panic!("{}: {e}", entry.name));
            let ua = user_agent(&profile);
            let os_marker = match entry.os {
                Os::Windows => "Windows",
                Os::MacOS => "Macintosh",
                Os::Linux => "Linux",
                Os::Android => "Android",
                Os::Ios => "iPhone",
            };
            if entry.browser != Browser::OkHttp {
                assert!(ua.contains(os_marker), "{}: {ua}", entry.name);
            }
            assert!(ua.contains(&entry.version), "{}: {ua}", entry.name);
        }
        for browser in Browser::ALL {
            assert!(names.iter().any(|p| p.browser == browser), "{browser}");
        }
    }

    /// Every listed name resolves to its own entry; aliases, bare names and both Safari spellings
    /// to the entry of their profile.
    #[test]
    fn names_resolve_to_their_entry() {
        for entry in BrowserProfile::names() {
            assert_eq!(BrowserProfile::resolve_name(&entry.name).unwrap(), entry);
        }
        let name = |alias: &str| BrowserProfile::resolve_name(alias).unwrap().name;
        assert_eq!(
            name("chrome"),
            format!("chrome{}-{DEFAULT_OS}", Chrome::LATEST_VERSION)
        );
        assert_eq!(name("Chrome140Windows"), "chrome140-windows");
        assert_eq!(
            name("chrome-mobile"),
            format!("chrome{}-android", Chrome::LATEST_VERSION)
        );
        assert_eq!(name("safari-mobile26.6"), "safari266-ios");
        assert_eq!(name("safari18.3"), "safari183-macos");
        assert_eq!(name("okhttp4-android"), "okhttp4");
        assert_eq!(
            name("edge-mobile"),
            format!("edge{}-android", Edge::LATEST_VERSION)
        );
        assert_eq!(
            name("brave-mobile"),
            format!("brave{}-android", Brave::LATEST_VERSION)
        );
        assert_eq!(
            name("samsung"),
            format!("samsung{}-android", Samsung::LATEST_VERSION)
        );
        assert_eq!(
            name("opera-mobile"),
            format!("opera-mobile{}-android", OperaMobile::LATEST_VERSION)
        );
        assert_eq!(name("opera136"), "opera136-windows");
        let safari = BrowserProfile::resolve_name("safari").unwrap();
        assert_eq!(safari.version, SAFARI_VERSIONS.last().unwrap().version);
        assert!(BrowserProfile::resolve_name("chrome999").is_err());
        assert!(BrowserProfile::resolve_name("safari-android").is_err());
    }

    #[test]
    fn from_name_or_json_uses_json_when_given() {
        let profile = BrowserProfile::resolve("chrome").unwrap();
        let json = profile.to_json_pretty().unwrap();
        // `name` is ignored once `json` is given.
        let resolved = BrowserProfile::from_name_or_json("firefox", Some(&json)).unwrap();
        assert_eq!(resolved.headers, profile.headers);
    }

    #[test]
    fn from_name_or_json_resolves_by_name_without_json() {
        let resolved = BrowserProfile::from_name_or_json("chrome", None).unwrap();
        assert_eq!(
            resolved.headers,
            BrowserProfile::resolve("chrome").unwrap().headers
        );
    }

    /// The README's profile count follows the profiles.
    #[test]
    fn readme_counts_every_profile() {
        let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));
        let count = readme
            .split(" profiles** total")
            .next()
            .and_then(|before| before.rsplit("**").next())
            .and_then(|n| n.trim().parse::<usize>().ok())
            .expect("README states the total as **N profiles** total");
        assert_eq!(count, BrowserProfile::names().count());
    }

    #[test]
    fn os_parses_case_insensitively() {
        assert_eq!("MacOS".parse::<Os>().unwrap(), Os::MacOS);
        for os in Os::ALL {
            assert_eq!(os.to_string().parse::<Os>().unwrap(), os);
        }
    }

    /// Names without an OS resolve to `DEFAULT_OS` (Windows); Safari's to macOS, OkHttp's to
    /// Android.
    #[test]
    fn bare_names_take_the_default_os() {
        assert_eq!(DEFAULT_OS, Os::Windows);
        for browser in ["chrome", "firefox154", "edge", "opera", "brave"] {
            let bare = BrowserProfile::resolve(browser).unwrap();
            let explicit =
                BrowserProfile::resolve(&format!("{browser}-{}", DEFAULT_OS.name())).unwrap();
            assert_eq!(bare.user_agent(), explicit.user_agent(), "{browser}");
        }
        for browser in Browser::ALL {
            let entry = BrowserProfile::resolve_name(browser.name()).unwrap();
            assert_eq!(entry.os, browser.default_os(), "{browser}");
        }
        assert_eq!(Browser::Safari.default_os(), Os::MacOS);
        assert_eq!(Browser::OkHttp.default_os(), Os::Android);
        assert_eq!(Browser::Samsung.default_os(), Os::Android);
        assert_eq!(Browser::OperaMobile.default_os(), Os::Android);
        let mut profile = Chrome::latest();
        profile.headers.retain(|(k, _)| k != "user-agent");
        assert_eq!(profile.user_agent(), None);
    }

    #[test]
    fn test_latest_is_the_profile_of_the_bare_name() {
        let pairs = [
            ("chrome", Chrome::latest()),
            ("firefox", Firefox::latest()),
            ("edge", Edge::latest()),
            ("opera", Opera::latest()),
            ("brave", Brave::latest()),
            ("samsung", Samsung::latest()),
            ("opera-mobile", OperaMobile::latest()),
            ("safari", Safari::latest()),
            ("okhttp", OkHttp::latest()),
        ];
        for (name, latest) in pairs {
            let resolved = BrowserProfile::resolve(name).unwrap();
            assert_eq!(
                resolved.to_json_pretty().unwrap(),
                latest.to_json_pretty().unwrap(),
                "{name}"
            );
        }
    }
}
