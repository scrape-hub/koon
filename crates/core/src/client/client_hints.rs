//! User-Agent, device and network client hints, as Chromium sends them.
//!
//! `sec-ch-ua`, `sec-ch-ua-mobile` and `sec-ch-ua-platform` go with every request to a secure
//! origin. The rest go out only once an origin asks: via a persisted `Accept-CH` response header,
//! or an ALPS `ACCEPT_CH` frame (restarts the connection's next navigation with the hints added),
//! with `Critical-CH` retrying a request that's still missing one. Firefox and Safari send none.
//! koon leaves out `Save-Data` and the resource width hints; a caller can set either itself.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use http::Uri;
use lru::LruCache;

use crate::profile::{BrowserProfile, UaClientHints};

/// Most origins whose client hints are remembered; the least recently used is evicted to make room
/// for a new one. A browser bounds this by how many sites a human visits in one profile's lifetime;
/// a long-running scraper has no such natural bound (mirrors the proxy CA leaf cache's reasoning,
/// `proxy::ca::MAX_CACHED_HOSTS`).
const MAX_CLIENT_HINT_ORIGINS: usize = 10_000;

/// A client hint koon can send. The declaration order is the order in which Chromium adds them to a
/// navigation (`AddRequestClientHintsHeaders`). The `…Legacy` hints are the names without
/// `sec-ch-`, which an origin asks for separately.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum Hint {
    DeviceMemoryLegacy,
    DeviceMemory,
    DprLegacy,
    Dpr,
    ViewportWidthLegacy,
    ViewportWidth,
    ViewportHeight,
    Rtt,
    Downlink,
    Ect,
    Ua,
    UaMobile,
    UaFullVersion,
    UaArch,
    UaPlatform,
    UaPlatformVersion,
    UaModel,
    UaBitness,
    UaWoW64,
    UaFullVersionList,
    UaFormFactors,
    PrefersColorScheme,
    PrefersReducedMotion,
    PrefersReducedTransparency,
}

impl Hint {
    /// Every hint, in Chromium's order.
    const ALL: [Self; 24] = [
        Self::DeviceMemoryLegacy,
        Self::DeviceMemory,
        Self::DprLegacy,
        Self::Dpr,
        Self::ViewportWidthLegacy,
        Self::ViewportWidth,
        Self::ViewportHeight,
        Self::Rtt,
        Self::Downlink,
        Self::Ect,
        Self::Ua,
        Self::UaMobile,
        Self::UaFullVersion,
        Self::UaArch,
        Self::UaPlatform,
        Self::UaPlatformVersion,
        Self::UaModel,
        Self::UaBitness,
        Self::UaWoW64,
        Self::UaFullVersionList,
        Self::UaFormFactors,
        Self::PrefersColorScheme,
        Self::PrefersReducedMotion,
        Self::PrefersReducedTransparency,
    ];

    /// The request header (`network::GetClientHintToNameMap`).
    pub const fn header(self) -> &'static str {
        match self {
            Self::DeviceMemoryLegacy => "device-memory",
            Self::DeviceMemory => "sec-ch-device-memory",
            Self::DprLegacy => "dpr",
            Self::Dpr => "sec-ch-dpr",
            Self::ViewportWidthLegacy => "viewport-width",
            Self::ViewportWidth => "sec-ch-viewport-width",
            Self::ViewportHeight => "sec-ch-viewport-height",
            Self::Rtt => "rtt",
            Self::Downlink => "downlink",
            Self::Ect => "ect",
            Self::Ua => "sec-ch-ua",
            Self::UaMobile => "sec-ch-ua-mobile",
            Self::UaFullVersion => "sec-ch-ua-full-version",
            Self::UaArch => "sec-ch-ua-arch",
            Self::UaPlatform => "sec-ch-ua-platform",
            Self::UaPlatformVersion => "sec-ch-ua-platform-version",
            Self::UaModel => "sec-ch-ua-model",
            Self::UaBitness => "sec-ch-ua-bitness",
            Self::UaWoW64 => "sec-ch-ua-wow64",
            Self::UaFullVersionList => "sec-ch-ua-full-version-list",
            Self::UaFormFactors => "sec-ch-ua-form-factors",
            Self::PrefersColorScheme => "sec-ch-prefers-color-scheme",
            Self::PrefersReducedMotion => "sec-ch-prefers-reduced-motion",
            Self::PrefersReducedTransparency => "sec-ch-prefers-reduced-transparency",
        }
    }

    /// Sent with every request, asked for or not (`blink::IsClientHintSentByDefault`).
    pub const fn by_default(self) -> bool {
        matches!(self, Self::Ua | Self::UaMobile | Self::UaPlatform)
    }

    /// Every hint in the order Blink sets them on a subresource or `fetch()` request; decides where
    /// colliding names land in the header map.
    pub const BLINK_ORDER: [Self; 24] = [
        Self::DeviceMemoryLegacy,
        Self::DeviceMemory,
        Self::Rtt,
        Self::Downlink,
        Self::Ect,
        Self::Ua,
        Self::UaMobile,
        Self::UaArch,
        Self::UaPlatform,
        Self::UaPlatformVersion,
        Self::UaModel,
        Self::UaFullVersion,
        Self::UaFullVersionList,
        Self::UaBitness,
        Self::UaWoW64,
        Self::UaFormFactors,
        Self::PrefersReducedTransparency,
        Self::PrefersReducedMotion,
        Self::PrefersColorScheme,
        Self::DprLegacy,
        Self::Dpr,
        Self::ViewportWidthLegacy,
        Self::ViewportWidth,
        Self::ViewportHeight,
    ];

    /// The hint a header name stands for, ignoring case.
    pub fn from_header(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|hint| hint.header().eq_ignore_ascii_case(name))
    }
}

/// Hints of an `Accept-CH` value or `ACCEPT_CH` frame, in Chromium's order. A value that isn't a
/// structured-field token list is invalid (`None`); unknown names are skipped, and an empty value
/// is a valid empty list.
pub fn parse_accept_ch(value: &str) -> Option<Vec<Hint>> {
    let mut hints = Vec::new();
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() {
        return Some(hints);
    }
    for member in value.split(',') {
        // Parameters are allowed and ignored.
        let item = member.trim_matches([' ', '\t']);
        let token = item.split(';').next().unwrap_or("");
        if !is_sf_token(token) {
            return None;
        }
        if let Some(hint) = Hint::from_header(token) {
            if !hints.contains(&hint) {
                hints.push(hint);
            }
        }
    }
    hints.sort_unstable();
    Some(hints)
}

/// A structured-field token (RFC 8941 §3.3.4).
fn is_sf_token(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '*')
        && chars.all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~:/".contains(c))
}

/// `ACCEPT_CH` entries of a server's ALPS data, as (origin, value) pairs: HTTP/2 frames with 16-bit
/// lengths (`net::AlpsDecoder`), HTTP/3 with varint lengths (quiche `HttpDecoder`); malformed data
/// yields the entries parsed so far.
// A truncated length only makes the following bounds-checked slice fail, ending parsing early
// rather than reading out of bounds.
#[allow(clippy::cast_possible_truncation)]
pub fn alps_accept_ch(data: &[u8], http3: bool) -> Vec<(String, String)> {
    const ACCEPT_CH: u64 = 0x89;
    let mut entries = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (frame_type, payload) = if http3 {
            let Some((frame_type, after_type)) = read_varint(rest) else {
                break;
            };
            let Some((len, after_len)) = read_varint(after_type) else {
                break;
            };
            let Some(payload) = after_len.get(..len as usize) else {
                break;
            };
            rest = &after_len[len as usize..];
            (frame_type, payload)
        } else {
            let Some(header) = rest.get(..9) else {
                break;
            };
            let len =
                usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
            let stream =
                u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
            let Some(payload) = rest.get(9..9 + len) else {
                break;
            };
            rest = &rest[9 + len..];
            // Chromium ignores an ACCEPT_CH frame with flags or on a stream.
            if header[4] != 0 || stream != 0 {
                continue;
            }
            (u64::from(header[3]), payload)
        };
        if frame_type != ACCEPT_CH {
            continue;
        }
        let mut payload = payload;
        while !payload.is_empty() {
            let field = |p: &mut &[u8]| -> Option<String> {
                let (len, after) = if http3 {
                    let (len, after) = read_varint(p)?;
                    (usize::try_from(len).ok()?, after)
                } else {
                    let len = u16::from_be_bytes([*p.first()?, *p.get(1)?]);
                    (usize::from(len), &p[2..])
                };
                let bytes = after.get(..len)?;
                *p = &after[len..];
                String::from_utf8(bytes.to_vec()).ok()
            };
            let (Some(origin), Some(value)) = (field(&mut payload), field(&mut payload)) else {
                break;
            };
            entries.push((origin, value));
        }
    }
    entries
}

/// A QUIC variable-length integer (RFC 9000 §16) and the bytes after it.
fn read_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    let bytes = data.get(..len)?;
    let mut value = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        value = value << 8 | u64::from(b);
    }
    Some((value, &data[len..]))
}

/// The ASCII serialization of a URL's origin (`https://example.com:8443`), as `ACCEPT_CH` entries
/// and the persisted hints name it.
pub fn origin_of(uri: &Uri) -> String {
    let scheme = uri.scheme_str().unwrap_or("https");
    let host = uri.host().unwrap_or("").to_ascii_lowercase();
    match uri.port_u16() {
        Some(port) if port != default_port(scheme) => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" { 80 } else { 443 }
}

/// The client hints a client has learned: the hints each origin asked for with `Accept-CH`, and the
/// salt of Chromium's network-hint noise.
#[derive(Debug)]
pub struct ClientHintsState {
    persisted: Mutex<LruCache<String, Vec<Hint>>>,
    /// Chromium draws it once per browser process, 1 to 21.
    salt: u8,
    /// Brave's farbling seed, drawn once per client as Brave draws one per browser session.
    farbling_seed: u64,
}

impl Default for ClientHintsState {
    fn default() -> Self {
        Self {
            persisted: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_CLIENT_HINT_ORIGINS).expect("nonzero constant"),
            )),
            salt: rand::random_range(1..=21),
            farbling_seed: rand::random(),
        }
    }
}

impl ClientHintsState {
    /// The hints `origin` asked for.
    pub fn persisted(&self, origin: &str) -> Vec<Hint> {
        crate::util::lock_recover(&self.persisted)
            .get(origin)
            .cloned()
            .unwrap_or_default()
    }

    /// Remember the `Accept-CH` of a navigation response from `origin`: its hints replace what was
    /// asked before, an empty list forgets them, an invalid value changes nothing. Bounded at
    /// [`MAX_CLIENT_HINT_ORIGINS`]: the least recently used origin is evicted to make room for a
    /// new one, same as [`persisted`](Self::persisted) touching an origin keeps it recent.
    pub fn persist(&self, origin: &str, accept_ch: &str) {
        let Some(hints) = parse_accept_ch(accept_ch) else {
            return;
        };
        let mut persisted = crate::util::lock_recover(&self.persisted);
        if hints.is_empty() {
            persisted.pop(origin);
        } else {
            persisted.put(origin.to_string(), hints);
        }
    }

    /// A value below `n` fixed for this client and `site` (a registrable domain): Brave's farbling
    /// PRNG, seeded per session and site.
    // `hash % (n as u64)` is always below `n`, which is already a `usize`.
    #[allow(clippy::cast_possible_truncation)]
    pub fn farbling_index(&self, site: &str, n: usize) -> usize {
        let hash = site
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325u64 ^ self.farbling_seed, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            });
        (hash % n as u64) as usize
    }

    /// Chromium's per-host noise on the network hints (`GetRandomMultiplier`): 0.90-1.10 in steps
    /// of 0.01, keyed by host and salt (the hash need not match Chromium's own, which varies by
    /// platform too).
    // `hash % 21` is always 0-20, exact in an f64.
    #[allow(clippy::cast_precision_loss)]
    fn random_multiplier(&self, host: &str) -> f64 {
        let hash = host
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            })
            .wrapping_add(u64::from(self.salt));
        0.9 + (hash % 21) as f64 * 0.01
    }
}

/// Default network quality before Chromium has measured any (`NetworkQualityEstimatorParams`):
/// wired RTT/throughput for desktop, Wi-Fi for mobile; both report `4g`.
fn default_network_quality(mobile: bool) -> (f64, f64) {
    if mobile {
        (116.0, 2658.0)
    } else {
        (90.0, 1456.0)
    }
}

/// A structured-field string.
fn sf_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Chromium's `DoubleToSpecCompliantString`: the shortest decimal form.
fn spec_number(value: f64) -> String {
    let s = format!("{value}");
    if s.starts_with('.') {
        format!("0{s}")
    } else {
        s
    }
}

/// Blink's `String::Number(float)`: six significant digits, trailing zeros dropped
/// (`ToStringWithFixedPrecision`), for the values of a subresource.
// Matches Blink's own float-to-int cast when computing the digit count.
#[allow(clippy::cast_possible_truncation)]
fn blink_number(value: f32) -> String {
    let value = f64::from(value);
    if value == 0.0 {
        return "0".into();
    }
    let integer_digits = value.abs().log10().floor() as i32 + 1;
    let decimals = usize::try_from(6 - integer_digits).unwrap_or(0);
    let s = format!("{value:.decimals$}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// `ApproximatedDeviceMemory`: the memory rounded to the nearest power of two (ties down), in GiB,
/// kept within 2 to 32 GiB, on Android 1 to 8.
// Matches Chromium's own float cast (`nearest` is a power of two well within f32's exact integer
// range).
#[allow(clippy::cast_precision_loss)]
fn approximated_device_memory(mib: u64, android: bool) -> f32 {
    // Equivalent to `1u64 << mib.ilog2()`, but does not panic on `mib == 0`.
    let lower = 1u64 << (63 - mib.leading_zeros());
    let upper = lower << 1;
    let nearest = if mib - lower <= upper - mib {
        lower
    } else {
        upper
    };
    let (min, max) = if android { (1.0, 8.0) } else { (2.0, 32.0) };
    (nearest as f32 / 1024.0).clamp(min, max)
}

/// CSS-pixel viewport for `px` device pixels at `ratio`. A navigation takes the DIP size rounded
/// down, scaled to width 980 on Android (`GetScaledViewportSize`); a subresource takes Blink's
/// layout viewport, rounded.
// Matches Chromium's own viewport rounding; CSS pixel counts stay far below u32::MAX.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn css_viewport(
    (width, height): (u32, u32),
    ratio: f32,
    navigation: bool,
    android: bool,
) -> (u32, u32) {
    let ratio = if ratio > 0.0 { f64::from(ratio) } else { 1.0 };
    let css = |px: u32| f64::from(px) / ratio;
    if !navigation {
        return (css(width).round() as u32, css(height).round() as u32);
    }
    let (w, h) = (css(width).floor() as u32, css(height).floor() as u32);
    if android && w > 0 {
        let scale = 980.0 / f64::from(w);
        (980, (f64::from(h) * scale).round() as u32)
    } else {
        (w, h)
    }
}

/// Rejects values of `ua` that cannot go into a header, as
/// [`validate_headers`](super::execute::validate_headers) does: they are sent as they are (quoted,
/// for most hints).
pub fn validate(ua: &UaClientHints) -> Result<(), crate::Error> {
    let fields = [
        (Hint::UaFullVersion, &ua.full_version),
        (Hint::UaFullVersionList, &ua.full_version_list),
        (Hint::UaPlatformVersion, &ua.platform_version),
        (Hint::UaArch, &ua.architecture),
        (Hint::UaBitness, &ua.bitness),
        (Hint::UaModel, &ua.model),
    ]
    .into_iter()
    .chain(ua.form_factors.iter().map(|f| (Hint::UaFormFactors, f)));
    let headers: Vec<(String, String)> = fields
        .map(|(hint, value)| (hint.header().to_string(), value.clone()))
        .collect();
    super::execute::validate_headers(&headers)
}

/// The value `profile` sends for `hint` in a request to `host`, a navigation or not (the browser
/// process formats a navigation's device hints, Blink a subresource's); `None` if the profile has
/// no value for it (a profile without [`UaClientHints`] sends only the default hints).
pub fn hint_value(
    hint: Hint,
    profile: &BrowserProfile,
    state: &ClientHintsState,
    host: &str,
    navigation: bool,
) -> Option<String> {
    let header = |name: &str| {
        profile
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let ua: &UaClientHints = profile.ua_client_hints.as_ref()?;
    if let Some(sent) = &ua.sent_hints {
        if !sent.iter().any(|h| h.eq_ignore_ascii_case(hint.header())) {
            return None;
        }
    }
    let mobile = header("sec-ch-ua-mobile").as_deref() == Some("?1");
    let android = header("sec-ch-ua-platform").as_deref() == Some("\"Android\"");
    let (rtt_ms, downlink_kbps) = match ua.network_quality {
        Some(quality) => {
            let (rtt, downlink) = if navigation {
                quality.navigation
            } else {
                quality.subresource
            };
            (f64::from(rtt), f64::from(downlink))
        }
        None => default_network_quality(mobile),
    };
    let viewport = css_viewport(ua.viewport_px, ua.device_pixel_ratio, navigation, android);
    Some(match hint {
        Hint::DeviceMemoryLegacy | Hint::DeviceMemory => {
            if ua.device_memory_mib == 0 {
                return None;
            }
            let gib = approximated_device_memory(ua.device_memory_mib, android);
            if navigation {
                spec_number(f64::from(gib))
            } else {
                blink_number(gib)
            }
        }
        Hint::DprLegacy | Hint::Dpr => {
            if ua.device_pixel_ratio <= 0.0 {
                return None;
            }
            if navigation {
                spec_number(f64::from(ua.device_pixel_ratio))
            } else {
                blink_number(ua.device_pixel_ratio)
            }
        }
        Hint::ViewportWidthLegacy | Hint::ViewportWidth if viewport.0 > 0 => viewport.0.to_string(),
        Hint::ViewportHeight if viewport.1 > 0 => viewport.1.to_string(),
        Hint::ViewportWidthLegacy | Hint::ViewportWidth | Hint::ViewportHeight => return None,
        Hint::Ua | Hint::UaMobile | Hint::UaPlatform => header(hint.header())?,
        // `RoundRtt`: the noisy value rounded to 50 ms, at most 3 s.
        Hint::Rtt => {
            let rtt = (rtt_ms * state.random_multiplier(host)).min(3000.0);
            spec_number((rtt / 50.0).round() * 50.0)
        }
        // `RoundKbpsToMbps`: rounded to 50 kbit/s, at most 10 Mbit/s, in Mbit/s.
        Hint::Downlink => {
            let kbps = (downlink_kbps * state.random_multiplier(host)).min(10_000.0);
            spec_number((kbps / 50.0).round() * 50.0 / 1000.0)
        }
        Hint::Ect => "4g".into(),
        Hint::UaFullVersion => sf_string(&ua.full_version),
        Hint::UaArch => sf_string(&ua.architecture),
        Hint::UaPlatformVersion => sf_string(&ua.platform_version),
        Hint::UaModel => sf_string(&ua.model),
        Hint::UaBitness => sf_string(&ua.bitness),
        Hint::UaWoW64 => if ua.wow64 { "?1" } else { "?0" }.into(),
        Hint::UaFullVersionList => ua.full_version_list.clone(),
        Hint::UaFormFactors => ua
            .form_factors
            .iter()
            .map(|f| sf_string(f))
            .collect::<Vec<_>>()
            .join(", "),
        Hint::PrefersColorScheme => "light".into(),
        Hint::PrefersReducedMotion | Hint::PrefersReducedTransparency => "no-preference".into(),
    })
}

/// The values of every `name` header line, joined as one list (servers send Accept-CH on several
/// lines).
fn combined(headers: &[(String, String)], name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

impl super::Client {
    /// Learn from a navigation response: remember the hints its `Accept-CH` asks for, and return
    /// the origin if `Critical-CH` asks for a new one koon can send — the caller then restarts the
    /// navigation once per origin (`CriticalClientHintsThrottle`); `restarted` names origins
    /// already restarted.
    pub(super) fn learn_client_hints(
        &self,
        url: &Uri,
        response: &super::body::ResponseParts,
        restarted: &std::collections::HashSet<String>,
    ) -> Option<String> {
        use super::headers::{Family, header_value, is_potentially_trustworthy};

        if Family::of(&self.profile) != Family::Chromium || !is_potentially_trustworthy(url) {
            return None;
        }
        let accept_ch = combined(&response.headers, "accept-ch")?;
        let origin = origin_of(url);
        let before = self.client_hints.persisted(&origin);
        self.client_hints.persist(&origin, &accept_ch);

        if restarted.contains(&origin) {
            return None;
        }
        let asked = parse_accept_ch(&accept_ch)?;
        let critical = parse_accept_ch(&combined(&response.headers, "critical-ch")?)?;
        let host = url.host().unwrap_or("");
        let missing = critical.iter().any(|hint| {
            asked.contains(hint)
                && !hint.by_default()
                && !before.contains(hint)
                && header_value(&response.request_headers, hint.header()).is_none()
                && hint_value(*hint, &self.profile, &self.client_hints, host, true).is_some()
        });
        missing.then_some(origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// www.google.com's HTTP/3 ALPS data (Chrome 153): one ACCEPT_CH frame.
    const GOOGLE_H3_ALPS: &str = "408940b21668747470733a2f2f7777772e676f6f676c652e636f6d40995365632d43482d55412d417263682c205365632d43482d55412d4269746e6573732c205365632d43482d55412d4d6f64656c2c205365632d43482d55412d576f5736342c205365632d43482d55412d506c6174666f726d2d56657273696f6e2c205365632d43482d55412d46756c6c2d56657273696f6e2d4c6973742c205365632d43482d507265666572732d436f6c6f722d536368656d65";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decodes_googles_http3_alps() {
        let entries = alps_accept_ch(&unhex(GOOGLE_H3_ALPS), true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "https://www.google.com");
        assert_eq!(
            parse_accept_ch(&entries[0].1).unwrap(),
            [
                Hint::UaArch,
                Hint::UaPlatformVersion,
                Hint::UaModel,
                Hint::UaBitness,
                Hint::UaWoW64,
                Hint::UaFullVersionList,
                Hint::PrefersColorScheme
            ]
        );
    }

    #[test]
    fn decodes_http2_alps() {
        // SETTINGS (one setting), then ACCEPT_CH with two entries.
        let mut data = vec![0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0x00, 0x09, 0, 0, 0, 1];
        let mut payload = Vec::new();
        for (origin, value) in [
            ("https://a.test", "Sec-CH-UA-Arch"),
            ("https://b.test:8443", ""),
        ] {
            payload.extend((origin.len() as u16).to_be_bytes());
            payload.extend(origin.as_bytes());
            payload.extend((value.len() as u16).to_be_bytes());
            payload.extend(value.as_bytes());
        }
        let len = payload.len();
        data.extend([
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            0x89,
            0,
            0,
            0,
            0,
            0,
        ]);
        data.extend(&payload);
        assert_eq!(
            alps_accept_ch(&data, false),
            [
                ("https://a.test".to_string(), "Sec-CH-UA-Arch".to_string()),
                ("https://b.test:8443".to_string(), String::new())
            ]
        );
        // Truncated data keeps what was complete.
        assert!(alps_accept_ch(&data[..data.len() - 3], false).is_empty());
        assert_eq!(alps_accept_ch(&data[..15], false), []);
    }

    #[test]
    fn accept_ch_is_a_list_of_tokens() {
        assert_eq!(
            parse_accept_ch("sec-ch-ua-model, Sec-CH-UA-Arch;x=1, Viewport-Width, rtt").unwrap(),
            [
                Hint::ViewportWidthLegacy,
                Hint::Rtt,
                Hint::UaArch,
                Hint::UaModel
            ]
        );
        assert_eq!(parse_accept_ch("").unwrap(), []);
        assert_eq!(parse_accept_ch("\"sec-ch-ua-model\""), None);
        assert_eq!(parse_accept_ch("sec-ch-ua-model, (rtt)"), None);
        assert_eq!(parse_accept_ch("sec-ch-ua-model,,rtt"), None);
    }

    #[test]
    fn persisted_hints_follow_the_last_accept_ch() {
        let state = ClientHintsState::default();
        state.persist("https://a.test", "Sec-CH-UA-Model, RTT");
        assert_eq!(
            state.persisted("https://a.test"),
            [Hint::Rtt, Hint::UaModel]
        );
        state.persist("https://a.test", "\"broken\"");
        assert_eq!(
            state.persisted("https://a.test"),
            [Hint::Rtt, Hint::UaModel]
        );
        state.persist("https://a.test", "");
        assert_eq!(state.persisted("https://a.test"), []);
        assert_eq!(state.persisted("https://b.test"), []);
    }

    /// A long-running client that keeps visiting new origins does not grow this map forever: the
    /// oldest ones are evicted once it's full.
    #[test]
    fn persisted_map_is_bounded() {
        let state = ClientHintsState::default();
        for i in 0..MAX_CLIENT_HINT_ORIGINS + 10 {
            state.persist(&format!("https://h{i}.test"), "rtt");
        }
        assert_eq!(
            crate::util::lock_recover(&state.persisted).len(),
            MAX_CLIENT_HINT_ORIGINS
        );
        assert_eq!(
            state.persisted(&format!("https://h{}.test", MAX_CLIENT_HINT_ORIGINS + 9)),
            [Hint::Rtt]
        );
        assert_eq!(state.persisted("https://h0.test"), []);
    }

    #[test]
    fn network_hints_have_chromiums_granularity() {
        let state = ClientHintsState::default();
        for host in ["www.google.com", "example.com", "a.test"] {
            let m = state.random_multiplier(host);
            assert!((0.9..=1.1).contains(&m), "{m}");
        }
        let profile = crate::profile::Chrome::latest();
        let rtt: f64 = hint_value(Hint::Rtt, &profile, &state, "www.google.com", true)
            .unwrap()
            .parse()
            .unwrap();
        // 90 ms ± 10 % is always rounded to 100 ms.
        assert_eq!(rtt, 100.0);
        let downlink: f64 = hint_value(Hint::Downlink, &profile, &state, "www.google.com", true)
            .unwrap()
            .parse()
            .unwrap();
        assert!((1.3..=1.6).contains(&downlink), "{downlink}");
        assert_eq!(((downlink * 1000.0).round() as u64) % 50, 0);
        assert_eq!(spec_number(1.55), "1.55");
        assert_eq!(spec_number(2.0), "2");
    }

    /// Device hints as Chrome sent them on Windows and on the Pixel 9 Pro XL.
    #[test]
    fn device_hints_follow_chromium() {
        let state = ClientHintsState::default();
        let value = |profile: &BrowserProfile, hint, navigation| {
            hint_value(hint, profile, &state, "a.test", navigation).unwrap()
        };
        // Default new window on Windows: 1249×1261 device pixels.
        let windows = crate::profile::Chrome::latest();
        assert_eq!(value(&windows, Hint::Dpr, true), "1.1799999475479126");
        assert_eq!(value(&windows, Hint::DprLegacy, false), "1.18");
        assert_eq!(value(&windows, Hint::DeviceMemory, true), "32");
        assert_eq!(value(&windows, Hint::ViewportWidth, true), "1058");
        assert_eq!(value(&windows, Hint::ViewportWidthLegacy, false), "1058");
        assert_eq!(value(&windows, Hint::ViewportHeight, true), "1068");
        assert_eq!(value(&windows, Hint::ViewportHeight, false), "1069");
        let edge = crate::profile::Edge::version(154, crate::profile::Os::Windows).unwrap();
        assert_eq!(value(&edge, Hint::ViewportWidth, true), "1049");
        assert_eq!(value(&edge, Hint::ViewportHeight, true), "1070");
        assert_eq!(value(&edge, Hint::ViewportHeight, false), "1070");
        let linux = crate::profile::Chrome::version(154, crate::profile::Os::Linux).unwrap();
        assert_eq!(value(&linux, Hint::DeviceMemory, true), "8");
        assert_eq!(value(&linux, Hint::Dpr, false), "1");
        assert_eq!(value(&linux, Hint::ViewportWidth, true), "1265");
        assert_eq!(value(&linux, Hint::ViewportHeight, false), "1333");
        assert_eq!(
            linux.ua_client_hints.as_ref().unwrap().full_version_list,
            "\"Chromium\";v=\"154.0.8037.57\", \"Google Chrome\";v=\"154.0.8037.57\", \"Not A(Brand\";v=\"99.0.0.0\""
        );
        let android = crate::profile::Chrome::version(155, crate::profile::Os::Android).unwrap();
        assert_eq!(value(&android, Hint::DeviceMemoryLegacy, true), "8");
        assert_eq!(value(&android, Hint::DeviceMemory, false), "8");
        assert_eq!(value(&android, Hint::Dpr, true), "2.25");
        assert_eq!(value(&android, Hint::Dpr, false), "2.25");
        assert_eq!(value(&android, Hint::ViewportWidth, true), "980");
        assert_eq!(value(&android, Hint::ViewportWidth, false), "448");
        // Chrome's own values, with/without a viewport meta tag.
        assert_eq!(value(&android, Hint::ViewportHeight, true), "1862");
        assert_eq!(value(&android, Hint::ViewportHeight, false), "851");

        // Chromium's rounding and limits.
        assert_eq!(approximated_device_memory(32_563, false), 32.0);
        assert_eq!(approximated_device_memory(65_536, false), 32.0);
        assert_eq!(approximated_device_memory(1024, false), 2.0);
        assert_eq!(approximated_device_memory(6144, false), 4.0);
        assert_eq!(approximated_device_memory(6145, false), 8.0);
        assert_eq!(approximated_device_memory(3072, true), 2.0);
        assert_eq!(approximated_device_memory(512, true), 1.0);
        assert_eq!(blink_number(1.333_333_4), "1.33333");
        assert_eq!(blink_number(2.0), "2");
        assert_eq!(blink_number(0.5), "0.5");
        assert_eq!(blink_number(1.75), "1.75");

        // A profile without a value sends nothing for the hint.
        let mut none = windows;
        let hints = none.ua_client_hints.as_mut().unwrap();
        hints.device_memory_mib = 0;
        hints.device_pixel_ratio = 0.0;
        hints.viewport_px = (0, 0);
        for hint in [
            Hint::DeviceMemory,
            Hint::Dpr,
            Hint::ViewportWidth,
            Hint::ViewportHeight,
        ] {
            assert_eq!(hint_value(hint, &none, &state, "a.test", true), None);
            assert_eq!(hint_value(hint, &none, &state, "a.test", false), None);
        }
    }

    #[test]
    fn blink_order_lists_every_hint_once() {
        let mut blink = Hint::BLINK_ORDER.to_vec();
        blink.sort_unstable();
        assert_eq!(blink, Hint::ALL);
    }

    #[test]
    fn accept_ch_knows_the_device_hints() {
        assert_eq!(
            parse_accept_ch("Viewport-Width, DPR, Sec-CH-Viewport-Height, Device-Memory, RTT")
                .unwrap(),
            [
                Hint::DeviceMemoryLegacy,
                Hint::DprLegacy,
                Hint::ViewportWidthLegacy,
                Hint::ViewportHeight,
                Hint::Rtt
            ]
        );
        // Save-Data and the resource width are not sent.
        assert_eq!(
            parse_accept_ch("Save-Data, Sec-CH-Width, Width").unwrap(),
            []
        );
    }

    #[test]
    fn origins_serialize_without_default_ports() {
        let origin = |url: &str| origin_of(&url.parse().unwrap());
        assert_eq!(
            origin("https://WWW.Google.com/search?q=1"),
            "https://www.google.com"
        );
        assert_eq!(origin("https://a.test:443/"), "https://a.test");
        assert_eq!(origin("https://a.test:8443/x"), "https://a.test:8443");
        assert_eq!(origin("http://a.test:80/"), "http://a.test");
    }
}
