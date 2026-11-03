use std::sync::Mutex;

use crate::util::GrowingLru;
use http::Uri;

use crate::profile::{BrowserProfile, UaClientHints};

const MAX_CLIENT_HINT_ORIGINS: usize = 10_000;

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

    pub const fn by_default(self) -> bool {
        matches!(self, Self::Ua | Self::UaMobile | Self::UaPlatform)
    }

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

    pub fn from_header(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|hint| hint.header().eq_ignore_ascii_case(name))
    }
}

pub fn parse_accept_ch(value: &str) -> Option<Vec<Hint>> {
    let mut hints = Vec::new();
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() {
        return Some(hints);
    }
    for member in value.split(',') {
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

fn is_sf_token(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '*')
        && chars.all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~:/".contains(c))
}

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

#[derive(Debug)]
pub struct ClientHintsState {
    persisted: Mutex<GrowingLru<String, Vec<Hint>>>,
    salt: u8,
    farbling_seed: u64,
}

impl Default for ClientHintsState {
    fn default() -> Self {
        Self {
            persisted: Mutex::new(GrowingLru::new(MAX_CLIENT_HINT_ORIGINS)),
            salt: rand::random_range(1..=21),
            farbling_seed: rand::random(),
        }
    }
}

impl ClientHintsState {
    pub fn persisted(&self, origin: &str) -> Vec<Hint> {
        crate::util::lock_recover(&self.persisted)
            .get(origin)
            .cloned()
            .unwrap_or_default()
    }

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

    #[allow(clippy::cast_possible_truncation)]
    pub fn farbling_index(&self, site: &str, n: usize) -> usize {
        let hash = site
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325u64 ^ self.farbling_seed, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            });
        (hash % n as u64) as usize
    }

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

fn default_network_quality(mobile: bool) -> (f64, f64) {
    if mobile {
        (116.0, 2658.0)
    } else {
        (90.0, 1456.0)
    }
}

fn sf_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn spec_number(value: f64) -> String {
    let s = format!("{value}");
    if s.starts_with('.') {
        format!("0{s}")
    } else {
        s
    }
}

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

#[allow(clippy::cast_precision_loss)]
fn approximated_device_memory(mib: u64, android: bool) -> f32 {
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
        Hint::Rtt => {
            let rtt = (rtt_ms * state.random_multiplier(host)).min(3000.0);
            spec_number((rtt / 50.0).round() * 50.0)
        }
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

fn combined(headers: &[(String, String)], name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

impl super::Client {
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
