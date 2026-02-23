mod chrome;
mod edge;
mod firefox;
mod opera;
mod safari;

pub use chrome::Chrome;
pub use edge::Edge;
pub use firefox::Firefox;
pub use opera::Opera;
pub use safari::Safari;

use std::path::Path;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::http2::Http2Config;
use crate::quic::QuicConfig;
use crate::tls::TlsConfig;

/// A complete browser fingerprint profile.
///
/// Combines TLS, HTTP/2, HTTP/3, and header configurations to fully impersonate
/// a specific browser version on a specific OS.
///
/// Profiles can be serialized to/from JSON, allowing users to:
/// - Export built-in profiles and customize them
/// - Load custom profiles from JSON files
/// - Share profiles between applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    /// TLS fingerprint settings (JA3/JA4).
    pub tls: TlsConfig,

    /// HTTP/2 fingerprint settings (Akamai H2).
    pub http2: Http2Config,

    /// QUIC/HTTP/3 transport settings.
    /// When None, HTTP/3 is disabled for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<QuicConfig>,

    /// Default headers in the correct order.
    /// The order matters for fingerprinting.
    pub headers: Vec<(String, String)>,
}

impl BrowserProfile {
    /// Resolve a browser profile by name string.
    ///
    /// Accepts formats like:
    /// - `"chrome"`, `"firefox"`, `"safari"`, `"edge"`, `"opera"` — latest version, default OS
    /// - `"chrome145"`, `"firefox147"` — specific version, default OS (Windows; Safari: macOS)
    /// - `"chrome145-windows"`, `"chrome145-macos"`, `"chrome145-linux"` — specific version + OS (dash-separated)
    /// - `"chrome145windows"`, `"chrome145macos"` — specific version + OS (no dash, for Node.js/Python compat)
    /// - `"safari183"`, `"safari18.3"` — Safari version formats
    ///
    /// Case-insensitive.
    pub fn resolve(name: &str) -> Result<Self, String> {
        let name_lower = name.to_lowercase();
        let (browser, os) = Self::parse_browser_os(&name_lower);

        if let Some(rest) = browser.strip_prefix("chrome") {
            return if rest.is_empty() {
                Chrome::resolve(Chrome::LATEST_VERSION, os)
            } else {
                let major: u32 = rest.parse().map_err(|_| {
                    format!("Invalid Chrome version: '{rest}'. Expected a number (131-145)")
                })?;
                Chrome::resolve(major, os)
            };
        }

        if let Some(rest) = browser.strip_prefix("firefox") {
            return if rest.is_empty() {
                Firefox::resolve(Firefox::LATEST_VERSION, os)
            } else {
                let major: u32 = rest.parse().map_err(|_| {
                    format!("Invalid Firefox version: '{rest}'. Expected a number (135-147)")
                })?;
                Firefox::resolve(major, os)
            };
        }

        if let Some(rest) = browser.strip_prefix("safari") {
            return Safari::resolve(rest, os);
        }

        if let Some(rest) = browser.strip_prefix("edge") {
            return if rest.is_empty() {
                Edge::resolve(Edge::LATEST_VERSION, os)
            } else {
                let major: u32 = rest.parse().map_err(|_| {
                    format!("Invalid Edge version: '{rest}'. Expected a number (131-145)")
                })?;
                Edge::resolve(major, os)
            };
        }

        if let Some(rest) = browser.strip_prefix("opera") {
            return if rest.is_empty() {
                Opera::resolve(Opera::LATEST_VERSION, os)
            } else {
                let major: u32 = rest.parse().map_err(|_| {
                    format!("Invalid Opera version: '{rest}'. Expected a number (124-127)")
                })?;
                Opera::resolve(major, os)
            };
        }

        Err(format!(
            "Unknown browser: '{name}'. Supported: chrome, firefox, safari, edge, opera"
        ))
    }

    /// Parse a browser name into (browser_with_version, optional_os).
    ///
    /// Handles both dash-separated ("chrome145-windows") and
    /// concatenated ("chrome145windows") OS suffixes.
    fn parse_browser_os(input: &str) -> (&str, Option<&str>) {
        // Try dash-separated first (CLI format: "chrome145-windows")
        if let Some(pos) = input.rfind('-') {
            let suffix = &input[pos + 1..];
            if matches!(suffix, "windows" | "macos" | "linux") {
                return (&input[..pos], Some(suffix));
            }
        }
        // Try suffix without dash (Node/Python format: "chrome145windows")
        for os in &["windows", "macos", "linux"] {
            if let Some(prefix) = input.strip_suffix(os) {
                if !prefix.is_empty() {
                    return (prefix, Some(os));
                }
            }
        }
        (input, None)
    }

    /// Deserialize a profile from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the profile to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load a profile from a JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        let contents = std::fs::read_to_string(path).map_err(crate::Error::Io)?;
        serde_json::from_str(&contents).map_err(crate::Error::Json)
    }

    /// Apply subtle randomization to make each client instance unique.
    ///
    /// Randomizes fields that anti-bot systems can use to correlate clients
    /// sharing the same profile, while keeping TLS/H2 fingerprint-critical
    /// values (ciphers, curves, sigalgs, extension order) untouched.
    ///
    /// What changes:
    /// - Chrome/Edge: UA build number within the same major version range
    /// - `sec-ch-ua` version kept in sync with randomized UA
    /// - `accept-language` q-values get small jitter
    /// - H2 `initial_window_size` and `initial_conn_window_size` get ±32KB jitter
    pub fn randomize(&mut self) {
        let mut rng = rand::rng();
        self.randomize_user_agent(&mut rng);
        self.randomize_accept_language(&mut rng);
        self.randomize_h2_window_sizes(&mut rng);
    }

    fn randomize_user_agent(&mut self, rng: &mut impl Rng) {
        // Find user-agent header and detect Chrome/Edge pattern
        let ua_idx = self.headers.iter().position(|(k, _)| k == "user-agent");
        let ua_idx = match ua_idx {
            Some(i) => i,
            None => return,
        };

        let ua = &self.headers[ua_idx].1;

        // Match Chrome UA pattern: "Chrome/MAJOR.0.BUILD.PATCH"
        // We randomize BUILD and PATCH within realistic ranges
        if let Some(chrome_pos) = ua.find("Chrome/") {
            let after = &ua[chrome_pos + 7..];
            // Parse "MAJOR.0.BUILD.PATCH"
            let parts: Vec<&str> = after
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .next()
                .unwrap_or("")
                .split('.')
                .collect();
            if parts.len() >= 4 {
                let major = parts[0];
                let build: u32 = rng.random_range(6778..=6810);
                let patch: u32 = rng.random_range(0..=265);
                let new_version = format!("{major}.0.{build}.{patch}");
                let old_version = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);

                // Replace in UA string
                let new_ua = ua.replace(&old_version, &new_version);
                self.headers[ua_idx].1 = new_ua;

                // Update sec-ch-ua to match (keep same major version)
                // sec-ch-ua only contains major version, so no change needed
            }
        }
    }

    fn randomize_accept_language(&mut self, rng: &mut impl Rng) {
        if let Some(idx) = self
            .headers
            .iter()
            .position(|(k, _)| k == "accept-language")
        {
            let val = &self.headers[idx].1;
            // Replace q=0.9 or q=0.5 with random jitter
            let new_val = val
                .split(',')
                .map(|part| {
                    if let Some(q_pos) = part.find(";q=0.") {
                        let prefix = &part[..q_pos];
                        let q_digit: u8 = rng.random_range(7..=9);
                        format!("{prefix};q=0.{q_digit}")
                    } else {
                        part.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            self.headers[idx].1 = new_val;
        }
    }

    fn randomize_h2_window_sizes(&mut self, rng: &mut impl Rng) {
        // ±32KB jitter on window sizes (32768 bytes)
        let jitter: i32 = rng.random_range(-32768..=32768);
        self.http2.initial_window_size =
            (self.http2.initial_window_size as i64 + jitter as i64) as u32;

        let jitter: i32 = rng.random_range(-32768..=32768);
        self.http2.initial_conn_window_size =
            (self.http2.initial_conn_window_size as i64 + jitter as i64) as u32;
    }
}
