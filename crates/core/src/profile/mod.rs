mod chrome;

pub use chrome::Chrome;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::http2::Http2Config;
use crate::tls::TlsConfig;

/// A complete browser fingerprint profile.
///
/// Combines TLS, HTTP/2, and header configurations to fully impersonate
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

    /// Default headers in the correct order.
    /// The order matters for fingerprinting.
    pub headers: Vec<(String, String)>,
}

impl BrowserProfile {
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
}
