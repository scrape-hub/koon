use std::time::{Duration, Instant};

use http::Uri;

use crate::error::Error;

/// Cached Alt-Svc entry for HTTP/3 discovery.
pub(super) struct AltSvcEntry {
    pub(super) h3_port: u16,
    pub(super) expires: Instant,
}

/// Check if a status code is a redirect.
pub(super) fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Resolve a redirect Location against the current URL.
pub(super) fn resolve_redirect(base: &Uri, location: &str) -> Result<Uri, Error> {
    // If location is already absolute, use it directly
    if location.starts_with("http://") || location.starts_with("https://") {
        return location
            .parse()
            .map_err(|_| Error::Url(url::ParseError::EmptyHost));
    }

    // Relative URL — resolve against base
    let scheme = base.scheme_str().unwrap_or("https");
    let authority = base.authority().map(|a| a.as_str()).unwrap_or("");

    let absolute = if location.starts_with('/') {
        // Absolute path
        format!("{scheme}://{authority}{location}")
    } else {
        // Relative path — resolve against base path directory
        let base_path = base.path();
        let dir = match base_path.rfind('/') {
            Some(i) => &base_path[..=i],
            None => "/",
        };
        format!("{scheme}://{authority}{dir}{location}")
    };

    absolute
        .parse()
        .map_err(|_| Error::Url(url::ParseError::EmptyHost))
}

/// Parse `ma=SECONDS` from an Alt-Svc entry.
fn parse_alt_svc_max_age(entry: &str) -> Option<u64> {
    for part in entry.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("ma=") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Alt-Svc cache methods on Client.
impl super::Client {
    /// Check Alt-Svc cache for an H3 port for the given origin.
    pub(super) fn get_alt_svc_h3_port(&self, host: &str, port: u16) -> Option<u16> {
        let cache = self.alt_svc_cache.lock().unwrap();
        if let Some(entry) = cache.get(&(host.to_string(), port)) {
            if entry.expires > Instant::now() {
                return Some(entry.h3_port);
            }
        }
        None
    }

    /// Remove an Alt-Svc entry.
    pub(super) fn remove_alt_svc(&self, host: &str, port: u16) {
        self.alt_svc_cache
            .lock()
            .unwrap()
            .remove(&(host.to_string(), port));
    }

    /// Parse Alt-Svc header from H1/H2 response and cache H3 port.
    /// When a new Alt-Svc entry is discovered, evict the existing H2/H1 pool entry
    /// so the next request to this origin will attempt H3.
    pub(super) fn parse_alt_svc_from_response(
        &self,
        host: &str,
        port: u16,
        headers: &[(String, String)],
    ) {
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("alt-svc") {
                continue;
            }
            // Look for h3=":PORT" or h3=":443"
            for part in value.split(',') {
                let part = part.trim();
                if let Some(rest) = part.strip_prefix("h3=\":") {
                    if let Some(end) = rest.find('"') {
                        if let Ok(h3_port) = rest[..end].parse::<u16>() {
                            let max_age = parse_alt_svc_max_age(part).unwrap_or(86400);
                            let entry = AltSvcEntry {
                                h3_port,
                                expires: Instant::now() + Duration::from_secs(max_age),
                            };
                            self.alt_svc_cache
                                .lock()
                                .unwrap()
                                .insert((host.to_string(), port), entry);
                            // Evict existing H2/H1 pool entry so next request tries H3
                            self.pool.remove(host, port);
                            return;
                        }
                    }
                }
            }
        }
    }
}
