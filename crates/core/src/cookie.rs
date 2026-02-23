use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::Uri;
use serde::{Deserialize, Serialize};

/// A simple in-memory cookie jar for storing and matching cookies.
#[derive(Debug, Clone)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
}

/// The `SameSite` cookie attribute (RFC 6265bis).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSite {
    /// Cookie is sent with same-site and top-level navigation requests.
    Lax,
    /// Cookie is only sent with same-site requests.
    Strict,
    /// Cookie is sent with all requests (requires `Secure`).
    None,
}

/// A single stored HTTP cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain the cookie belongs to (lowercase).
    pub domain: String,
    /// URL path scope.
    pub path: String,
    /// Only send over HTTPS.
    pub secure: bool,
    /// Not accessible via JavaScript.
    #[serde(rename = "http_only")]
    pub _http_only: bool,
    /// Expiration time (`None` = session cookie).
    #[serde(
        serialize_with = "serialize_expires",
        deserialize_with = "deserialize_expires"
    )]
    pub expires: Option<SystemTime>,
    /// SameSite attribute.
    pub same_site: SameSite,
    /// If true, only exact domain match (no subdomain matching).
    pub host_only: bool,
}

fn serialize_expires<S: serde::Serializer>(
    time: &Option<SystemTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match time {
        Some(t) => {
            let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            serializer.serialize_some(&secs)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_expires<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SystemTime>, D::Error> {
    let opt: Option<u64> = Option::deserialize(deserializer)?;
    Ok(opt.map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}

impl CookieJar {
    /// Create an empty cookie jar.
    pub fn new() -> Self {
        CookieJar {
            cookies: Vec::new(),
        }
    }

    /// Parse Set-Cookie headers from a response and store matching cookies.
    pub fn store_from_response(&mut self, url: &Uri, headers: &[(String, String)]) {
        let request_host = url.host().unwrap_or("");
        let request_path = url.path();
        let is_secure = url.scheme_str() == Some("https");

        for (name, value) in headers {
            if name.eq_ignore_ascii_case("set-cookie") {
                if let Some(cookie) = parse_set_cookie(value, request_host, request_path, is_secure)
                {
                    // Remove existing cookie with same name+domain+path
                    self.cookies.retain(|c| {
                        !(c.name == cookie.name
                            && c.domain == cookie.domain
                            && c.path == cookie.path)
                    });
                    self.cookies.push(cookie);
                }
            }
        }

        // Purge expired cookies
        let now = SystemTime::now();
        self.cookies.retain(|c| match c.expires {
            Some(exp) => exp > now,
            None => true,
        });
    }

    /// Build a Cookie header value for the given URL.
    /// Returns None if no cookies match.
    pub fn cookie_header(&self, url: &Uri) -> Option<String> {
        let host = url.host().unwrap_or("");
        let path = url.path();
        let is_secure = url.scheme_str() == Some("https");
        let now = SystemTime::now();

        let matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                // Check expiry
                if let Some(exp) = c.expires {
                    if exp <= now {
                        return false;
                    }
                }
                // Check secure flag
                if c.secure && !is_secure {
                    return false;
                }
                // Domain matching: host_only requires exact match
                if c.host_only {
                    if host.to_lowercase() != c.domain {
                        return false;
                    }
                } else if !domain_matches(host, &c.domain) {
                    return false;
                }
                // Path matching: cookie path must be prefix of request path
                if !path_matches(path, &c.path) {
                    return false;
                }
                true
            })
            .collect();

        if matching.is_empty() {
            return None;
        }

        // Sort by path length descending (more specific paths first), then by creation order
        let mut sorted = matching;
        sorted.sort_by(|a, b| b.path.len().cmp(&a.path.len()));

        let header = sorted
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");

        Some(header)
    }

    /// Remove all stored cookies.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Get a reference to all stored cookies.
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Serialize all cookies to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.cookies)
    }

    /// Deserialize cookies from a JSON string, creating a new CookieJar.
    pub fn from_json(json: &str) -> Result<CookieJar, serde_json::Error> {
        let cookies: Vec<Cookie> = serde_json::from_str(json)?;
        Ok(CookieJar { cookies })
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a single Set-Cookie header value into a Cookie.
fn parse_set_cookie(
    header: &str,
    request_host: &str,
    request_path: &str,
    _is_secure: bool,
) -> Option<Cookie> {
    let mut parts = header.split(';');

    // First part is name=value
    let name_value = parts.next()?.trim();
    let eq_pos = name_value.find('=')?;
    let name = name_value[..eq_pos].trim().to_string();
    let value = name_value[eq_pos + 1..].trim().to_string();

    if name.is_empty() {
        return None;
    }

    let mut domain = String::new();
    let mut domain_explicit = false;
    let mut path = String::new();
    let mut secure = false;
    let mut _http_only = false;
    let mut max_age: Option<SystemTime> = None;
    let mut expires_parsed: Option<SystemTime> = None;
    let mut same_site = SameSite::Lax; // Default per RFC 6265bis

    // Collect all parts first so we can access the original case for Expires
    let remaining: Vec<&str> = parts.collect();

    for part in &remaining {
        let part = part.trim();
        let lower = part.to_lowercase();

        if lower == "secure" {
            secure = true;
        } else if lower == "httponly" {
            _http_only = true;
        } else if let Some(val) = lower.strip_prefix("domain=") {
            domain = val.trim().trim_start_matches('.').to_string();
            domain_explicit = true;
        } else if let Some(val) = part
            .strip_prefix("path=")
            .or_else(|| part.strip_prefix("Path="))
        {
            path = val.trim().to_string();
        } else if let Some(val) = lower.strip_prefix("max-age=") {
            if let Ok(secs) = val.trim().parse::<i64>() {
                if secs <= 0 {
                    max_age = Some(SystemTime::UNIX_EPOCH);
                } else {
                    max_age = SystemTime::now().checked_add(Duration::from_secs(secs as u64));
                }
            }
        } else if lower.starts_with("expires=") {
            // Use original case for date parsing (not lowercased)
            if let Some(val) = part.split_once('=').map(|(_, v)| v.trim()) {
                expires_parsed = parse_http_date(val);
            }
        } else if let Some(val) = lower.strip_prefix("samesite=") {
            same_site = match val.trim() {
                "strict" => SameSite::Strict,
                "lax" => SameSite::Lax,
                "none" => SameSite::None,
                _ => SameSite::Lax,
            };
        }
    }

    // Max-Age takes precedence over Expires per RFC 6265
    let expires = max_age.or(expires_parsed);

    // host_only = true when domain was NOT explicitly set
    let host_only = !domain_explicit;

    // Default domain to request host
    if domain.is_empty() {
        domain = request_host.to_lowercase();
    } else {
        domain = domain.to_lowercase();
    }

    // Default path: use the directory of the request path
    if path.is_empty() {
        path = default_path(request_path);
    }

    Some(Cookie {
        name,
        value,
        domain,
        path,
        secure,
        _http_only,
        expires,
        same_site,
        host_only,
    })
}

/// Parse an HTTP date in IMF-fixdate format: "Thu, 01 Dec 2025 00:00:00 GMT"
fn parse_http_date(s: &str) -> Option<SystemTime> {
    // IMF-fixdate: "day-name, DD Mon YYYY HH:MM:SS GMT"
    let s = s.trim();

    // Skip "day-name, " part
    let rest = s.split_once(", ")?.1;

    // "DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month = month_from_str(parts[1])?;
    let year: i64 = parts[2].parse().ok()?;

    // Parse HH:MM:SS
    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;

    // Convert to seconds since Unix epoch using Hinnant's algorithm
    let days = days_from_civil(year, month, day)?;
    let total_secs = days as u64 * 86400 + hour * 3600 + min * 60 + sec;

    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(total_secs))
}

fn month_from_str(s: &str) -> Option<u32> {
    match s {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

/// Convert a civil date to days since Unix epoch (1970-01-01) using Hinnant's algorithm.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i64 - 719468)
}

/// Domain matching per RFC 6265: the cookie domain must be a suffix of the request host.
fn domain_matches(request_host: &str, cookie_domain: &str) -> bool {
    let host = request_host.to_lowercase();
    let domain = cookie_domain.to_lowercase();

    if host == domain {
        return true;
    }

    // The host must end with ".domain"
    if host.ends_with(&format!(".{domain}")) {
        return true;
    }

    false
}

/// Path matching per RFC 6265: the cookie path must be a prefix of the request path.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }

    if request_path.starts_with(cookie_path) {
        // Cookie path must end with '/' or request path must have '/' after cookie path
        if cookie_path.ends_with('/') {
            return true;
        }
        if request_path.as_bytes().get(cookie_path.len()) == Some(&b'/') {
            return true;
        }
    }

    false
}

/// Get the default cookie path from a request path.
/// Per RFC 6265: directory of the request URI path.
fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("www.example.com", "example.com"));
        assert!(domain_matches("sub.www.example.com", "example.com"));
        assert!(!domain_matches("notexample.com", "example.com"));
        assert!(!domain_matches("example.com", "www.example.com"));
    }

    #[test]
    fn test_path_matches() {
        assert!(path_matches("/", "/"));
        assert!(path_matches("/foo", "/"));
        assert!(path_matches("/foo/bar", "/foo"));
        assert!(path_matches("/foo/bar", "/foo/"));
        assert!(!path_matches("/foobar", "/foo"));
        assert!(!path_matches("/bar", "/foo"));
    }

    #[test]
    fn test_parse_and_retrieve() {
        let mut jar = CookieJar::new();
        let url: Uri = "https://example.com/path".parse().unwrap();

        jar.store_from_response(
            &url,
            &[
                (
                    "set-cookie".to_string(),
                    "session=abc123; Path=/; Secure".to_string(),
                ),
                (
                    "set-cookie".to_string(),
                    "theme=dark; Path=/; Domain=example.com".to_string(),
                ),
            ],
        );

        let header = jar.cookie_header(&url).unwrap();
        assert!(header.contains("session=abc123"));
        assert!(header.contains("theme=dark"));
    }

    #[test]
    fn test_cookie_overwrite() {
        let mut jar = CookieJar::new();
        let url: Uri = "https://example.com/".parse().unwrap();

        jar.store_from_response(
            &url,
            &[("set-cookie".to_string(), "a=1; Path=/".to_string())],
        );
        jar.store_from_response(
            &url,
            &[("set-cookie".to_string(), "a=2; Path=/".to_string())],
        );

        let header = jar.cookie_header(&url).unwrap();
        assert_eq!(header, "a=2");
    }

    #[test]
    fn test_secure_cookie_not_sent_over_http() {
        let mut jar = CookieJar::new();
        let https_url: Uri = "https://example.com/".parse().unwrap();
        let http_url: Uri = "http://example.com/".parse().unwrap();

        jar.store_from_response(
            &https_url,
            &[(
                "set-cookie".to_string(),
                "secret=val; Path=/; Secure".to_string(),
            )],
        );

        assert!(jar.cookie_header(&https_url).is_some());
        assert!(jar.cookie_header(&http_url).is_none());
    }

    #[test]
    fn test_expires_parsing() {
        let mut jar = CookieJar::new();
        let url: Uri = "https://example.com/".parse().unwrap();

        // Cookie with a far-future Expires
        jar.store_from_response(
            &url,
            &[(
                "set-cookie".to_string(),
                "future=yes; Path=/; Expires=Thu, 01 Dec 2030 00:00:00 GMT".to_string(),
            )],
        );
        assert!(jar.cookie_header(&url).is_some());
        assert!(jar.cookie_header(&url).unwrap().contains("future=yes"));

        // Cookie with a past Expires (should be expired)
        jar.store_from_response(
            &url,
            &[(
                "set-cookie".to_string(),
                "past=no; Path=/; Expires=Thu, 01 Jan 2020 00:00:00 GMT".to_string(),
            )],
        );
        // The "past" cookie should have been purged
        let header = jar.cookie_header(&url).unwrap();
        assert!(!header.contains("past=no"));
        assert!(header.contains("future=yes"));
    }

    #[test]
    fn test_max_age_precedence() {
        let mut jar = CookieJar::new();
        let url: Uri = "https://example.com/".parse().unwrap();

        // Max-Age=3600 should override the past Expires
        jar.store_from_response(
            &url,
            &[(
                "set-cookie".to_string(),
                "pref=val; Path=/; Expires=Thu, 01 Jan 2020 00:00:00 GMT; Max-Age=3600".to_string(),
            )],
        );

        // Max-Age takes precedence, cookie should still be valid
        let header = jar.cookie_header(&url).unwrap();
        assert!(header.contains("pref=val"));
    }

    #[test]
    fn test_host_only_cookie() {
        let mut jar = CookieJar::new();
        let url: Uri = "https://example.com/".parse().unwrap();
        let sub_url: Uri = "https://sub.example.com/".parse().unwrap();

        // Cookie without explicit Domain → host_only = true
        jar.store_from_response(
            &url,
            &[("set-cookie".to_string(), "hostonly=yes; Path=/".to_string())],
        );

        // Should match exact host
        assert!(jar.cookie_header(&url).is_some());
        // Should NOT match subdomain (host_only)
        assert!(jar.cookie_header(&sub_url).is_none());

        // Now set a cookie WITH explicit Domain
        jar.store_from_response(
            &url,
            &[(
                "set-cookie".to_string(),
                "shared=yes; Path=/; Domain=example.com".to_string(),
            )],
        );

        // Domain cookie should match subdomain
        let sub_header = jar.cookie_header(&sub_url).unwrap();
        assert!(sub_header.contains("shared=yes"));
    }

    #[test]
    fn test_samesite_stored() {
        // Test that SameSite is correctly parsed (we store it, even if we don't enforce yet)
        let url: Uri = "https://example.com/".parse().unwrap();

        let cookie_strict =
            parse_set_cookie("a=1; Path=/; SameSite=Strict", "example.com", "/", true).unwrap();
        assert_eq!(cookie_strict.same_site, SameSite::Strict);

        let cookie_lax =
            parse_set_cookie("b=2; Path=/; SameSite=Lax", "example.com", "/", true).unwrap();
        assert_eq!(cookie_lax.same_site, SameSite::Lax);

        let cookie_none = parse_set_cookie(
            "c=3; Path=/; SameSite=None; Secure",
            "example.com",
            "/",
            true,
        )
        .unwrap();
        assert_eq!(cookie_none.same_site, SameSite::None);

        // Default should be Lax
        let cookie_default = parse_set_cookie("d=4; Path=/", "example.com", "/", true).unwrap();
        assert_eq!(cookie_default.same_site, SameSite::Lax);

        // Verify cookies are stored and retrievable
        let mut jar = CookieJar::new();
        jar.store_from_response(
            &url,
            &[(
                "set-cookie".to_string(),
                "strict=val; Path=/; SameSite=Strict".to_string(),
            )],
        );
        assert!(jar.cookie_header(&url).unwrap().contains("strict=val"));
    }

    #[test]
    fn test_http_date_parsing() {
        // Valid IMF-fixdate
        let date = parse_http_date("Thu, 01 Dec 2025 00:00:00 GMT");
        assert!(date.is_some());

        // Another valid date
        let date = parse_http_date("Mon, 15 Jan 2024 12:30:45 GMT");
        assert!(date.is_some());

        // Invalid format
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }
}
