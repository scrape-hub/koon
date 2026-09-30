use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// A `name=value` pair may not exceed this many bytes, matching the limit browsers enforce on a
/// single cookie (RFC 6265 recommends at least 4096).
pub(crate) const MAX_COOKIE_SIZE: usize = 4096;

/// Maximum number of cookies kept per stored `domain`, Chrome's per-domain cap (counted per exact
/// stored domain here, not per eTLD+1 as Chrome does).
const MAX_COOKIES_PER_DOMAIN: usize = 180;

/// Maximum number of cookies kept in the jar overall, mirroring Chrome's global cap.
const MAX_COOKIES_TOTAL: usize = 3300;

/// Longest lifetime a `Set-Cookie` can give a cookie: Expires and Max-Age are capped at 400 days
/// from now (RFC 6265bis §5.6.1/§5.6.2; Chrome and Firefox enforce the same cap).
const MAX_COOKIE_AGE: Duration = Duration::from_secs(400 * 24 * 60 * 60);

/// Latest `expires` an imported cookie may have: 9999-12-31T23:59:59Z, the limit Playwright
/// enforces (`kMaxCookieExpiresDateInSeconds`).
const MAX_IMPORT_EXPIRES: f64 = 253_402_300_799.0;

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

impl SameSite {
    /// Parse an attribute value, ASCII case-insensitively.
    fn parse(value: &str) -> Option<Self> {
        [
            ("strict", Self::Strict),
            ("lax", Self::Lax),
            ("none", Self::None),
        ]
        .into_iter()
        .find(|(name, _)| value.eq_ignore_ascii_case(name))
        .map(|(_, same_site)| same_site)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// A single stored HTTP cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name. Empty for a nameless cookie (`Set-Cookie: abc`), which is sent as just its
    /// value.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain the cookie belongs to (lowercase, without a leading dot).
    pub domain: String,
    /// URL path scope.
    pub path: String,
    /// Only send over HTTPS.
    pub secure: bool,
    /// Not accessible via JavaScript.
    pub http_only: bool,
    /// Expiration time (`None` = session cookie); an unrepresentable saved timestamp loads as
    /// `None`.
    #[serde(
        serialize_with = "serialize_expires",
        deserialize_with = "deserialize_expires"
    )]
    pub expires: Option<SystemTime>,
    /// `SameSite` attribute.
    pub same_site: SameSite,
    /// If true, only exact domain match (no subdomain matching).
    pub host_only: bool,
    /// When this cookie was first stored (kept across a replace, RFC 6265 §5.3 step 11.3; anchors
    /// its position in the `Cookie` header on a tied path length). An unrepresentable saved value
    /// loads as "now".
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub creation_time: SystemTime,
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
    let secs: Option<u64> = Option::deserialize(deserializer)?;
    Ok(secs.and_then(|secs| UNIX_EPOCH.checked_add(Duration::from_secs(secs))))
}

fn serialize_time<S: serde::Serializer>(
    time: &SystemTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    serializer.serialize_u64(secs)
}

fn deserialize_time<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SystemTime, D::Error> {
    let secs = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap_or_else(SystemTime::now))
}

impl CookieJar {
    /// Create an empty cookie jar.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }

    /// Insert or replace a cookie, keyed by (name, domain, path, `host_only`): a host-only and a
    /// domain cookie of the same name coexist, as in browsers. Replacing keeps the original
    /// creation time (RFC 6265 §5.3 step 11.3). A cookie whose `expires` is already past removes
    /// the matching stored cookie instead (a `Set-Cookie` deletion).
    pub(crate) fn set(&mut self, mut cookie: Cookie) {
        let existing = self.cookies.iter().position(|stored| {
            stored.name == cookie.name
                && stored.domain == cookie.domain
                && stored.path == cookie.path
                && stored.host_only == cookie.host_only
        });

        let expired = matches!(cookie.expires, Some(exp) if exp <= SystemTime::now());

        if let Some(idx) = existing {
            if expired {
                self.cookies.remove(idx);
            } else {
                cookie.creation_time = self.cookies[idx].creation_time;
                self.cookies[idx] = cookie;
            }
        } else if !expired {
            self.cookies.push(cookie);
        }
    }

    /// Parse Set-Cookie headers from a response and store the cookies a browser would accept.
    pub fn store_from_response(&mut self, url: &Uri, headers: &[(String, String)]) {
        let mut set_cookies = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            .peekable();
        if set_cookies.peek().is_none() {
            return;
        }

        let host = url.host().unwrap_or("").to_ascii_lowercase();
        let secure_origin = is_secure_origin(url, &host);
        let mut stored = false;
        for (_, value) in set_cookies {
            let Some(cookie) = parse_set_cookie(value, &host, url.path(), secure_origin) else {
                continue;
            };
            if !secure_origin && self.shadows_secure_cookie(&cookie) {
                continue;
            }
            self.set(cookie);
            stored = true;
        }

        if stored {
            self.prune();
        }
    }

    /// "Leave Secure Cookies Alone" (RFC 6265bis §5.7 step 16): a non-secure origin may not set,
    /// overwrite or delete a cookie that would shadow a `Secure` one (same name, domains matching
    /// either way, path within it).
    fn shadows_secure_cookie(&self, cookie: &Cookie) -> bool {
        self.cookies.iter().any(|stored| {
            stored.secure
                && stored.name == cookie.name
                && (domain_matches(&stored.domain, &cookie.domain)
                    || domain_matches(&cookie.domain, &stored.domain))
                && path_matches(&cookie.path, &stored.path)
        })
    }

    /// Drop expired cookies, then evict the oldest cookies (by creation time) beyond browser-like
    /// limits: at most [`MAX_COOKIES_PER_DOMAIN`] per stored `domain`, then at most
    /// [`MAX_COOKIES_TOTAL`] overall. Expired cookies go first so they never count against the
    /// limits.
    pub(crate) fn prune(&mut self) {
        let now = SystemTime::now();
        self.cookies
            .retain(|cookie| cookie.expires.is_none_or(|exp| exp > now));

        // Per over-limit domain: how many of its cookies to evict.
        let mut excess: HashMap<&str, usize> = HashMap::new();
        for cookie in &self.cookies {
            *excess.entry(cookie.domain.as_str()).or_default() += 1;
        }
        excess.retain(|_, count| {
            *count = count.saturating_sub(MAX_COOKIES_PER_DOMAIN);
            *count > 0
        });
        if excess.is_empty() && self.cookies.len() <= MAX_COOKIES_TOTAL {
            return;
        }

        let mut oldest_first: Vec<usize> = (0..self.cookies.len()).collect();
        oldest_first.sort_by_key(|&i| self.cookies[i].creation_time);
        let mut evict = vec![false; self.cookies.len()];
        let mut remaining = self.cookies.len();
        for &i in &oldest_first {
            if let Some(count) = excess.get_mut(self.cookies[i].domain.as_str()) {
                if *count > 0 {
                    *count -= 1;
                    evict[i] = true;
                    remaining -= 1;
                }
            }
        }
        for &i in &oldest_first {
            if remaining <= MAX_COOKIES_TOTAL {
                break;
            }
            if !evict[i] {
                evict[i] = true;
                remaining -= 1;
            }
        }

        let mut evict = evict.into_iter();
        self.cookies.retain(|_| !evict.next().unwrap_or(false));
    }

    /// Build a Cookie header value for the given URL. Returns None if no cookies match.
    pub fn cookie_header(&self, url: &Uri) -> Option<String> {
        let host = url.host()?.to_ascii_lowercase();
        let path = url.path();
        let secure = is_secure_origin(url, &host);
        let now = SystemTime::now();

        let mut matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                c.expires.is_none_or(|exp| exp > now)
                    && (secure || !c.secure)
                    && if c.host_only {
                        host == c.domain
                    } else {
                        domain_matches(&host, &c.domain)
                    }
                    && path_matches(path, &c.path)
            })
            .collect();
        if matching.is_empty() {
            return None;
        }

        // RFC 6265 §5.4 step 2: longer paths first; among equal path lengths, earlier creation time
        // first.
        matching.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then(a.creation_time.cmp(&b.creation_time))
        });

        let mut header = String::new();
        for cookie in matching {
            if !header.is_empty() {
                header.push_str("; ");
            }
            // RFC 6265bis §5.8.3: a nameless cookie is sent as its value.
            if !cookie.name.is_empty() {
                header.push_str(&cookie.name);
                header.push('=');
            }
            header.push_str(&cookie.value);
        }
        Some(header)
    }

    /// Remove all stored cookies.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Get a reference to all stored cookies.
    #[must_use]
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Serialize all cookies to a JSON string.
    ///
    /// # Errors
    /// Returns an error if a cookie fails to serialize (never expected, since every field is a
    /// plain value serde already supports).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.cookies)
    }

    /// Deserialize cookies from a JSON string, creating a new `CookieJar`. Domains are normalized
    /// (lowercase, no leading dot) like every other way into the jar.
    ///
    /// # Errors
    /// Returns an error if `json` is not a valid JSON array of cookies.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        Ok(Self::from_cookies(serde_json::from_str(json)?))
    }

    /// Create a `CookieJar` holding `cookies`, with their domains normalized (lowercase, no leading
    /// dot) like every other way into the jar.
    #[must_use]
    pub fn from_cookies(mut cookies: Vec<Cookie>) -> Self {
        for cookie in &mut cookies {
            cookie.domain = normalize_domain(&cookie.domain);
        }
        Self { cookies }
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

/// A cookie in the shape browser automation tools use (Playwright's `addCookies()`/`cookies()`,
/// CDP's `Network.setCookies`).
///
/// Converted with `Cookie::try_from` (import) and `CookieParams::from(&Cookie)` (export). A cookie
/// has either a `url` or a `domain` (optional `path`, default `/`); a `url` gives a host-only
/// cookie for its host, path up to the last `/`, `secure` from the scheme. A `domain` with a
/// leading dot is a domain cookie, one without is host-only; `host_only` overrides either. Export
/// mirrors this (leading dot for domain cookies, none for host-only) so a round trip keeps the
/// distinction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CookieParams {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Cookie domain; a leading dot makes a domain cookie.
    pub domain: Option<String>,
    /// URL path scope. Defaults to `/`; not allowed together with `url`.
    pub path: Option<String>,
    /// URL to derive a host-only cookie from; not allowed with `domain`/`path`.
    pub url: Option<String>,
    /// Unix timestamp in seconds; `None` or `-1` is a session cookie.
    pub expires: Option<f64>,
    /// Not accessible via JavaScript.
    pub http_only: bool,
    /// Only send over HTTPS. Ignored with `url`, whose scheme decides.
    pub secure: bool,
    /// `Strict`, `Lax` or `None` (ASCII case-insensitive); defaults to `Lax`.
    pub same_site: Option<String>,
    /// Overrides whether the cookie is host-only.
    pub host_only: Option<bool>,
    /// A partitioned (CHIPS) cookie; unsupported (no partitions in the jar).
    /// `Client::set_cookie_params` skips and reports these; converting one alone is an error.
    pub partitioned: bool,
}

/// A cookie that [`Client::set_cookies`](crate::Client::set_cookies) or
/// [`Client::set_cookie_params`](crate::Client::set_cookie_params) did not import, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedCookie {
    /// Position of the cookie in the list given to the import (0-based).
    pub index: usize,
    /// The cookie's name.
    pub name: String,
    /// Why it was not imported.
    pub reason: String,
}

impl CookieParams {
    /// Convert into a [`Cookie`]; the error is the reason the params are invalid.
    pub(crate) fn into_cookie(self) -> Result<Cookie, String> {
        if self.partitioned {
            return Err(
                "partitioned (CHIPS) cookies are not supported: browsers send them \
                        only in a third-party context"
                    .into(),
            );
        }
        let (domain, path, default_host_only, secure) = match (self.url, self.domain) {
            (Some(_), Some(_)) => return Err("a cookie has either url or domain, not both".into()),
            (Some(_), None) if self.path.is_some() => {
                return Err("a cookie has either url or path, not both".into());
            }
            (Some(url), None) => {
                let url = url::Url::parse(&url).map_err(|e| format!("invalid url: {e}"))?;
                let host = url
                    .host_str()
                    .filter(|host| !host.is_empty())
                    .ok_or("url has no host")?;
                let url_path = url.path();
                let path = url_path.rfind('/').map_or("/", |last| &url_path[..=last]);
                (
                    host.to_ascii_lowercase(),
                    path.to_string(),
                    true,
                    url.scheme() == "https",
                )
            }
            (None, Some(domain)) => (
                normalize_domain(&domain),
                self.path.unwrap_or_else(|| "/".to_string()),
                !domain.starts_with('.'),
                self.secure,
            ),
            (None, None) => return Err("a cookie needs a url or a domain".into()),
        };
        let host_only = self.host_only.unwrap_or(default_host_only);

        // The same acceptance rules every other path into the jar applies (`parse_set_cookie`,
        // and `client/cookies.rs`'s import path for a raw `Cookie`): name/value shape and the
        // `__Secure-`/`__Host-` prefixes, not just the shape checked above.
        validate_name_value(&self.name, &self.value)?;
        prefix_ok(&self.name, &self.value, secure, host_only, path == "/")?;
        if !host_only && is_public_suffix(&domain) {
            return Err("domain cannot be a public suffix unless host_only".into());
        }

        let expires = match self.expires {
            None | Some(-1.0) => None,
            Some(secs) if (0.0..=MAX_IMPORT_EXPIRES).contains(&secs) => {
                Some(UNIX_EPOCH + Duration::from_secs_f64(secs))
            }
            Some(_) => {
                return Err(
                    "expires must be -1 or a Unix timestamp in seconds up to 253402300799".into(),
                );
            }
        };
        let same_site = match self.same_site.as_deref() {
            None => SameSite::Lax,
            Some(value) => {
                SameSite::parse(value).ok_or("sameSite must be 'Strict', 'Lax' or 'None'")?
            }
        };

        Ok(Cookie {
            name: self.name,
            value: self.value,
            domain,
            path,
            secure,
            http_only: self.http_only,
            expires,
            same_site,
            host_only,
            creation_time: SystemTime::now(),
        })
    }
}

impl TryFrom<CookieParams> for Cookie {
    type Error = Error;

    fn try_from(params: CookieParams) -> Result<Cookie, Error> {
        params.into_cookie().map_err(Error::InvalidCookie)
    }
}

impl From<&Cookie> for CookieParams {
    fn from(cookie: &Cookie) -> CookieParams {
        let domain = if cookie.host_only {
            cookie.domain.clone()
        } else {
            format!(".{}", cookie.domain)
        };
        let expires = cookie.expires.map_or(-1.0, |time| {
            time.duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64())
        });
        CookieParams {
            name: cookie.name.clone(),
            value: cookie.value.clone(),
            domain: Some(domain),
            path: Some(cookie.path.clone()),
            url: None,
            expires: Some(expires),
            http_only: cookie.http_only,
            secure: cookie.secure,
            same_site: Some(cookie.same_site.as_str().to_string()),
            host_only: Some(cookie.host_only),
            partitioned: false,
        }
    }
}

/// Whitespace around cookie names, values and attributes (RFC 6265bis §5.6: SP and HTAB).
fn trim_wsp(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// A control character other than HTAB (RFC 6265bis §5.6 step 1).
const fn is_control_except_htab(b: u8) -> bool {
    (b < 0x20 && b != 0x09) || b == 0x7f
}

/// Lowercase a cookie domain and strip its leading dots.
pub(crate) fn normalize_domain(domain: &str) -> String {
    domain.trim_start_matches('.').to_ascii_lowercase()
}

/// The name/value rules shared by `Set-Cookie` parsing and imported cookies: not both empty, no
/// control character other than HTAB, no `;`, no `=` in the name, and at most [`MAX_COOKIE_SIZE`]
/// bytes together.
pub(crate) fn validate_name_value(name: &str, value: &str) -> Result<(), &'static str> {
    if name.is_empty() && value.is_empty() {
        return Err("name and value cannot both be empty");
    }
    if name
        .bytes()
        .any(|b| is_control_except_htab(b) || b == b';' || b == b'=')
    {
        return Err("name contains a control character, ';' or '='");
    }
    if value
        .bytes()
        .any(|b| is_control_except_htab(b) || b == b';')
    {
        return Err("value contains a control character or ';'");
    }
    if name.len() + value.len() > MAX_COOKIE_SIZE {
        return Err("name + value exceeds the 4096-byte limit");
    }
    Ok(())
}

/// The `__Secure-`/`__Host-` cookie-name prefixes (RFC 6265bis §4.1.3): `__Secure-` requires
/// `Secure`; `__Host-` additionally requires a host-only cookie (no Domain attribute) with path
/// `/`. A nameless cookie's value may not start with either prefix either (§5.7 step 21).
pub(crate) fn prefix_ok(
    name: &str,
    value: &str,
    secure: bool,
    host_only: bool,
    root_path: bool,
) -> Result<(), &'static str> {
    if name.is_empty()
        && (has_cookie_prefix(value, "__Secure-") || has_cookie_prefix(value, "__Host-"))
    {
        return Err("a nameless cookie's value cannot start with '__Secure-' or '__Host-'");
    }
    if has_cookie_prefix(name, "__Host-") && !(secure && host_only && root_path) {
        return Err(
            "'__Host-' cookies require secure=true, path=\"/\" and host_only=true (no Domain)",
        );
    }
    if has_cookie_prefix(name, "__Secure-") && !secure {
        return Err("'__Secure-' cookies require secure=true");
    }
    Ok(())
}

/// Case-insensitive prefix match for the `__Secure-`/`__Host-` prefixes, as RFC 6265bis and current
/// browsers do.
fn has_cookie_prefix(name: &str, prefix: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Whether the cookie rules treat a URL as a secure origin: https, or a loopback host (`localhost`,
/// `*.localhost`, 127.0.0.0/8, `::1`), which browsers treat as potentially trustworthy. `host` is
/// the URL's host, lowercased.
fn is_secure_origin(url: &Uri, host: &str) -> bool {
    url.scheme_str() == Some("https")
        || host == "localhost"
        || host.ends_with(".localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Parse a single `Set-Cookie` header value received from `host` (lowercase) for a request to
/// `request_path` (RFC 6265bis §5.6 and §5.7). Returns `None` for a cookie a browser would ignore.
fn parse_set_cookie(
    header: &str,
    host: &str,
    request_path: &str,
    secure_origin: bool,
) -> Option<Cookie> {
    // §5.6 step 1: a control character anywhere voids the whole header.
    if header.bytes().any(is_control_except_htab) {
        return None;
    }

    let mut parts = header.split(';');
    let name_value = parts.next().unwrap_or("");
    let (name, value) = match name_value.split_once('=') {
        Some((name, value)) => (trim_wsp(name), trim_wsp(value)),
        // §5.6 step 3: without `=` the pair is the value of a nameless cookie.
        None => ("", trim_wsp(name_value)),
    };
    validate_name_value(name, value).ok()?;

    let now = SystemTime::now();
    let attrs = parse_attributes(parts, now);

    // §5.7 step 8 ("strict secure cookies"): only a secure origin may set a Secure cookie.
    if attrs.secure && !secure_origin {
        return None;
    }
    // Chrome and Firefox reject SameSite=None without Secure.
    if attrs.same_site == SameSite::None && !attrs.secure {
        return None;
    }

    // §5.7 step 9: an explicit Domain must domain-match the request host and must not be a public
    // suffix (else a response could set cookies for an unrelated host or a whole eTLD). A Domain
    // equal to the request host itself (e.g. `herokuapp.com`) gives a host-only cookie instead.
    let (domain, host_only) = match &attrs.domain {
        None => (host.to_string(), true),
        Some(domain) => {
            if !domain_matches(host, domain) {
                return None;
            }
            if is_public_suffix(domain) {
                if domain != host {
                    return None;
                }
                (domain.clone(), true)
            } else {
                (domain.clone(), false)
            }
        }
    };

    // §5.6.4: a Path that is empty or doesn't start with `/` falls back to the default path.
    let path = match attrs.path {
        Some(path) if path.starts_with('/') => path.to_string(),
        _ => default_path(request_path),
    };

    // `__Host-` needs an explicit `Path=/` attribute, not a defaulted path.
    prefix_ok(
        name,
        value,
        attrs.secure,
        attrs.domain.is_none(),
        attrs.path == Some("/"),
    )
    .ok()?;

    Some(Cookie {
        name: name.to_string(),
        value: value.to_string(),
        domain,
        path,
        secure: attrs.secure,
        http_only: attrs.http_only,
        // §5.6.2: Max-Age wins over Expires.
        expires: attrs.max_age.or(attrs.expires),
        same_site: attrs.same_site,
        host_only,
        creation_time: now,
    })
}

/// The `Set-Cookie` attributes accumulated from the `; name=value` pairs after the cookie's own
/// name and value (RFC 6265bis §5.6 step 4), before validation against the request context.
struct Attributes<'a> {
    domain: Option<String>,
    path: Option<&'a str>,
    secure: bool,
    http_only: bool,
    max_age: Option<SystemTime>,
    expires: Option<SystemTime>,
    same_site: SameSite,
}

/// Parse the `; name=value` pairs following a `Set-Cookie` header's own name and value, keeping the
/// last recognized value of each attribute.
fn parse_attributes<'a>(parts: impl Iterator<Item = &'a str>, now: SystemTime) -> Attributes<'a> {
    let mut attrs = Attributes {
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        max_age: None,
        expires: None,
        same_site: SameSite::Lax,
    };
    for attribute in parts {
        let (key, value) = match attribute.split_once('=') {
            Some((key, value)) => (trim_wsp(key), trim_wsp(value)),
            None => (trim_wsp(attribute), ""),
        };
        match key.to_ascii_lowercase().as_str() {
            "secure" => attrs.secure = true,
            "httponly" => attrs.http_only = true,
            "domain" => {
                // §5.6.3: an empty Domain attribute is ignored, leaving the cookie host-only.
                let domain = normalize_domain(value);
                if !domain.is_empty() {
                    attrs.domain = Some(domain);
                }
            }
            "path" => attrs.path = Some(value),
            "max-age" => {
                if let Some(time) = parse_max_age(value, now) {
                    attrs.max_age = Some(time);
                }
            }
            "expires" => {
                if let Some(time) = parse_http_date(value) {
                    attrs.expires = Some(time.min(now + MAX_COOKIE_AGE));
                }
            }
            // An unknown value leaves the default (Lax).
            "samesite" => attrs.same_site = SameSite::parse(value).unwrap_or(SameSite::Lax),
            _ => {}
        }
    }
    attrs
}

/// Parse a `Max-Age` value (RFC 6265bis §5.6.2): `-?DIGIT+`, capped at [`MAX_COOKIE_AGE`]; zero or
/// negative means already expired. Anything else is ignored.
fn parse_max_age(value: &str, now: SystemTime) -> Option<SystemTime> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |digits| (true, digits));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Too many digits for a u64 is still more than the cap.
    let secs = digits.parse::<u64>().unwrap_or(u64::MAX);
    if negative || secs == 0 {
        return Some(UNIX_EPOCH);
    }
    Some(now + Duration::from_secs(secs).min(MAX_COOKIE_AGE))
}

const fn is_cookie_date_delimiter(c: char) -> bool {
    !(c.is_ascii_digit() || c.is_ascii_alphabetic() || c == ':')
}

/// Greedily take up to `max` ASCII digits starting at byte offset `start`, requiring at least
/// `min`. Returns the parsed value and the offset right after the digits consumed.
fn take_digits(bytes: &[u8], start: usize, min: usize, max: usize) -> Option<(u32, usize)> {
    let mut pos = start;
    let mut count = 0;
    let mut value: u32 = 0;
    while pos < bytes.len() && count < max && bytes[pos].is_ascii_digit() {
        value = value * 10 + u32::from(bytes[pos] - b'0');
        pos += 1;
        count += 1;
    }
    if count < min {
        None
    } else {
        Some((value, pos))
    }
}

/// RFC 6265 §5.1.1 `day-of-month = 1*2DIGIT ( non-digit *OCTET )` and `year = 2*4DIGIT ( non-digit
/// *OCTET )`: `min` to `max` digits, and if more of the token follows, the next byte must not be a
/// digit (otherwise this is a longer number).
fn match_number(token: &str, min: usize, max: usize) -> Option<u32> {
    let bytes = token.as_bytes();
    let (value, pos) = take_digits(bytes, 0, min, max)?;
    if bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    Some(value)
}

/// RFC 6265 §5.1.1 `time = hms-time ( non-digit *OCTET )`, `hms-time = time-field ":" time-field
/// ":" time-field`, `time-field = 1*2DIGIT`.
fn match_time(token: &str) -> Option<(u32, u32, u32)> {
    let bytes = token.as_bytes();
    let (hour, pos) = take_digits(bytes, 0, 1, 2)?;
    if bytes.get(pos) != Some(&b':') {
        return None;
    }
    let (min, pos) = take_digits(bytes, pos + 1, 1, 2)?;
    if bytes.get(pos) != Some(&b':') {
        return None;
    }
    let (sec, pos) = take_digits(bytes, pos + 1, 1, 2)?;
    if bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    Some((hour, min, sec))
}

const MONTHS: [&[u8]; 12] = [
    b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov", b"dec",
];

/// RFC 6265 §5.1.1 `month`: a case-insensitive match on the first three letters against the
/// `jan".."dec` list; trailing characters (e.g. the full "September") are allowed.
fn match_month(token: &str) -> Option<u32> {
    let bytes = token.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    let prefix = &bytes[..3];
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(prefix))
        .map(|i| i as u32 + 1)
}

/// Parse a cookie-date per RFC 6265 §5.1.1 (unlike strict IMF-fixdate, accepts RFC 850 style,
/// asctime, and 2-digit years: 70-99 -> 19xx, 0-69 -> 20xx). The string is split into tokens on
/// non-alphanumeric, non-`:` bytes; each token fills the first field it matches, in any order.
fn parse_http_date(s: &str) -> Option<SystemTime> {
    let mut time = None;
    let mut day = None;
    let mut month = None;
    let mut year = None;

    for token in s.split(is_cookie_date_delimiter).filter(|t| !t.is_empty()) {
        if time.is_none() {
            time = match_time(token);
            if time.is_some() {
                continue;
            }
        }
        if day.is_none() {
            day = match_number(token, 1, 2);
            if day.is_some() {
                continue;
            }
        }
        if month.is_none() {
            month = match_month(token);
            if month.is_some() {
                continue;
            }
        }
        if year.is_none() {
            year = match_number(token, 2, 4);
        }
    }

    let (hour, min, sec) = time?;
    let (day, month) = (day?, month?);
    let mut year = i64::from(year?);

    if (70..=99).contains(&year) {
        year += 1900;
    } else if (0..=69).contains(&year) {
        year += 2000;
    }

    if !(1..=31).contains(&day) || year < 1601 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let total_secs = days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);
    // Valid per RFC 6265 (min year 1601) but pre-epoch; clamp since `SystemTime` can't go negative
    // still reads as "already expired".
    let total_secs = total_secs.max(0) as u64;
    UNIX_EPOCH.checked_add(Duration::from_secs(total_secs))
}

/// Convert a civil date to days since Unix epoch (1970-01-01) using Hinnant's algorithm.
const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Check whether `domain` is itself a public suffix (eTLD, e.g. `com` or `co.uk`): cookies must
/// not be scoped to one, or one site could set cookies readable by every sibling under it. Requires
/// a *known* PSL entry (`Suffix::is_known`): `psl::suffix`'s "no rule matched" fallback would
/// otherwise treat any single-label intranet host (`localhost`, `corp`) as a public suffix too.
pub(crate) fn is_public_suffix(domain: &str) -> bool {
    psl::suffix(domain.as_bytes()).is_some_and(|suffix| {
        suffix.is_known() && suffix.as_bytes().eq_ignore_ascii_case(domain.as_bytes())
    })
}

/// Domain matching per RFC 6265 §5.1.3: the host equals the cookie domain, or ends with `.` + the
/// cookie domain. Both must be lowercase.
fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
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

/// Get the default cookie path from a request path. Per RFC 6265: directory of the request URI
/// path.
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

    fn uri(url: &str) -> Uri {
        url.parse().unwrap()
    }

    /// Feed `set_cookies` to the jar as the Set-Cookie headers of one response from `url`.
    fn store(jar: &mut CookieJar, url: &str, set_cookies: &[&str]) {
        let headers: Vec<(String, String)> = set_cookies
            .iter()
            .map(|value| ("set-cookie".to_string(), value.to_string()))
            .collect();
        jar.store_from_response(&uri(url), &headers);
    }

    fn parse(header: &str) -> Option<Cookie> {
        parse_set_cookie(header, "example.com", "/", true)
    }

    fn test_cookie(name: &str, domain: &str, path: &str, host_only: bool) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: "v".to_string(),
            domain: domain.to_string(),
            path: path.to_string(),
            secure: false,
            http_only: false,
            expires: None,
            same_site: SameSite::Lax,
            host_only,
            creation_time: SystemTime::now(),
        }
    }

    fn epoch_secs(date: SystemTime) -> u64 {
        date.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("www.example.com", "example.com"));
        assert!(domain_matches("sub.www.example.com", "example.com"));
        assert!(!domain_matches("notexample.com", "example.com"));
        assert!(!domain_matches("example.com", "www.example.com"));
    }

    #[test]
    fn test_is_public_suffix() {
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("co.uk"));
        assert!(!is_public_suffix("example.com"));
        assert!(!is_public_suffix("example.co.uk"));
    }

    #[test]
    fn test_is_public_suffix_unknown_single_label_is_not_public() {
        // psl's fallback treats any unlisted single-label name as an unknown suffix; these must not
        // count as public suffixes.
        assert!(!is_public_suffix("localhost"));
        assert!(!is_public_suffix("corp"));
        assert!(!is_public_suffix("internal"));
    }

    #[test]
    fn test_reject_cross_site_cookie_domain() {
        let mut jar = CookieJar::new();
        store(&mut jar, "https://evil.com/", &["sid=x; Domain=bank.com"]);
        assert!(jar.cookies().is_empty());
        assert!(jar.cookie_header(&uri("https://bank.com/")).is_none());
    }

    #[test]
    fn test_reject_public_suffix_cookie_domain() {
        let mut jar = CookieJar::new();
        store(&mut jar, "https://foo.co.uk/", &["sid=x; Domain=co.uk"]);
        assert!(jar.cookies().is_empty());
    }

    #[test]
    fn test_reject_single_label_public_suffix_domain() {
        let mut jar = CookieJar::new();
        store(&mut jar, "https://example.com/", &["sid=x; Domain=com"]);
        assert!(jar.cookies().is_empty());
    }

    #[test]
    fn test_public_suffix_domain_equal_to_request_host_is_host_only() {
        // A site that IS a public-suffix entry (e.g. it directly owns a PSL domain) setting
        // `Domain=<itself>` is downgraded to a host-only cookie instead of being rejected outright.
        let mut jar = CookieJar::new();
        store(&mut jar, "https://com/", &["sid=x; Domain=com"]);
        assert_eq!(jar.cookies().len(), 1);
        assert!(jar.cookies()[0].host_only);
    }

    #[test]
    fn test_accept_valid_parent_domain_cookie() {
        // sub.example.com setting Domain=example.com is legitimate.
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://sub.example.com/",
            &["sid=x; Domain=example.com"],
        );
        assert!(
            jar.cookie_header(&uri("https://www.example.com/"))
                .is_some()
        );
    }

    #[test]
    fn test_empty_domain_attribute_stays_host_only() {
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://example.com/",
            &["sid=x; Domain=; Path=/"],
        );
        assert_eq!(jar.cookies().len(), 1);
        assert!(jar.cookies()[0].host_only);
        assert_eq!(jar.cookies()[0].domain, "example.com");
        assert!(
            jar.cookie_header(&uri("https://sub.example.com/"))
                .is_none()
        );
    }

    #[test]
    fn test_attribute_names_are_case_insensitive_and_trimmed() {
        let cookie = parse("a=1; PATH=/x; DOMAIN = Example.COM ; SECURE; HttpOnly").unwrap();
        assert_eq!(cookie.path, "/x");
        assert_eq!(cookie.domain, "example.com");
        assert!(!cookie.host_only);
        assert!(cookie.secure);
        assert!(cookie.http_only);
    }

    #[test]
    fn test_invalid_path_attribute_uses_default_path() {
        let cookie = parse_set_cookie("a=1; Path=foo", "example.com", "/app/page", true).unwrap();
        assert_eq!(cookie.path, "/app");
        let cookie = parse_set_cookie("a=1; Path=", "example.com", "/app/page", true).unwrap();
        assert_eq!(cookie.path, "/app");
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
        store(
            &mut jar,
            "https://example.com/path",
            &[
                "session=abc123; Path=/; Secure",
                "theme=dark; Path=/; Domain=example.com",
            ],
        );

        let header = jar.cookie_header(&uri("https://example.com/path")).unwrap();
        assert!(header.contains("session=abc123"));
        assert!(header.contains("theme=dark"));
    }

    #[test]
    fn test_cookie_overwrite() {
        let mut jar = CookieJar::new();
        store(&mut jar, "https://example.com/", &["a=1; Path=/"]);
        store(&mut jar, "https://example.com/", &["a=2; Path=/"]);
        assert_eq!(
            jar.cookie_header(&uri("https://example.com/")).unwrap(),
            "a=2"
        );
    }

    #[test]
    fn test_replace_keeps_creation_time_and_single_entry() {
        let mut jar = CookieJar::new();
        store(&mut jar, "https://example.com/", &["a=1; Path=/"]);
        let original_creation = jar.cookies()[0].creation_time;

        store(&mut jar, "https://example.com/", &["a=2; Path=/"]);

        assert_eq!(jar.cookies().len(), 1);
        assert_eq!(jar.cookies()[0].value, "2");
        assert_eq!(jar.cookies()[0].creation_time, original_creation);
    }

    #[test]
    fn test_cookie_header_orders_by_path_then_creation_time() {
        let mut jar = CookieJar::new();

        // Same path length ("/"): "first" must come before "second" because it was created earlier.
        let mut first = test_cookie("first", "example.com", "/", true);
        first.creation_time -= Duration::from_secs(1);
        jar.set(first);
        jar.set(test_cookie("second", "example.com", "/", true));
        // Longer, more specific path: must be sent first regardless of creation time.
        jar.set(test_cookie("third", "example.com", "/a", true));

        let header = jar.cookie_header(&uri("https://example.com/a/b")).unwrap();
        assert_eq!(header, "third=v; first=v; second=v");
    }

    #[test]
    fn test_cookie_header_matches_host_case_insensitively() {
        let mut jar = CookieJar::new();
        jar.set(test_cookie("a", "example.com", "/", true));
        jar.set(test_cookie("b", "example.com", "/", false));
        let header = jar.cookie_header(&uri("https://WWW.Example.COM/")).unwrap();
        assert_eq!(header, "b=v");
        let header = jar.cookie_header(&uri("https://EXAMPLE.com/")).unwrap();
        assert_eq!(header, "a=v; b=v");
    }

    #[test]
    fn test_host_only_and_domain_cookie_coexist() {
        // A host-only `sid` on example.com and a domain `sid` on .example.com are distinct cookies,
        // not an overwrite of one another: the upsert key must include host_only.
        let mut jar = CookieJar::new();
        jar.set(test_cookie("sid", "example.com", "/", true));
        jar.set(test_cookie("sid", "example.com", "/", false));

        assert_eq!(jar.cookies().len(), 2);

        // Both are sent, as by a browser: they are different cookies that both match.
        let header = jar.cookie_header(&uri("https://example.com/")).unwrap();
        assert_eq!(header.matches("sid=v").count(), 2);
    }

    #[test]
    fn test_secure_cookie_not_sent_over_http() {
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://example.com/",
            &["secret=val; Path=/; Secure"],
        );

        assert!(jar.cookie_header(&uri("https://example.com/")).is_some());
        assert!(jar.cookie_header(&uri("http://example.com/")).is_none());
    }

    #[test]
    fn test_secure_cookie_from_insecure_origin_is_rejected() {
        let mut jar = CookieJar::new();
        store(&mut jar, "http://example.com/", &["a=1; Path=/; Secure"]);
        assert!(jar.cookies().is_empty());
    }

    #[test]
    fn test_loopback_hosts_count_as_secure() {
        for url in [
            "http://localhost:8080/",
            "http://app.localhost/",
            "http://127.0.0.1/",
            "http://127.1.2.3/",
            "http://[::1]:3000/",
        ] {
            let mut jar = CookieJar::new();
            store(
                &mut jar,
                url,
                &["a=1; Path=/; Secure", "__Secure-b=1; Path=/; Secure"],
            );
            assert_eq!(jar.cookies().len(), 2, "{url}");
            assert_eq!(
                jar.cookie_header(&uri(url)).as_deref(),
                Some("a=1; __Secure-b=1"),
                "{url}"
            );
        }
    }

    #[test]
    fn test_insecure_origin_cannot_shadow_secure_cookie() {
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://example.com/",
            &["sid=secure; Path=/; Secure"],
        );

        // Same name from http: neither overwritten nor shadowed, not even on a narrower path or
        // from a subdomain.
        store(&mut jar, "http://example.com/", &["sid=plain; Path=/"]);
        store(
            &mut jar,
            "http://example.com/app/x",
            &["sid=plain; Path=/app"],
        );
        store(
            &mut jar,
            "http://www.example.com/",
            &["sid=plain; Domain=example.com"],
        );
        // ... nor deleted.
        store(&mut jar, "http://example.com/", &["sid=; Max-Age=0"]);
        assert_eq!(jar.cookies().len(), 1);
        assert_eq!(jar.cookies()[0].value, "secure");

        // Other names are unaffected, and https may replace it.
        store(&mut jar, "http://example.com/", &["other=1; Path=/"]);
        store(&mut jar, "https://example.com/", &["sid=new; Path=/"]);
        assert_eq!(
            jar.cookie_header(&uri("https://example.com/")).unwrap(),
            "sid=new; other=1"
        );
    }

    #[test]
    fn test_secure_prefix_requires_secure() {
        let mut jar = CookieJar::new();

        store(
            &mut jar,
            "http://example.com/",
            &["__Secure-a=1; Path=/; Secure"],
        );
        assert!(jar.cookies().is_empty(), "rejected: request wasn't https");

        store(&mut jar, "https://example.com/", &["__Secure-b=1; Path=/"]);
        assert!(jar.cookies().is_empty(), "rejected: no Secure attribute");

        store(
            &mut jar,
            "https://example.com/",
            &["__Secure-c=1; Path=/; Secure"],
        );
        assert_eq!(jar.cookies().len(), 1);

        // Case-insensitive prefix match, like current browsers.
        store(&mut jar, "https://example.com/", &["__secure-d=1; Path=/"]);
        assert_eq!(jar.cookies().len(), 1);
        store(
            &mut jar,
            "https://example.com/",
            &["__secure-d=1; Path=/; Secure"],
        );
        assert_eq!(jar.cookies().len(), 2);
    }

    #[test]
    fn test_host_prefix_requires_secure_explicit_root_path_and_no_domain() {
        let rejected = [
            "__Host-a=1; Path=/; Secure; Domain=example.com",
            "__Host-b=1; Path=/app; Secure",
            "__Host-c=1; Path=/",
            // The default path would be "/", but `__Host-` needs the attribute.
            "__Host-d=1; Secure",
        ];
        for header in rejected {
            let mut jar = CookieJar::new();
            store(&mut jar, "https://example.com/", &[header]);
            assert!(jar.cookies().is_empty(), "{header}");
        }

        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://example.com/",
            &["__Host-e=1; Path=/; Secure"],
        );
        assert_eq!(jar.cookies().len(), 1);
        assert!(jar.cookies()[0].host_only);
    }

    #[test]
    fn test_nameless_cookies() {
        let mut jar = CookieJar::new();
        store(&mut jar, "https://example.com/", &["abc; Path=/"]);
        assert_eq!(jar.cookies().len(), 1);
        assert_eq!(jar.cookies()[0].name, "");
        assert_eq!(jar.cookies()[0].value, "abc");

        // `=xyz` is the same nameless cookie, so it replaces `abc`.
        store(&mut jar, "https://example.com/", &["=xyz; Path=/"]);
        assert_eq!(jar.cookies().len(), 1);
        assert_eq!(
            jar.cookie_header(&uri("https://example.com/")).unwrap(),
            "xyz"
        );

        // Empty name and value, or a prefixed value: ignored.
        for header in [
            "=",
            "",
            " ; Path=/",
            "__Host-x; Path=/; Secure",
            "=__secure-y",
        ] {
            let mut jar = CookieJar::new();
            store(&mut jar, "https://example.com/", &[header]);
            assert!(jar.cookies().is_empty(), "{header:?}");
        }
    }

    #[test]
    fn test_imported_nameless_cookie_sent_without_equals() {
        let mut jar = CookieJar::new();
        jar.set(test_cookie("", "example.com", "/", true));
        jar.set(test_cookie("a", "example.com", "/", true));
        assert_eq!(
            jar.cookie_header(&uri("https://example.com/")).unwrap(),
            "v; a=v"
        );
    }

    #[test]
    fn test_control_characters_reject_the_cookie() {
        for header in ["a=b\x01c", "a\x7f=b", "a=b; Path=/\x00", "a=b\nc"] {
            assert!(parse(header).is_none(), "{header:?}");
        }
        // HTAB is allowed inside a value.
        assert_eq!(parse("a=b\tc").unwrap().value, "b\tc");
    }

    #[test]
    fn test_expiry_capped_at_400_days() {
        let limit = epoch_secs(SystemTime::now() + MAX_COOKIE_AGE);

        let cookie = parse("a=1; Max-Age=999999999999").unwrap();
        let expires = epoch_secs(cookie.expires.unwrap());
        assert!(expires <= limit + 1 && expires + 5 >= limit);

        let cookie = parse("a=1; Max-Age=99999999999999999999999").unwrap();
        assert!(epoch_secs(cookie.expires.unwrap()) <= limit + 1);

        let cookie = parse("a=1; Expires=Fri, 31 Dec 9999 23:59:59 GMT").unwrap();
        let expires = epoch_secs(cookie.expires.unwrap());
        assert!(expires <= limit + 1 && expires + 5 >= limit);

        // A near date is kept as is.
        let cookie = parse("a=1; Max-Age=60").unwrap();
        assert!(epoch_secs(cookie.expires.unwrap()) < limit);
    }

    #[test]
    fn test_invalid_max_age_is_ignored() {
        for header in [
            "a=1; Max-Age=+5",
            "a=1; Max-Age=5s",
            "a=1; Max-Age=-",
            "a=1; Max-Age=",
        ] {
            assert_eq!(parse(header).unwrap().expires, None, "{header}");
        }
        assert_eq!(parse("a=1; Max-Age=-0").unwrap().expires, Some(UNIX_EPOCH));
    }

    #[test]
    fn test_samesite_none_requires_secure() {
        assert!(parse("a=1; SameSite=None").is_none());
        assert_eq!(
            parse("a=1; SameSite=none; Secure").unwrap().same_site,
            SameSite::None
        );
    }

    #[test]
    fn test_cookie_size_limit_rejected() {
        let mut jar = CookieJar::new();
        let url = "https://example.com/";

        let huge = format!("a={}; Path=/", "x".repeat(MAX_COOKIE_SIZE));
        store(&mut jar, url, &[&huge]);
        assert!(
            jar.cookies().is_empty(),
            "name+value over the 4096-byte cap"
        );

        let at_cap = format!("a={}; Path=/", "x".repeat(MAX_COOKIE_SIZE - 1));
        store(&mut jar, url, &[&at_cap]);
        assert_eq!(jar.cookies().len(), 1, "exactly at the cap is allowed");
    }

    #[test]
    fn test_per_domain_cookie_cap_evicts_oldest() {
        let mut jar = CookieJar::new();

        for i in 0..(MAX_COOKIES_PER_DOMAIN + 5) {
            store(
                &mut jar,
                "https://example.com/",
                &[&format!("c{i}=v; Path=/")],
            );
        }

        assert_eq!(jar.cookies().len(), MAX_COOKIES_PER_DOMAIN);
        // The first 5 inserted (oldest) must have been evicted.
        for i in 0..5 {
            assert!(
                !jar.cookies().iter().any(|c| c.name == format!("c{i}")),
                "c{i} should have been evicted as the oldest"
            );
        }
        // The most recently inserted must still be present.
        let last = MAX_COOKIES_PER_DOMAIN + 4;
        assert!(jar.cookies().iter().any(|c| c.name == format!("c{last}")));
    }

    #[test]
    fn test_expired_cookies_do_not_count_against_limits() {
        // A full domain whose newest cookie has expired: storing one more must purge the expired
        // one instead of evicting a live cookie.
        let base = SystemTime::now() - Duration::from_secs(3600);
        let mut cookies: Vec<Cookie> = (0..MAX_COOKIES_PER_DOMAIN)
            .map(|i| {
                let mut cookie = test_cookie(&format!("c{i}"), "example.com", "/", true);
                cookie.creation_time = base + Duration::from_secs(i as u64);
                cookie
            })
            .collect();
        cookies.last_mut().unwrap().expires = Some(UNIX_EPOCH + Duration::from_secs(1));
        let mut jar = CookieJar { cookies };

        store(&mut jar, "https://example.com/", &["new=1; Path=/"]);

        assert_eq!(jar.cookies().len(), MAX_COOKIES_PER_DOMAIN);
        assert!(jar.cookies().iter().any(|c| c.name == "c0"));
        assert!(jar.cookies().iter().any(|c| c.name == "new"));
        let expired = format!("c{}", MAX_COOKIES_PER_DOMAIN - 1);
        assert!(!jar.cookies().iter().any(|c| c.name == expired));
    }

    #[test]
    fn test_total_cap_keeps_jar_order() {
        let base = SystemTime::now() - Duration::from_secs(3600);
        // Creation times descend, so the oldest cookies sit at the end.
        let cookies: Vec<Cookie> = (0..MAX_COOKIES_TOTAL + 2)
            .map(|i| {
                let mut cookie = test_cookie("c", &format!("d{i}.example.com"), "/", true);
                cookie.creation_time = base - Duration::from_secs(i as u64);
                cookie
            })
            .collect();
        let mut jar = CookieJar { cookies };
        jar.prune();

        assert_eq!(jar.cookies().len(), MAX_COOKIES_TOTAL);
        assert_eq!(jar.cookies()[0].domain, "d0.example.com");
        assert_eq!(
            jar.cookies().last().unwrap().domain,
            format!("d{}.example.com", MAX_COOKIES_TOTAL - 1)
        );
    }

    #[test]
    fn test_expires_parsing() {
        let mut jar = CookieJar::new();
        let url = "https://example.com/";

        store(
            &mut jar,
            url,
            &["future=yes; Path=/; Expires=Thu, 01 Dec 2050 00:00:00 GMT"],
        );
        assert!(jar.cookie_header(&uri(url)).unwrap().contains("future=yes"));

        // A past Expires deletes rather than stores.
        store(
            &mut jar,
            url,
            &["past=no; Path=/; Expires=Thu, 01 Jan 2020 00:00:00 GMT"],
        );
        let header = jar.cookie_header(&uri(url)).unwrap();
        assert!(!header.contains("past=no"));
        assert!(header.contains("future=yes"));
    }

    #[test]
    fn test_max_age_precedence() {
        // Max-Age=3600 overrides the past Expires, in either order.
        let cookie =
            parse("pref=val; Expires=Thu, 01 Jan 2020 00:00:00 GMT; Max-Age=3600").unwrap();
        assert!(cookie.expires.unwrap() > SystemTime::now());
        let cookie =
            parse("pref=val; Max-Age=3600; Expires=Thu, 01 Jan 2020 00:00:00 GMT").unwrap();
        assert!(cookie.expires.unwrap() > SystemTime::now());
    }

    #[test]
    fn test_max_age_non_positive_means_expired() {
        let mut jar = CookieJar::new();
        let url = "https://example.com/";

        store(&mut jar, url, &["a=1; Path=/; Max-Age=0"]);
        assert!(jar.cookie_header(&uri(url)).is_none());

        store(&mut jar, url, &["b=1; Path=/; Max-Age=-100"]);
        assert!(jar.cookie_header(&uri(url)).is_none());
    }

    #[test]
    fn test_host_only_cookie() {
        let mut jar = CookieJar::new();
        let url = "https://example.com/";
        let sub_url = uri("https://sub.example.com/");

        // Cookie without explicit Domain -> host_only = true
        store(&mut jar, url, &["hostonly=yes; Path=/"]);
        assert!(jar.cookie_header(&uri(url)).is_some());
        assert!(jar.cookie_header(&sub_url).is_none());

        // A cookie WITH explicit Domain also matches subdomains.
        store(&mut jar, url, &["shared=yes; Path=/; Domain=example.com"]);
        assert_eq!(jar.cookie_header(&sub_url).unwrap(), "shared=yes");
    }

    #[test]
    fn test_samesite_stored() {
        assert_eq!(
            parse("a=1; SameSite=Strict").unwrap().same_site,
            SameSite::Strict
        );
        assert_eq!(parse("b=2; SameSite=Lax").unwrap().same_site, SameSite::Lax);
        assert_eq!(
            parse("c=3; SameSite=None; Secure").unwrap().same_site,
            SameSite::None
        );
        // Default and unknown values: Lax.
        assert_eq!(parse("d=4").unwrap().same_site, SameSite::Lax);
        assert_eq!(
            parse("e=5; SameSite=bogus").unwrap().same_site,
            SameSite::Lax
        );
    }

    #[test]
    fn test_response_without_set_cookie_leaves_jar_untouched() {
        let mut expired = test_cookie("old", "example.com", "/", true);
        expired.expires = Some(UNIX_EPOCH + Duration::from_secs(1));
        let mut jar = CookieJar {
            cookies: vec![expired],
        };
        jar.store_from_response(
            &uri("https://example.com/"),
            &[("content-type".to_string(), "text/html".to_string())],
        );
        // Not pruned (no Set-Cookie), and never sent.
        assert_eq!(jar.cookies().len(), 1);
        assert!(jar.cookie_header(&uri("https://example.com/")).is_none());
    }

    #[test]
    fn test_from_json_normalizes_domain_and_survives_huge_timestamps() {
        let json = r#"[{"name":"a","value":"1","domain":".EXAMPLE.com","path":"/",
            "secure":false,"http_only":true,"expires":18446744073709551615,
            "same_site":"lax","host_only":false,"creation_time":18446744073709551615}]"#;
        let jar = CookieJar::from_json(json).unwrap();
        let cookie = &jar.cookies()[0];
        assert_eq!(cookie.domain, "example.com");
        assert!(cookie.http_only);
        assert_eq!(cookie.expires, None);
        assert!(cookie.creation_time <= SystemTime::now());
        assert_eq!(
            jar.cookie_header(&uri("https://www.example.com/")).unwrap(),
            "a=1"
        );
    }

    #[test]
    fn test_http_date_parsing() {
        assert!(parse_http_date("Thu, 01 Dec 2025 00:00:00 GMT").is_some());
        assert!(parse_http_date("Mon, 15 Jan 2024 12:30:45 GMT").is_some());
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }

    #[test]
    fn test_http_date_parsing_rfc850_style() {
        // "DD-Mon-YY(YY)": still sent by a number of real servers.
        let date = parse_http_date("Fri, 18-Sep-2026 12:00:00 GMT").unwrap();
        let expected = days_from_civil(2026, 9, 18) as u64 * 86400 + 12 * 3600;
        assert_eq!(epoch_secs(date), expected);
    }

    #[test]
    fn test_http_date_parsing_asctime_style() {
        // asctime: "Sun Nov 6 08:49:37 1994" (note the double space before a single-digit day).
        let date = parse_http_date("Sun Nov  6 08:49:37 1994").unwrap();
        let expected = days_from_civil(1994, 11, 6) as u64 * 86400 + 8 * 3600 + 49 * 60 + 37;
        assert_eq!(epoch_secs(date), expected);
    }

    #[test]
    fn test_http_date_parsing_two_digit_year() {
        // 70-99 -> 19xx
        let date = parse_http_date("Fri, 18-Sep-99 12:00:00 GMT").unwrap();
        assert_eq!(
            epoch_secs(date),
            days_from_civil(1999, 9, 18) as u64 * 86400 + 12 * 3600
        );

        // 0-69 -> 20xx
        let date = parse_http_date("Fri, 18-Sep-26 12:00:00 GMT").unwrap();
        assert_eq!(
            epoch_secs(date),
            days_from_civil(2026, 9, 18) as u64 * 86400 + 12 * 3600
        );
    }

    #[test]
    fn test_http_date_before_epoch_clamped_to_expired() {
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://example.com/",
            &["old=yes; Path=/; Expires=Wed, 01 Jan 1900 00:00:00 GMT"],
        );
        assert!(jar.cookie_header(&uri("https://example.com/")).is_none());
        assert!(jar.cookies().is_empty());
    }

    fn params(name: &str) -> CookieParams {
        CookieParams {
            name: name.to_string(),
            value: "v".to_string(),
            ..CookieParams::default()
        }
    }

    #[test]
    fn test_params_from_url() {
        let cookie = CookieParams {
            url: Some("https://Example.com/a/b?q=1".to_string()),
            secure: false,
            ..params("a")
        }
        .into_cookie()
        .unwrap();
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/a/");
        assert!(cookie.host_only);
        assert!(cookie.secure, "https URL makes the cookie secure");

        let cookie = CookieParams {
            url: Some("http://example.com/login".to_string()),
            secure: true,
            ..params("a")
        }
        .into_cookie()
        .unwrap();
        assert_eq!(cookie.path, "/");
        assert!(!cookie.secure, "http URL overrides secure");
    }

    #[test]
    fn test_params_from_domain() {
        let domain_cookie = CookieParams {
            domain: Some(".Example.com".to_string()),
            ..params("a")
        }
        .into_cookie()
        .unwrap();
        assert_eq!(domain_cookie.domain, "example.com");
        assert_eq!(domain_cookie.path, "/");
        assert!(!domain_cookie.host_only);

        let host_cookie = CookieParams {
            domain: Some("example.com".to_string()),
            path: Some("/x".to_string()),
            ..params("a")
        }
        .into_cookie()
        .unwrap();
        assert!(host_cookie.host_only);
        assert_eq!(host_cookie.path, "/x");

        let overridden = CookieParams {
            domain: Some(".example.com".to_string()),
            host_only: Some(true),
            ..params("a")
        }
        .into_cookie()
        .unwrap();
        assert!(overridden.host_only);
    }

    #[test]
    fn test_params_rejects_invalid_shapes() {
        let url = || Some("https://example.com/".to_string());
        let domain = || Some("example.com".to_string());
        let invalid = [
            params("neither"),
            CookieParams {
                url: url(),
                domain: domain(),
                ..params("both")
            },
            CookieParams {
                url: url(),
                path: Some("/".to_string()),
                ..params("url and path")
            },
            CookieParams {
                url: Some("about:blank".to_string()),
                ..params("no host")
            },
            CookieParams {
                domain: domain(),
                partitioned: true,
                ..params("partitioned")
            },
            CookieParams {
                domain: domain(),
                same_site: Some("sometimes".to_string()),
                ..params("same site")
            },
        ];
        for p in invalid {
            let name = p.name.clone();
            assert!(p.into_cookie().is_err(), "{name}");
        }
    }

    #[test]
    fn test_params_applies_the_same_name_value_and_prefix_rules_as_set_cookie() {
        // A raw CRLF in the value: rejected on its own terms, the same as a Set-Cookie header
        // with a control character would be, not only by a second check somewhere else.
        let injected = CookieParams {
            domain: Some("example.com".to_string()),
            value: "x\r\ninjected".to_string(),
            ..params("a")
        };
        assert!(injected.into_cookie().is_err());

        // `;`/`=` in the name.
        let bad_name = CookieParams {
            domain: Some("example.com".to_string()),
            ..params("a;b")
        };
        assert!(bad_name.into_cookie().is_err());

        // `__Host-` needs secure, host-only and path "/"; a domain cookie fails it.
        let host_prefix_with_domain = CookieParams {
            domain: Some(".example.com".to_string()),
            secure: true,
            ..params("__Host-a")
        };
        assert!(host_prefix_with_domain.into_cookie().is_err());

        // `__Secure-` needs secure=true.
        let secure_prefix_without_secure = CookieParams {
            domain: Some("example.com".to_string()),
            secure: false,
            ..params("__Secure-a")
        };
        assert!(secure_prefix_without_secure.into_cookie().is_err());

        // The same `__Host-` cookie with everything it requires is accepted.
        let valid_host_prefix = CookieParams {
            domain: Some("example.com".to_string()),
            secure: true,
            ..params("__Host-a")
        };
        assert!(valid_host_prefix.into_cookie().is_ok());
    }

    #[test]
    fn test_params_expires() {
        let with_expires = |expires: f64| {
            CookieParams {
                domain: Some("example.com".to_string()),
                expires: Some(expires),
                ..params("a")
            }
            .into_cookie()
        };
        assert_eq!(with_expires(-1.0).unwrap().expires, None);
        assert_eq!(
            with_expires(1_700_000_000.5).unwrap().expires,
            Some(UNIX_EPOCH + Duration::from_millis(1_700_000_000_500))
        );
        assert_eq!(with_expires(0.0).unwrap().expires, Some(UNIX_EPOCH));
        assert!(with_expires(MAX_IMPORT_EXPIRES).is_ok());
        for bad in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -2.0,
            -0.5,
            1e300,
        ] {
            assert!(with_expires(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_params_same_site_case_insensitive() {
        for (value, expected) in [
            ("STRICT", SameSite::Strict),
            ("lax", SameSite::Lax),
            ("None", SameSite::None),
        ] {
            let cookie = CookieParams {
                domain: Some("example.com".to_string()),
                same_site: Some(value.to_string()),
                ..params("a")
            }
            .into_cookie()
            .unwrap();
            assert_eq!(cookie.same_site, expected);
        }
    }

    #[test]
    fn test_params_export_roundtrip() {
        let mut host_only = test_cookie("h", "example.com", "/a", true);
        host_only.expires = Some(UNIX_EPOCH + Duration::from_secs(2_000_000_000));
        host_only.same_site = SameSite::Strict;
        host_only.http_only = true;
        let domain = test_cookie("d", "example.com", "/", false);

        let exported: Vec<CookieParams> = [&host_only, &domain]
            .into_iter()
            .map(CookieParams::from)
            .collect();
        assert_eq!(exported[0].domain.as_deref(), Some("example.com"));
        assert_eq!(exported[0].expires, Some(2_000_000_000.0));
        assert_eq!(exported[0].same_site.as_deref(), Some("Strict"));
        assert_eq!(exported[1].domain.as_deref(), Some(".example.com"));
        assert_eq!(exported[1].expires, Some(-1.0));

        for (original, params) in [&host_only, &domain].into_iter().zip(exported) {
            let back = Cookie::try_from(params).unwrap();
            assert_eq!(back.domain, original.domain);
            assert_eq!(back.path, original.path);
            assert_eq!(back.host_only, original.host_only);
            assert_eq!(back.expires, original.expires);
            assert_eq!(back.same_site, original.same_site);
            assert_eq!(back.http_only, original.http_only);
        }
    }
}
