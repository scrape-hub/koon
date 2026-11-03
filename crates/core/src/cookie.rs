use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::error::Error;

pub(crate) const MAX_COOKIE_SIZE: usize = 4096;

const MAX_COOKIES_PER_DOMAIN: usize = 180;

const MAX_COOKIES_TOTAL: usize = 3300;

const MAX_COOKIE_AGE: Duration = Duration::from_secs(400 * 24 * 60 * 60);

const MAX_IMPORT_EXPIRES: f64 = 253_402_300_799.0;

/// A simple in-memory cookie jar for storing and matching cookies.
#[derive(Debug, Clone)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
}

/// The `SameSite` cookie attribute (RFC 6265bis).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SameSite {
    /// Cookie is sent with same-site and top-level navigation requests.
    Lax,
    /// Cookie is only sent with same-site requests.
    Strict,
    /// Cookie is sent with all requests (requires `Secure`).
    None,
    /// No (valid) attribute: Chromium treats the cookie as `Lax`, Firefox and Safari as `None`.
    Unspecified,
}

impl SameSite {
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

    const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Strict => Some("Strict"),
            Self::Lax => Some("Lax"),
            Self::None => Some("None"),
            Self::Unspecified => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SameSiteRules {
    Chromium,
    UnspecifiedIsNone,
    Ignored,
}

const LAX_ALLOW_UNSAFE_MAX_AGE: Duration = Duration::from_secs(2 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThirdPartyCookies {
    Allowed,
    Partitioned,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CookieRules {
    pub same_site: SameSiteRules,
    pub third_party: ThirdPartyCookies,
    pub chips: bool,
    pub redirect_is_third_party: bool,
}

impl CookieRules {
    pub(crate) const NONE: Self = Self {
        same_site: SameSiteRules::Ignored,
        third_party: ThirdPartyCookies::Allowed,
        chips: false,
        redirect_is_third_party: false,
    };
}

#[derive(Debug, Clone)]
pub(crate) struct CookieContext {
    pub same_site: bool,
    pub top_level_navigation: bool,
    pub safe_method: bool,
    pub rules: CookieRules,
    pub top_level_site: String,
    pub third_party: bool,
}

impl CookieContext {
    pub(crate) fn top_level(url: &Uri) -> Self {
        Self {
            same_site: true,
            top_level_navigation: true,
            safe_method: true,
            rules: CookieRules::NONE,
            top_level_site: top_level_site(url),
            third_party: false,
        }
    }

    fn includes(&self, cookie: &Cookie, now: SystemTime) -> bool {
        let in_partition = match &cookie.partition_key {
            Some(key) => *key == self.top_level_site,
            None => !self.third_party || self.rules.third_party == ThirdPartyCookies::Allowed,
        };
        if !in_partition {
            return false;
        }
        if self.same_site || self.rules.same_site == SameSiteRules::Ignored {
            return true;
        }
        let lax = self.top_level_navigation && self.safe_method;
        match cookie.same_site {
            SameSite::Strict => false,
            SameSite::Lax => lax,
            SameSite::None => true,
            SameSite::Unspecified => match self.rules.same_site {
                SameSiteRules::Chromium => {
                    lax || (self.top_level_navigation
                        && now
                            .duration_since(cookie.creation_time)
                            .is_ok_and(|age| age < LAX_ALLOW_UNSAFE_MAX_AGE))
                }
                SameSiteRules::UnspecifiedIsNone | SameSiteRules::Ignored => true,
            },
        }
    }

    fn may_set(&self, cookie: &Cookie) -> bool {
        if self.same_site
            || self.top_level_navigation
            || self.rules.same_site == SameSiteRules::Ignored
        {
            return true;
        }
        match cookie.same_site {
            SameSite::None => true,
            SameSite::Unspecified => self.rules.same_site != SameSiteRules::Chromium,
            SameSite::Strict | SameSite::Lax => false,
        }
    }

    fn partition_for(&self, cookie: &Cookie, partitioned: bool) -> Option<Option<String>> {
        if partitioned && self.rules.chips {
            return cookie.secure.then(|| Some(self.top_level_site.clone()));
        }
        if !self.third_party {
            return Some(None);
        }
        match self.rules.third_party {
            ThirdPartyCookies::Allowed => Some(None),
            ThirdPartyCookies::Partitioned => Some(Some(self.top_level_site.clone())),
            ThirdPartyCookies::Blocked => None,
        }
    }
}

pub(crate) fn top_level_site(url: &Uri) -> String {
    format!(
        "{}://{}",
        url.scheme_str().unwrap_or("https"),
        crate::util::site(url.host().unwrap_or(""))
    )
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
    /// The top-level site (`https://example.com`) of a partitioned cookie (CHIPS, or Firefox's
    /// Total Cookie Protection): it goes only with requests from pages of that site. `None` for an
    /// unpartitioned cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_key: Option<String>,
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

    pub(crate) fn set(&mut self, mut cookie: Cookie) {
        let existing = self.cookies.iter().position(|stored| {
            stored.name == cookie.name
                && stored.domain == cookie.domain
                && stored.path == cookie.path
                && stored.host_only == cookie.host_only
                && stored.partition_key == cookie.partition_key
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

    /// Parse Set-Cookie headers from the response to a top-level request and store the cookies a
    /// browser would accept.
    pub fn store_from_response(&mut self, url: &Uri, headers: &[(String, String)]) {
        self.store_from_response_in(url, headers, &CookieContext::top_level(url));
    }

    pub(crate) fn store_from_response_in(
        &mut self,
        url: &Uri,
        headers: &[(String, String)],
        context: &CookieContext,
    ) {
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
            let Some((mut cookie, partitioned)) =
                parse_set_cookie(value, &host, url.path(), secure_origin)
            else {
                continue;
            };
            if !context.may_set(&cookie) {
                continue;
            }
            let Some(partition_key) = context.partition_for(&cookie, partitioned) else {
                continue;
            };
            cookie.partition_key = partition_key;
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

    fn shadows_secure_cookie(&self, cookie: &Cookie) -> bool {
        self.cookies.iter().any(|stored| {
            stored.secure
                && stored.name == cookie.name
                && (domain_matches(&stored.domain, &cookie.domain)
                    || domain_matches(&cookie.domain, &stored.domain))
                && path_matches(&cookie.path, &stored.path)
        })
    }

    pub(crate) fn prune(&mut self) {
        let now = SystemTime::now();
        self.cookies
            .retain(|cookie| cookie.expires.is_none_or(|exp| exp > now));

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

    /// Build a Cookie header value for the given URL, as for a top-level same-site request.
    /// Returns None if no cookies match.
    pub fn cookie_header(&self, url: &Uri) -> Option<String> {
        self.cookie_header_for(url, &CookieContext::top_level(url))
    }

    pub(crate) fn cookie_header_for(&self, url: &Uri, context: &CookieContext) -> Option<String> {
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
                    && context.includes(c, now)
            })
            .collect();
        if matching.is_empty() {
            return None;
        }

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

    /// Create a `CookieJar` holding `cookies` that pass the checks every other way into the jar
    /// applies (name and value, host name, path, no public suffix as a domain, the `__Host-` and
    /// `__Secure-` prefixes), with their domains normalized; the others are left out.
    #[must_use]
    pub fn from_cookies(mut cookies: Vec<Cookie>) -> Self {
        cookies.retain_mut(|cookie| validate_imported(cookie).is_ok());
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
    /// The partition of a partitioned (CHIPS) cookie: a top-level site, whose pages' requests
    /// carry it. A key with a cross-site ancestor or an opaque one does not convert: browsers send
    /// those cookies only in frames below another site, which koon never loads
    /// (`Client::set_cookie_params` skips and reports them).
    pub partition_key: Option<PartitionKey>,
}

/// The partition key of a partitioned (CHIPS) cookie, as browsers export it (CDP's
/// `partitionKey` and `partitionKeyOpaque`, Playwright's `partitionKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionKey {
    /// Keyed by a top-level site such as `https://example.com`.
    Site {
        /// The top-level site.
        top_level_site: String,
        /// Whether a frame of another site stood between the top-level page and the frame that
        /// set the cookie (CDP's `hasCrossSiteAncestor`).
        cross_site_ancestor: bool,
    },
    /// An opaque key (a sandboxed or fenced frame).
    Opaque,
}

impl std::fmt::Display for PartitionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Site {
                top_level_site,
                cross_site_ancestor: false,
            } => f.write_str(top_level_site),
            Self::Site { top_level_site, .. } => {
                write!(f, "{top_level_site} with a cross-site ancestor")
            }
            Self::Opaque => f.write_str("an opaque key"),
        }
    }
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
    pub(crate) fn into_cookie(self) -> Result<Cookie, String> {
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
                    host.to_string(),
                    path.to_string(),
                    true,
                    url.scheme() == "https",
                )
            }
            (None, Some(domain)) => {
                let host_only = !domain.starts_with('.');
                let path = self.path.unwrap_or_else(|| "/".to_string());
                (domain, path, host_only, self.secure)
            }
            (None, None) => return Err("a cookie needs a url or a domain".into()),
        };

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
            None => SameSite::Unspecified,
            Some(value) => {
                SameSite::parse(value).ok_or("sameSite must be 'Strict', 'Lax' or 'None'")?
            }
        };

        let partition_key = match self.partition_key {
            None => None,
            Some(PartitionKey::Site {
                top_level_site,
                cross_site_ancestor: false,
            }) => Some(top_level_site),
            Some(key) => {
                return Err(format!(
                    "partitioned under {key}: browsers send it only in frames below another site, \
                     which koon never loads"
                ));
            }
        };
        let mut cookie = Cookie {
            name: self.name,
            value: self.value,
            domain,
            path,
            secure,
            http_only: self.http_only,
            expires,
            same_site,
            host_only: self.host_only.unwrap_or(default_host_only),
            creation_time: SystemTime::now(),
            partition_key,
        };
        validate_imported(&mut cookie)?;
        Ok(cookie)
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
            same_site: cookie.same_site.as_str().map(str::to_string),
            host_only: Some(cookie.host_only),
            partition_key: cookie
                .partition_key
                .clone()
                .map(|top_level_site| PartitionKey::Site {
                    top_level_site,
                    cross_site_ancestor: false,
                }),
        }
    }
}

fn trim_wsp(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

const fn is_control_except_htab(b: u8) -> bool {
    (b < 0x20 && b != 0x09) || b == 0x7f
}

pub(crate) fn normalize_domain(domain: &str) -> String {
    domain.trim_start_matches('.').to_ascii_lowercase()
}

pub(crate) fn validate_imported(cookie: &mut Cookie) -> Result<(), &'static str> {
    validate_name_value(&cookie.name, &cookie.value)?;
    let host = match url::Host::parse(cookie.domain.trim_start_matches('.')) {
        Ok(host) => host,
        Err(url::ParseError::EmptyHost) => return Err("domain cannot be empty"),
        Err(_) => return Err("domain is not a valid host name"),
    };
    if !matches!(host, url::Host::Domain(_)) {
        cookie.host_only = true;
    }
    cookie.domain = host.to_string();
    if let Some(key) = &cookie.partition_key {
        let site = key
            .parse::<Uri>()
            .ok()
            .filter(|url| {
                matches!(url.scheme_str(), Some("http" | "https")) && url.host().is_some()
            })
            .ok_or("partition key must be a site such as https://example.com")?;
        cookie.partition_key = Some(top_level_site(&site));
    }
    if !cookie.path.starts_with('/') {
        return Err("path must start with '/'");
    }
    if !cookie.host_only && is_public_suffix(&cookie.domain) {
        return Err("domain cannot be a public suffix unless host_only");
    }
    prefix_ok(
        &cookie.name,
        &cookie.value,
        cookie.secure,
        cookie.host_only,
        cookie.path == "/",
    )
}

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

fn has_cookie_prefix(name: &str, prefix: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn is_secure_origin(url: &Uri, host: &str) -> bool {
    url.scheme_str() == Some("https")
        || host == "localhost"
        || host.ends_with(".localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn parse_set_cookie(
    header: &str,
    host: &str,
    request_path: &str,
    secure_origin: bool,
) -> Option<(Cookie, bool)> {
    if header.bytes().any(is_control_except_htab) {
        return None;
    }

    let mut parts = header.split(';');
    let name_value = parts.next().unwrap_or("");
    let (name, value) = match name_value.split_once('=') {
        Some((name, value)) => (trim_wsp(name), trim_wsp(value)),
        None => ("", trim_wsp(name_value)),
    };
    validate_name_value(name, value).ok()?;

    let now = SystemTime::now();
    let attrs = parse_attributes(parts, now);

    if attrs.secure && !secure_origin {
        return None;
    }
    if attrs.same_site == SameSite::None && !attrs.secure {
        return None;
    }

    let (domain, host_only) = match &attrs.domain {
        None => (host.to_string(), true),
        Some(domain) => {
            if !domain_matches(host, domain) {
                return None;
            }
            if is_ip(host) || is_public_suffix(domain) {
                if domain != host {
                    return None;
                }
                (domain.clone(), true)
            } else {
                (domain.clone(), false)
            }
        }
    };

    let path = match attrs.path {
        Some(path) if path.starts_with('/') => path.to_string(),
        _ => default_path(request_path),
    };

    prefix_ok(
        name,
        value,
        attrs.secure,
        attrs.domain.is_none(),
        attrs.path == Some("/"),
    )
    .ok()?;

    let cookie = Cookie {
        name: name.to_string(),
        value: value.to_string(),
        domain,
        path,
        secure: attrs.secure,
        http_only: attrs.http_only,
        expires: attrs.max_age.or(attrs.expires),
        same_site: attrs.same_site,
        host_only,
        creation_time: now,
        partition_key: None,
    };
    Some((cookie, attrs.partitioned))
}

struct Attributes<'a> {
    domain: Option<String>,
    path: Option<&'a str>,
    secure: bool,
    http_only: bool,
    max_age: Option<SystemTime>,
    expires: Option<SystemTime>,
    same_site: SameSite,
    partitioned: bool,
}

fn parse_attributes<'a>(parts: impl Iterator<Item = &'a str>, now: SystemTime) -> Attributes<'a> {
    let mut attrs = Attributes {
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        max_age: None,
        expires: None,
        same_site: SameSite::Unspecified,
        partitioned: false,
    };
    for attribute in parts {
        let (key, value) = match attribute.split_once('=') {
            Some((key, value)) => (trim_wsp(key), trim_wsp(value)),
            None => (trim_wsp(attribute), ""),
        };
        match key.to_ascii_lowercase().as_str() {
            "secure" => attrs.secure = true,
            "httponly" => attrs.http_only = true,
            "partitioned" => attrs.partitioned = true,
            "domain" => {
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
            "samesite" => {
                attrs.same_site = SameSite::parse(value).unwrap_or(SameSite::Unspecified);
            }
            _ => {}
        }
    }
    attrs
}

fn parse_max_age(value: &str, now: SystemTime) -> Option<SystemTime> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |digits| (true, digits));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().unwrap_or(u64::MAX);
    if negative || secs == 0 {
        return Some(UNIX_EPOCH);
    }
    Some(now + Duration::from_secs(secs).min(MAX_COOKIE_AGE))
}

const fn is_cookie_date_delimiter(c: char) -> bool {
    !(c.is_ascii_digit() || c.is_ascii_alphabetic() || c == ':')
}

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

fn match_number(token: &str, min: usize, max: usize) -> Option<u32> {
    let bytes = token.as_bytes();
    let (value, pos) = take_digits(bytes, 0, min, max)?;
    if bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    Some(value)
}

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
    let total_secs = total_secs.max(0) as u64;
    UNIX_EPOCH.checked_add(Duration::from_secs(total_secs))
}

const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

pub(crate) fn is_public_suffix(domain: &str) -> bool {
    psl::suffix(domain.as_bytes()).is_some_and(|suffix| {
        suffix.is_known() && suffix.as_bytes().eq_ignore_ascii_case(domain.as_bytes())
    })
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || (!is_ip(host)
            && host
                .strip_suffix(domain)
                .is_some_and(|rest| rest.ends_with('.')))
}

fn is_ip(host: &str) -> bool {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .is_ok()
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }

    if request_path.starts_with(cookie_path) {
        if cookie_path.ends_with('/') {
            return true;
        }
        if request_path.as_bytes().get(cookie_path.len()) == Some(&b'/') {
            return true;
        }
    }

    false
}

fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}
